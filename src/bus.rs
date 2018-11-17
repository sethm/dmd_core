use err::BusError;

use std::cell::{RefCell, RefMut};
use std::cmp;
use std::collections::HashMap;
use std::fmt::Debug;

const MEM_MAX: usize = 1 << 32;

/// Access Status Code
pub enum AccessCode {
    MoveTranslated,
    CoprDataWrite,
    AutoVectorIrqAck,
    CoprDataFetch,
    StopAck,
    CoprBroadcast,
    CoprStatusFetch,
    ReadInterlocked,
    AddressFetch,
    OperandFetch,
    Write,
    IrqAck,
    IFAfterPCDisc,
    InstrPrefetch,
    InstrFetch,
    NoOp,
}

/// A virtual device on the bus.
pub trait Device: Send + Sync + Debug {
    fn address_ranges(&self) -> &[AddressRange];
    fn name(&self) -> &str;
    fn is_read_only(&self) -> bool;
    fn read_byte(&mut self, address: usize, access: AccessCode) -> Result<u8, BusError>;
    fn read_half(&mut self, address: usize, access: AccessCode) -> Result<u16, BusError>;
    fn read_word(&mut self, address: usize, access: AccessCode) -> Result<u32, BusError>;
    fn write_byte(&mut self, address: usize, val: u8, access: AccessCode) -> Result<(), BusError>;
    fn write_half(&mut self, address: usize, val: u16, access: AccessCode) -> Result<(), BusError>;
    fn write_word(&mut self, address: usize, val: u32, access: AccessCode) -> Result<(), BusError>;
    fn load(&mut self, address: usize, data: &[u8]) -> Result<(), BusError>;
}

#[derive(Eq, PartialEq, Debug)]
pub struct AddressRange {
    pub start_address: usize,
    pub len: usize,
}

impl AddressRange {
    pub fn new(start_address: usize, len: usize) -> AddressRange {
        AddressRange { start_address, len }
    }

    pub fn contains(&self, address: usize) -> bool {
        address >= self.start_address && address < self.start_address + self.len
    }
}

#[derive(Debug)]
pub struct Bus<'a> {
    len: usize,
    devices: Vec<RefCell<&'a mut Device>>,
    device_map: HashMap<usize, usize>,
}

impl<'a> Bus<'a> {
    pub fn new(len: usize) -> Bus<'a> {
        Bus {
            len: cmp::min(len, MEM_MAX),
            devices: Vec::new(),
            device_map: HashMap::new(),
        }
    }

    pub fn add_device(&mut self, device: &'a mut Device) -> Result<(), BusError> {
        for range in device.address_ranges() {
            if range.start_address + range.len > self.len {
                return Err(BusError::Range);
            }
            // Scan to see if there's room.
            for i in range.start_address..(range.start_address + range.len) {
                if self.device_map.contains_key(&i) {
                    return Err(BusError::Range);
                }
            }
        }

        // Now add the device
        let offset = self.devices.len();

        // Fill in the bus map with the offset of the given device
        for range in device.address_ranges() {
            for i in range.start_address..(range.start_address + range.len) {
                self.device_map.insert(i, offset);
            }
        }

        // Finally, move the refrence into the device list.
        self.devices.push(RefCell::new(device));

        Ok(())
    }

    /// Return the memory at a specified address
    fn get_device(&mut self, address: usize) -> Result<RefMut<&'a mut Device>, BusError> {
        let offset = self.device_map.get(&address);
        match offset {
            Some(o) => {
                let dev = self.devices[*o].try_borrow_mut();
                match dev {
                    Ok(d) => Ok(d),
                    Err(_) => Err(BusError::NoDevice),
                }
            }
            None => Err(BusError::NoDevice),
        }
    }

    pub fn read_byte(&mut self, address: usize, access: AccessCode) -> Result<u8, BusError> {
        self.get_device(address)?.read_byte(address, access)
    }

    pub fn read_half(&mut self, address: usize, access: AccessCode) -> Result<u16, BusError> {
        if address & 1 != 0 {
            return Err(BusError::Alignment);
        }
        self.get_device(address)?.read_half(address, access)
    }

    pub fn read_word(&mut self, address: usize, access: AccessCode) -> Result<u32, BusError> {
        if address & 3 != 0 {
            return Err(BusError::Alignment);
        }
        self.get_device(address)?.read_word(address, access)
    }

    pub fn read_half_unaligned(
        &mut self,
        address: usize,
        access: AccessCode,
    ) -> Result<u16, BusError> {
        self.get_device(address)?.read_half(address, access)
    }

    pub fn read_word_unaligned(
        &mut self,
        address: usize,
        access: AccessCode,
    ) -> Result<u32, BusError> {
        self.get_device(address)?.read_word(address, access)
    }

    pub fn write_byte(&mut self, address: usize, val: u8) -> Result<(), BusError> {
        self.get_device(address)?
            .write_byte(address, val, AccessCode::Write)
    }

    pub fn write_half(&mut self, address: usize, val: u16) -> Result<(), BusError> {
        if address & 1 != 0 {
            return Err(BusError::Alignment);
        }
        self.get_device(address)?
            .write_half(address, val, AccessCode::Write)
    }

    pub fn write_word(&mut self, address: usize, val: u32) -> Result<(), BusError> {
        if address & 3 != 0 {
            return Err(BusError::Alignment);
        }
        self.get_device(address)?
            .write_word(address, val, AccessCode::Write)
    }

    pub fn load(&mut self, address: usize, data: &[u8]) -> Result<(), BusError> {
        self.get_device(address)?.load(address, data)
    }
}

#[cfg(test)]
mod tests {
    use bus::Bus;
    use mem::Mem;

    #[test]
    fn should_add_device() {
        let mut mem1: Mem = Mem::new(0, 0x1000, false);
        let mut mem2: Mem = Mem::new(0x1000, 0x2000, false);
        let mut bus: Bus = Bus::new(0x10000);
        assert!(bus.add_device(&mut mem1).is_ok());
        assert!(bus.add_device(&mut mem2).is_ok());
    }

    #[test]
    fn should_fail_on_overlap() {
        let mut mem1: Mem = Mem::new(0x800, 0x1000, false);
        let mut mem2: Mem = Mem::new(0x0, 0x1000, false);
        let mut bus: Bus = Bus::new(0x10000);
        assert!(bus.add_device(&mut mem1).is_ok());
        assert!(bus.add_device(&mut mem2).is_err());
        assert!(bus.get_device(0x1).is_err());
        assert!(bus.get_device(0x800).is_ok());
    }

    #[test]
    fn should_fail_on_too_long() {
        let mut mem1 = Mem::new(0, 0x10001, false);
        let mut bus: Bus = Bus::new(0x10000);
        assert!(bus.add_device(&mut mem1).is_err());
        // The memory should not have been added to any addresses
        assert!(bus.get_device(0).is_err());
    }

    #[test]
    fn should_fail_on_alignment_errors() {
        let mut mem1 = Mem::new(0, 0x10000, false);
        let mut bus: Bus = Bus::new(0x10000);
        bus.add_device(&mut mem1).unwrap();

        assert!(bus.write_byte(0, 0x1f).is_ok());
        assert!(bus.write_half(0, 0x1f1f).is_ok());
        assert!(bus.write_word(0, 0x1f1f1f1f).is_ok());
        assert!(bus.write_half(1, 0x1f1f).is_err());
        assert!(bus.write_half(2, 0x1f1f).is_ok());
        assert!(bus.write_word(1, 0x1f1f1f1f).is_err());
        assert!(bus.write_word(2, 0x1f1f1f1f).is_err());
        assert!(bus.write_word(3, 0x1f1f1f1f).is_err());
        assert!(bus.write_word(4, 0x1f1f1f1f).is_ok());
    }
}
