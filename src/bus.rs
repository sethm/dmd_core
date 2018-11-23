use err::BusError;

use std::fmt::Debug;
use mem::Mem;

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
pub struct Bus {
    rom: Mem,
    ram: Mem,
}

impl Bus {
    pub fn new(mem_size: usize) -> Bus {
        Bus {
            rom: Mem::new(0, 0x20000, true),
            ram: Mem::new(0x700000, mem_size, false),
        }
    }

    fn get_device(&mut self, address: usize) -> Result<&mut Device, BusError> {
        if address < 0x20000 {
            return Ok(&mut self.rom);
        }

        if address >= 0x700000 && address < 0x800000 {
            return Ok(&mut self.ram);
        }

        Err(BusError::NoDevice(address as u32))
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

    pub fn read_op_half(&mut self, address: usize) -> Result<u16, BusError> {
        let m = self.get_device(address)?;

        Ok((m.read_byte(address, AccessCode::OperandFetch)? as u16) |
            (m.read_byte(address + 1, AccessCode::OperandFetch)? as u16).wrapping_shl(8))
    }

    pub fn read_op_word(&mut self, address: usize) -> Result<u32, BusError> {
        let m = self.get_device(address)?;

        Ok((m.read_byte(address, AccessCode::OperandFetch)? as u32) |
            (m.read_byte(address + 1, AccessCode::OperandFetch)? as u32).wrapping_shl(8) |
            (m.read_byte(address + 2, AccessCode::OperandFetch)? as u32).wrapping_shl(16) |
            (m.read_byte(address + 3, AccessCode::OperandFetch)? as u32).wrapping_shl(24))
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

    #[test]
    fn should_fail_on_alignment_errors() {
        let mut bus: Bus = Bus::new(0x10000);

        assert!(bus.write_byte(0x700000, 0x1f).is_ok());
        assert!(bus.write_half(0x700000, 0x1f1f).is_ok());
        assert!(bus.write_word(0x700000, 0x1f1f1f1f).is_ok());
        assert!(bus.write_half(0x700001, 0x1f1f).is_err());
        assert!(bus.write_half(0x700002, 0x1f1f).is_ok());
        assert!(bus.write_word(0x700001, 0x1f1f1f1f).is_err());
        assert!(bus.write_word(0x700002, 0x1f1f1f1f).is_err());
        assert!(bus.write_word(0x700003, 0x1f1f1f1f).is_err());
        assert!(bus.write_word(0x700004, 0x1f1f1f1f).is_ok());
    }
}
