use bus::*;
use err::BusError;

use std::ops::Index;
use std::vec::Vec;

#[derive(Debug)]
pub struct Mem {
    address_ranges: Vec<AddressRange>,
    ram: Vec<u8>,
    is_read_only: bool,
}

/// Memory is a Device with a single address range.
impl Mem {
    pub fn new(start_address: usize, len: usize, is_read_only: bool) -> Mem {
        Mem {
            address_ranges: vec![AddressRange::new(start_address, len)],
            ram: vec![0; len],
            is_read_only,
        }
    }

    pub fn address_range(&self) -> &AddressRange {
        &self.address_ranges[0]
    }
}

impl Device for Mem {
    fn address_ranges(&self) -> &[AddressRange] {
        &self.address_ranges
    }

    fn name(&self) -> &str {
        if self.is_read_only {
            "ROM"
        } else {
            "RAM"
        }
    }

    fn is_read_only(&self) -> bool {
        self.is_read_only
    }

    /// Read from memory at the specified absolute address.
    fn read_byte(&mut self, address: usize, _: AccessCode) -> Result<u8, BusError> {
        let offset = address.wrapping_sub(self.address_range().start_address);

        if offset >= self.address_range().len {
            Err(BusError::Range)
        } else {
            Ok(self.ram[offset])
        }
    }

    fn read_half(&mut self, address: usize, _: AccessCode) -> Result<u16, BusError> {
        let offset = address.wrapping_sub(self.address_range().start_address);

        if offset >= self.address_range().len {
            Err(BusError::Range)
        } else {
            Ok(
                // Byte-swap
                u16::from(self.ram[offset]) | u16::from(self.ram[offset + 1]).wrapping_shl(8),
            )
        }
    }

    fn read_word(&mut self, address: usize, _: AccessCode) -> Result<u32, BusError> {
        let offset = address.wrapping_sub(self.address_range().start_address);

        if offset >= self.address_range().len {
            Err(BusError::Range)
        } else {
            Ok(
                // Byte-swap
                u32::from(self.ram[offset])
                    | u32::from(self.ram[offset + 1]).wrapping_shl(8)
                    | u32::from(self.ram[offset + 2]).wrapping_shl(16)
                    | u32::from(self.ram[offset + 3]).wrapping_shl(24),
            )
        }
    }

    /// Write to memory at the specified absolute address.
    fn write_byte(&mut self, address: usize, val: u8, _: AccessCode) -> Result<(), BusError> {
        if self.is_read_only {
            return Err(BusError::Write);
        }

        let offset = address.wrapping_sub(self.address_range().start_address);

        if offset >= self.address_range().len {
            Err(BusError::Range)
        } else {
            self.ram[offset] = val;
            Ok(())
        }
    }

    fn write_half(&mut self, address: usize, val: u16, _: AccessCode) -> Result<(), BusError> {
        if self.is_read_only {
            return Err(BusError::Write);
        }

        let offset = address.wrapping_sub(self.address_range().start_address);

        if offset >= self.address_range().len {
            Err(BusError::Range)
        } else {
            self.ram[offset] = (val & 0xff) as u8;
            self.ram[offset + 1] = (val.wrapping_shr(8) & 0xff) as u8;
            Ok(())
        }
    }

    fn write_word(&mut self, address: usize, val: u32, _: AccessCode) -> Result<(), BusError> {
        if self.is_read_only {
            return Err(BusError::Write);
        }

        let offset = address.wrapping_sub(self.address_range().start_address);

        if offset >= self.address_range().len {
            Err(BusError::Range)
        } else {
            self.ram[offset] = (val & 0xff) as u8;
            self.ram[offset + 1] = (val.wrapping_shr(8) & 0xff) as u8;
            self.ram[offset + 2] = (val.wrapping_shr(16) & 0xff) as u8;
            self.ram[offset + 3] = (val.wrapping_shr(24) & 0xff) as u8;
            Ok(())
        }
    }

    /// Load a block of bytes into memory at the specified absolute
    /// address. Note that "load" can load into read-only memory.
    fn load(&mut self, address: usize, program: &[u8]) -> Result<(), BusError> {
        let offset = address.wrapping_sub(self.address_range().start_address);

        if offset.wrapping_add(program.len()) > self.address_range().len {
            Err(BusError::Range)
        } else {
            for (i, byte) in program.iter().enumerate() {
                self.ram[offset.wrapping_add(i)] = *byte;
            }
            Ok(())
        }
    }
}

impl Index<usize> for Mem {
    type Output = u8;

    fn index(&self, idx: usize) -> &u8 {
        &self.ram[idx]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_read_big_endian() {
        let mut mem = Mem::new(0, 0x1000, false);
        let data: [u8; 4] = [0x01, 0x02, 0x03, 0x04];
        let result = mem.load(0, &data);
        assert!(result.is_ok());

        let a = mem.read_byte(0, AccessCode::AddressFetch).unwrap();
        let b = mem.read_half(0, AccessCode::AddressFetch).unwrap();
        let c = mem.read_word(0, AccessCode::AddressFetch).unwrap();

        assert_eq!(a, 0x01);
        assert_eq!(b, 0x0201);
        assert_eq!(c, 0x04030201);
    }

    #[test]
    fn should_write_big_endian() {
        let mut mem = Mem::new(0, 0x1000, false);
        let a: u8 = 0x01;
        let b: u16 = 0x0102u16;
        let c: u32 = 0x01020304u32;

        mem.write_byte(0, a, AccessCode::Write).unwrap();
        assert_eq!(0x01, mem[0]);

        mem.write_half(0, b, AccessCode::Write).unwrap();
        assert_eq!(0x02, mem[0]);
        assert_eq!(0x01, mem[1]);

        mem.write_word(0, c, AccessCode::Write).unwrap();
        assert_eq!(0x04, mem[0]);
        assert_eq!(0x03, mem[1]);
        assert_eq!(0x02, mem[2]);
        assert_eq!(0x01, mem[3]);
    }

    #[test]
    fn cannot_write_to_read_only_memory() {
        let mut mem = Mem::new(0, 0x1000, true);
        assert!(mem.write_byte(0, 0x1f, AccessCode::Write).is_err());
        assert!(mem.write_half(0, 0x1f1f, AccessCode::Write).is_err());
        assert!(mem.write_word(0, 0x1f1f1f1f, AccessCode::Write).is_err());
    }

    #[test]
    fn loads_program_if_it_fits() {
        let mut mem = Mem::new(0, 3, false);
        let program: [u8; 3] = [0x0a, 0x30, 0x1f];
        let result = mem.load(0, &program);
        assert!(result.is_ok());

        // Did it actually load?
        assert_eq!(mem[0], 0x0a);
        assert_eq!(mem[1], 0x30);
        assert_eq!(mem[2], 0x1f);
    }

    #[test]
    fn fails_to_load_program_if_it_doesnt_fit() {
        let mut mem = Mem::new(0, 3, false);
        let program: [u8; 4] = [0x0a, 0x30, 0x1f, 0x1b];
        let result = mem.load(0, &program);
        assert!(result.is_err());

        // Did it actually fail to load?
        assert_eq!(mem[0], 0);
        assert_eq!(mem[1], 0);
        assert_eq!(mem[2], 0);
    }

    #[test]
    fn can_write_and_read_memory() {
        let mut mem = Mem::new(0, 2, false);

        let mut read_result = mem.read_byte(0, AccessCode::AddressFetch);
        assert!(read_result.is_ok());
        assert_eq!(0, read_result.unwrap());

        let mut write_result = mem.write_byte(0, 0x01, AccessCode::Write);
        assert!(write_result.is_ok());

        read_result = mem.read_byte(0, AccessCode::AddressFetch);
        assert!(read_result.is_ok());
        assert_eq!(1, read_result.unwrap());

        write_result = mem.write_byte(1, 0x02, AccessCode::Write);
        assert!(write_result.is_ok());

        read_result = mem.read_byte(1, AccessCode::AddressFetch);
        assert!(read_result.is_ok());
        assert_eq!(2, read_result.unwrap());
    }

    #[test]
    fn fails_to_read_or_write_memory_when_out_of_bounds() {
        let mut mem = Mem::new(0, 2, false);

        let write_result = mem.write_byte(2, 0x03, AccessCode::Write);
        assert!(write_result.is_err());

        let read_result = mem.read_byte(2, AccessCode::AddressFetch);
        assert!(read_result.is_err());
    }

    #[test]
    fn memory_access_uses_absolute_addresses() {
        let mut mem = Mem::new(0x300, 2, false);

        let write_result = mem.write_byte(0x300, 0xfe, AccessCode::Write);
        assert!(write_result.is_ok());

        let read_result = mem.read_byte(0x300, AccessCode::AddressFetch);
        assert!(read_result.is_ok());
        assert_eq!(0xfe, read_result.unwrap());
    }
}
