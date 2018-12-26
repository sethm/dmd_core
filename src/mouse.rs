use crate::bus::Device;
use crate::bus::AccessCode;
use crate::err::BusError;
use std::ops::Range;

const START_ADDRESS: usize = 0x40_0000;
const END_ADDRESS: usize = 0x40_0004;
const ADDRESS_RANGE: Range<usize> = START_ADDRESS..END_ADDRESS;

#[derive(Debug)]
pub struct Mouse {
    pub x: u16,
    pub y: u16,
}

impl Mouse {
    pub fn new() -> Mouse {
        Mouse {
            x: 0,
            y: 0,
        }
    }
}

impl Default for Mouse {
    fn default() -> Self {
        Mouse::new()
    }
}

impl Device for Mouse {
    fn address_range(&self) -> &Range<usize> {
        &ADDRESS_RANGE
    }

    fn name(&self) -> &str {
        "MOUSE"
    }

    fn is_read_only(&self) -> bool {
        false
    }

    fn read_byte(&mut self, _address: usize, _access: AccessCode) -> Result<u8, BusError> {
        unimplemented!()
    }

    fn read_half(&mut self, address: usize, _access: AccessCode) -> Result<u16, BusError> {
        match address-START_ADDRESS {
            0 => Ok(self.y),
            2 => Ok(self.x),
            _ => Err(BusError::NoDevice(address as u32)),
        }
    }

    fn read_word(&mut self, _address: usize, _access: AccessCode) -> Result<u32, BusError> {
        unimplemented!()
    }

    fn write_byte(&mut self, _address: usize, _val: u8, _access: AccessCode) -> Result<(), BusError> {
        unimplemented!()
    }

    fn write_half(&mut self, _address: usize, _val: u16, _access: AccessCode) -> Result<(), BusError> {
        unimplemented!()
    }

    fn write_word(&mut self, _address: usize, _val: u32, _access: AccessCode) -> Result<(), BusError> {
        unimplemented!()
    }

    fn load(&mut self, _address: usize, _data: &[u8]) -> Result<(), BusError> {
        unimplemented!()
    }
}