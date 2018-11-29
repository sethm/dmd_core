use bus::Device;
use std::ops::Range;
use bus::AccessCode;
use err::BusError;

const START_ADDR: usize = 0x200000;
const END_ADDR: usize = 0x2000040;
const ADDRESS_RANGE: Range<usize> = START_ADDR..END_ADDR;

#[derive(Debug)]
pub struct Duart {
    mra: u8,
    mrb: u8,
    cra: u8,
    crb: u8,
    sra: u8,
    srb: u8,
    thrb: u8,
    interrupt: bool
}

impl Duart {
    pub fn new() -> Duart {
        Duart {
            mra: 0,
            mrb: 0,
            cra: 0,
            crb: 0,
            sra: 0,
            srb: 0,
            thrb: 0,
            interrupt: false
        }
    }

    pub fn get_interrupt(&mut self) -> bool {
        if self.interrupt {
            self.interrupt = false;
            return true
        }
        return false
    }

    pub fn keyboard(&mut self, keycode: u8) {
        self.thrb = keycode;
        self.srb = 0x01;
        self.interrupt = true;
    }
}

impl Device for Duart {
    fn address_range(&self) -> &Range<usize> {
        &ADDRESS_RANGE
    }

    fn name(&self) -> &str {
        "ACIA"
    }

    fn is_read_only(&self) -> bool {
        false
    }

    fn read_byte(&mut self, address: usize, _access: AccessCode) -> Result<u8, BusError> {
        match address - START_ADDR {
            0x03 => {
                println!("*** DUART READ: Mode Status Register A (flip-flop)...");
                Ok(0x21)
            }
            0x07 => {
                println!("*** DUART READ: SRA");
                Ok(0x1f)
            }
            0x27 => {
                println!("*** DUART READ: SRB...");
                if self.srb > 0 {
                    Ok(self.srb)
                } else {
                    Ok(0x21)
                }
            },
            0x2f => {
                println!("*** DUART READ: THRB...");
                Ok(self.thrb)
            },
            0x3f => {
                println!("*** DUART READ: Stop Counter Command...");
                Ok(0x01)
            }
            i => {
                println!("*** DUART READ FALL-THROUGH (port=0x{:02x})", i);
                Ok(0)
            }
        }
    }

    fn read_half(&mut self, _address: usize, _access: AccessCode) -> Result<u16, BusError> {
        unimplemented!()
    }

    fn read_word(&mut self, _address: usize, _access: AccessCode) -> Result<u32, BusError> {
        unimplemented!()
    }

    fn write_byte(&mut self, address: usize, val: u8, _access: AccessCode) -> Result<(), BusError> {
        match address - START_ADDR {
            0x2b => {
                // Command Register
                self.crb = val;
            }
            i => {
                println!("*** DUART WRITE FALL-THROUGH (port=0x{:02x} val=0x{:02x})", i, val);
            }
        };

        Ok(())
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