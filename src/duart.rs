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
    ipcr: u8,
    thrb: u8,
    in_port: u8,
    keyboard_interrupt: bool,
    mouse_interrupt: bool,
    blank_interrupt: bool,
    steps: u128,
}

const RXRDY: u8 = 0x01;
const FFULL: u8 = 0x02;
const TXRDY: u8 = 0x04;
const TXEMT: u8 = 0x08;

impl Duart {
    pub fn new() -> Duart {
        Duart {
            mra: 0,
            mrb: 0,
            cra: 0,
            crb: 0,
            sra: 0,
            srb: 0,
            ipcr: 0x40,
            thrb: 0,
            in_port: 0xb,
            keyboard_interrupt: false,
            mouse_interrupt: false,
            blank_interrupt: false,
            steps: 0,
        }
    }

    pub fn get_interrupt(&mut self) -> Option<u16> {
        self.steps += 1;

        if self.steps % 10000 == 0 {
            self.vertical_blank();
        }

        let mut vector: u16 = 0;

        if self.keyboard_interrupt {
            self.keyboard_interrupt = false;
            vector |= 0x04;
        }

        if self.mouse_interrupt {
            self.mouse_interrupt = false;
            vector |= 0x02;
        }

        if self.blank_interrupt {
            self.blank_interrupt = false;
            vector |= 0x02;
        }

        if vector > 0 {
            return Some(vector)
        } else {
            return None
        }
    }

    pub fn keyboard(&mut self, keycode: u8) {
        self.thrb = keycode;
        self.srb = TXRDY;
        self.keyboard_interrupt = true;
    }


    pub fn vertical_blank(&mut self) {
        self.blank_interrupt = true;
        self.ipcr = 0x40;
    }

    pub fn mouse_down(&mut self, button: u8) {
        self.mouse_interrupt = true;
        self.in_port = 0xb;
        self.ipcr = 0;
        match button {
            0 => {
                self.ipcr |= 0x80;
                self.in_port &= !(0x08);
            },
            1 => {
                self.ipcr |= 0x20;
                self.in_port &= !(0x02);
            },
            2 => {
                self.ipcr |= 0x10;
                self.in_port &= !(0x01)
            },
            _ => {}
        }
        println!("*** Mouse Down: Button {} (IPCR=0x{:02x})", button, self.ipcr);
    }

    pub fn mouse_up(&mut self, button: u8) {
        self.mouse_interrupt = true;
        self.in_port = 0xb;
        self.ipcr = 0;
        match button {
            0 => {
                self.ipcr |= 0x80;
            },
            1 => {
                self.ipcr |= 0x20;
            },
            2 => {
                self.ipcr |= 0x10;
            },
            _ => {}
        }
        println!("*** Mouse Up: Button {} (IPCR=0x{:02x})", button, self.ipcr);
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
                println!("*** DUART READ: SRA...");
                if self.sra > 0 {
                    Ok(self.sra)
                } else {
                    Ok(0x1f)
                }
            }
            0x13 => {
                Ok(self.ipcr)
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
                println!("*** DUART READ: THRB (val=0x{:02x})...", self.thrb);
                Ok(self.thrb)
            },
            0x3f => {
                println!("*** DUART READ: Stop Counter Command...");
                Ok(0x01)
            }
            0x37 => {
                println!("*** DUART READ: Input Port (val=0x{:02x})...", self.in_port);
                Ok(self.in_port)
            }
            _ => {
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