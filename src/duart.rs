use bus::Device;
use std::ops::Range;
use bus::AccessCode;
use err::BusError;
use std::fmt::Debug;
use std::fmt::Formatter;
use std::fmt::Error;
use std::time::Instant;
use std::time::Duration;

const START_ADDR: usize = 0x200000;
const END_ADDR: usize = 0x2000040;
const ADDRESS_RANGE: Range<usize> = START_ADDR..END_ADDR;

// Vertical blanks should occur at 60Hz. This value is in nanoseconds
const VERTICAL_BLANK_DELAY: u32 = 16666666;

const MRA: u8 = 0x03;
const CRA: u8 = 0x0b;
const SR_CSRA: u8 = 0x07;
const TX_RXA: u8 = 0x0f;
const IPCR_ACR: u8 = 0x13;
const SR_CSRB: u8 = 0x27;
const CRB: u8 = 0x2b;
const TX_RXB: u8 = 0x2f;
const IP_OPCR: u8 = 0x37;
const CTRSTRT_OPSET: u8 = 0x3b;
const CTRSTP_OPRESET: u8 = 0x3f;

#[allow(dead_code)]
const TXEMT: u8 = 0x08;
const TXRDY: u8 = 0x04;

const SR_ENABLE_TX: u8 = 0x04;

const KEYBOARD_INT: u16 = 0x004;
const MOUSE_BLANK_INT: u16 = 0x002;
const TX_INT: u16 = 0x010;
const RX_INT: u16 = 0x020;


#[allow(dead_code)]
pub struct Duart {
    tx_callback: Option<Box<FnMut(u8) + Send + Sync>>,
    mra: u8,
    mrb: u8,
    cra: u8,
    crb: u8,
    sra: u8,
    srb: u8,
    data_a: u8,
    data_b: u8,
    ipcr: u8,
    in_port: u8,
    interrupt_mask: u16,
    last_vblank: Instant,
}

impl Duart {
    pub fn new<CB: 'static + FnMut(u8) + Send + Sync>(tx_callback: CB) -> Duart {
        Duart {
            tx_callback: Some(Box::new(tx_callback)),
            mra: 0,
            mrb: 0,
            cra: 0,
            crb: 0,
            sra: 0,
            srb: 0,
            data_a: 0,
            data_b: 0,
            ipcr: 0x40,
            in_port: 0xb,
            interrupt_mask: 0,
            last_vblank: Instant::now(),
        }
    }

    pub fn get_interrupt(&mut self) -> Option<u16> {
        let new_vblank_time: Instant = self.last_vblank + Duration::new(0, VERTICAL_BLANK_DELAY);

        if Instant::now() > new_vblank_time {
            self.last_vblank = Instant::now();
            self.vertical_blank();
        }

        if self.interrupt_mask > 0 {
            let val = self.interrupt_mask;
            self.interrupt_mask = 0;
            Some(val)
        } else {
            return None
        }
    }

    pub fn keyboard(&mut self, keycode: u8) {
        self.interrupt_mask |= KEYBOARD_INT;
        self.data_b = keycode;
        self.srb = TXRDY;
    }

    pub fn vertical_blank(&mut self) {
        self.interrupt_mask |= MOUSE_BLANK_INT;
        self.ipcr = 0x40;
    }

    pub fn mouse_down(&mut self, button: u8) {
        self.interrupt_mask |= MOUSE_BLANK_INT;
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
        trace!("*** Mouse Down: Button {} (IPCR=0x{:02x})", button, self.ipcr);
    }

    pub fn mouse_up(&mut self, button: u8) {
        self.interrupt_mask |= MOUSE_BLANK_INT;
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
        trace!("*** Mouse Up: Button {} (IPCR=0x{:02x})", button, self.ipcr);
    }

    pub fn rx_char(&mut self, character: u8) {
        self.interrupt_mask |= RX_INT;
        self.data_a = character;
        trace!("*** DUART: RX_CHAR (from telnet) 0x{:02x} ({})",
                 character,
                 if character >= 0x20 && character < 127 {
                     character as char
                 } else {
                     '?'
                 });
    }
}

impl Debug for Duart {
    fn fmt(&self, f: &mut Formatter) -> Result<(), Error> {
        write!(f, "[DUART]")
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
        match (address - START_ADDR) as u8 {
            MRA => {
                trace!("*** DUART READ: Mode Status Register A (flip-flop)...");
                Ok(0x21)
            }
            SR_CSRA => {
                trace!("*** DUART READ: Status Register A (RS232)");
                if self.sra > 0 {
                    Ok(self.sra)
                } else {
                    Ok(0x0d)
                }
            }
            TX_RXA => {
                trace!("*** DUART READ: Receive Character (RS232) (0x{:02x})", self.data_a);
                Ok(self.data_a)
            }
            IPCR_ACR => {
                let result = Ok(self.ipcr);
                self.ipcr = 0;
                result
            }
            SR_CSRB => {
                if self.srb > 0 {
                    trace!("*** DUART READ: Status Register B (Keyboard) val=0x{:02x}", self.srb);
                    Ok(self.srb)
                } else {
                    trace!("*** DUART READ: Status Register B (Keyboard) val=0x21");
                    Ok(0x21)
                }
            }
            TX_RXB => {
                trace!("*** DUART READ: Receive Character (Keyboard) (0x{:02x})...", self.data_b);
                Ok(self.data_b)
            }
            IP_OPCR => {
                trace!("*** DUART READ: Input Port (val=0x{:02x})...", self.in_port);
                Ok(self.in_port)
            }
            CTRSTP_OPRESET => {
                trace!("*** DUART READ: Stop Counter Command...");
                Ok(0x01)
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
        match (address - START_ADDR) as u8 {
            CRA => {
                trace!("*** DUART WRITE: Command Register A. (val=0x{:02x})", val);
                self.cra = val;
                self.sra = 0;

                if (val & SR_ENABLE_TX) != 0 {
                    self.interrupt_mask |= TX_INT;
                }
            }
            TX_RXA => {
//                trace!("*** DUART: TX_CHAR (to telnet) 0x{:02x} ({})",
//                         val,
//                         if val >= 0x20 && val < 127 {
//                             val as char
//                         } else {
//                             '?'
//                         });
                self.data_a = val;
                match &mut self.tx_callback {
                    Some(cb) => (cb)(val),
                    None => {}
                };
            }
            CRB => {
                trace!("*** DUART WRITE: Command Register B (Keyboard) (val=0x{:02x})", val);
                self.crb = val;
            }
            TX_RXB => {
                trace!("*** DUART WRITE: Transmit Character (Keyboard) (val=0x{:02x})", val);
                self.data_b = val;
            }
            IP_OPCR => {
                trace!("*** DUART WRITE: Output Port Config (val=0x{:02x})", val);
            }
            CTRSTRT_OPSET => {
                trace!("*** DUART WRITE: Setting output bits (val=0x{:02x})", val);
            }
            _ => {
                // trace!("*** DUART WRITE FALL-THROUGH (port=0x{:02x} val=0x{:02x})", i, val);
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
