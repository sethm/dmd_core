/// The 2681 DUART has two I/O UARTs, each one represented by the
/// `Port` struct. The first is used only for the EIA RS232 serial
/// port. The second is duplexed between keyboard I/O and a write-only
/// parallel printer port.
///
/// Each of the two UARTs simulates the following hardware registers:
///
///   - Two MODE registers, duplexed at the same PIO address, with a
///     pointer that auto-increments on write.
///
///   - One STATUS register.
///
///   - One CONFIGURATION register.
///
///   - One RECEIVE FIFO with 3 slots. Reading from PIO reads from this
///     FIFO.
///
///   - One RECEIVE shift register that holds bits as they come in,
///     before they are pushed onto the FIFO.
///
///   - One TRANSMIT holding register. Writing to PIO writes to this
///     register.
///
///   - One TRANSMIT shift register that latches the data from the
///     holding register and shifts them out onto the serial line.
///
/// In addition to simulating these hardware registers, this
/// implementation has a TX queue and an RX queue. These queues do not
/// exist in hardware.  They are used to buffer data sent and received
/// by users of this library for maximum flexibility, since polling for
/// I/O may take place at any unknown rate. The simulated UART will
/// poll the RX queue whenever the RX FIFO is not full. It will push
/// data onto the TX queue as soon as possible after it has been moved
/// into the TX shift register.
///
/// The 2681 DUART is well documented in its datasheet.
///
use crate::bus::{AccessCode, Device};
use crate::err::BusError;

use log::{debug, trace};
use ringbuffer::{
    ConstGenericRingBuffer, RingBuffer, RingBufferExt, RingBufferRead, RingBufferWrite,
};
use std::collections::VecDeque;
use std::fmt::Debug;
use std::fmt::Error;
use std::fmt::Formatter;
use std::ops::Range;
use std::time::Duration;
use std::time::Instant;

const START_ADDR: usize = 0x200000;
const END_ADDR: usize = 0x2000040;
const ADDRESS_RANGE: Range<usize> = START_ADDR..END_ADDR;

// Vertical blanks should occur at 60Hz. This value is in nanoseconds
const VERTICAL_BLANK_DELAY: u32 = 16_666_666; // 60 Hz

const BAUD_RATES_A: [u32; 13] =
    [50, 110, 135, 200, 300, 600, 1200, 1050, 2400, 4800, 7200, 9600, 38400];

const BAUD_RATES_B: [u32; 13] =
    [75, 110, 135, 150, 300, 600, 1200, 2000, 2400, 4800, 1800, 9600, 19200];

const PORT_0: usize = 0;
const PORT_1: usize = 1;

//
// Registers
//
const MR12A: u8 = 0x03;
const CSRA: u8 = 0x07;
const CRA: u8 = 0x0b;
const THRA: u8 = 0x0f;
const RHRA: u8 = 0x0f;
const IPCR_ACR: u8 = 0x13;
const ISR_MASK: u8 = 0x17;
const MR12B: u8 = 0x23;
const CSRB: u8 = 0x27;
const CRB: u8 = 0x2b;
const THRB: u8 = 0x2f;
const RHRB: u8 = 0x2f;
const IP_OPCR: u8 = 0x37;
const OPBITS_SET: u8 = 0x3b;
const OPBITS_RESET: u8 = 0x3f;

//
// Port Configuration Bits
//
const CNF_ETX: u8 = 0x01; // TX Enabled
const CNF_ERX: u8 = 0x02; // RX Enabled

//
// Status Flags
//
const STS_RXR: u8 = 0x01; // Rx Ready
const STS_FFL: u8 = 0x02; // FIFO Full
const STS_TXR: u8 = 0x04; // Tx Ready
const STS_TXE: u8 = 0x08; // Tx Register Empty
const STS_OER: u8 = 0x10; // Overflow Error
const STS_PER: u8 = 0x20; // Parity Error
const STS_FER: u8 = 0x40; // Framing Error
const STS_RXB: u8 = 0x80; // Received Break

//
// Command Register Commands
//
const CMD_ERX: u8 = 0x01;
const CMD_DRX: u8 = 0x02;
const CMD_ETX: u8 = 0x04;
const CMD_DTX: u8 = 0x08;

//
// Control Register Commands
//
const CR_RST_MR: u8 = 0x01;
const CR_RST_RX: u8 = 0x02;
const CR_RST_TX: u8 = 0x03;
const CR_RST_ERR: u8 = 0x04;
const CR_RST_BRK: u8 = 0x05;
const CR_START_BRK: u8 = 0x06;
const CR_STOP_BRK: u8 = 0x07;

//
// Interrupt Status Register
//
const ISTS_TAI: u8 = 0x01; // Transmitter A Ready Interrupt
const ISTS_RAI: u8 = 0x02; // Receiver A Ready Interrupt
const ISTS_DBA: u8 = 0x04; // Delta Break A
const ISTS_TBI: u8 = 0x10; // Transmitter B Ready Interrupt
const ISTS_RBI: u8 = 0x20; // Receiver B Ready Interrupt
const ISTS_DBB: u8 = 0x40; // Delta Break B
const ISTS_IPC: u8 = 0x80; // Interrupt Port Change

//
// CPU Interrupt Vectors.
//
const KEYBOARD_INT: u8 = 0x04;
const MOUSE_BLANK_INT: u8 = 0x02;
const TX_INT: u8 = 0x10;
const RX_INT: u8 = 0x20;

// NB: The terrible Ring Buffer library requries capacities with a
// power of 2, so we have to have extra logic to deal with this!
//
// TODO: Pick a new ring buffer library or just implement our own
// 3-slot FIFO.
const RX_FIFO_LEN: usize = 3;
const RX_FIFO_INIT_LEN: usize = 4;

struct Port {
    // Mode, Status, and Configuration registers
    mode: [u8; 2],
    mode_ptr: usize,
    stat: u8,
    conf: u8,
    // State used by the RX and TX state machines.
    rx_fifo: ConstGenericRingBuffer<u8, RX_FIFO_INIT_LEN>,
    rx_shift_reg: Option<u8>,
    tx_holding_reg: Option<u8>,
    tx_shift_reg: Option<u8>,
    // Buffers to hold TX and RX characters so that they can be
    // processed by the user of this library in chunks.
    rx_deque: VecDeque<u8>,
    tx_deque: VecDeque<u8>,
    // Service timing info
    char_delay: Duration,
    next_tx_service: Instant,
    next_rx_service: Instant,
}

impl Port {
    fn new() -> Port {
        Port {
            mode: [0; 2],
            mode_ptr: 0,
            stat: 0,
            conf: 0,
            rx_fifo: ConstGenericRingBuffer::<u8, RX_FIFO_INIT_LEN>::new(),
            rx_shift_reg: None,
            tx_holding_reg: None,
            tx_shift_reg: None,
            rx_deque: VecDeque::new(),
            tx_deque: VecDeque::new(),
            char_delay: Duration::new(0, 1_000_000),
            next_tx_service: Instant::now(),
            next_rx_service: Instant::now(),
        }
    }

    /// Read a single character out of the RX channel.
    ///
    /// The character is read out of the FIFO, which is drained of one
    /// slot. If a character is currently in the shift register, it is
    /// moved into the FIFO now that there is room.
    fn rx_read_char(&mut self) -> Option<u8> {
        if self.rx_enabled() {
            let val = self.rx_fifo.dequeue();

            // The FIFO is no longer full (even if only temporarily)
            self.stat &= !STS_FFL;

            // If the RX shift register held a character, it's time
            // to move it into the FIFO.
            if let Some(c) = self.rx_shift_reg {
                self.rx_fifo.push(c);
                self.stat |= STS_RXR;
                if self.rx_fifo.len() >= RX_FIFO_LEN {
                    self.stat |= STS_FFL;
                }
            }

            // If the FIFO is now empty, mark it as such.
            if self.rx_fifo.is_empty() {
                self.stat &= !STS_RXR;
            }

            // Reset Parity Error and Received Break on read
            self.stat &= !(STS_PER | STS_RXB);

            val
        } else {
            None
        }
    }

    /// Receiver a single character.
    ///
    /// If there is room in the FIFO, the character is immediately
    /// stored there. If not, it is stored in the shift register until
    /// room becomes available. The shift register is overwitten if a
    /// new character is received while the FIFO is full.
    fn rx_char(&mut self, c: u8) {
        trace!("rx_char: {:02x}, fifo_len={}", c, self.rx_fifo.len());
        if self.rx_fifo.len() < RX_FIFO_LEN {
            self.rx_fifo.push(c);
            if self.rx_fifo.len() >= RX_FIFO_LEN {
                trace!("FIFO FULL.");
                self.stat |= STS_FFL;
            }
        } else {
            // The FIFO is full, and now we're going to have to
            // hold a character in the shift register until space
            // is available.
            //
            // If the register already had data, it's going to be
            // overwritten, so we have to set the overflow flag.
            if self.rx_shift_reg.is_some() {
                self.stat |= STS_OER;
            }

            self.rx_shift_reg = Some(c);
        }

        // In either case, RxRDY is now true.
        self.stat |= STS_RXR;
    }

    /// Move the receiver state machine
    fn rx_service(&mut self) {
        let rx_service_needed = self.rx_enabled()
            && !self.rx_deque.is_empty()
            && Instant::now() >= self.next_rx_service;

        if !rx_service_needed {
            // Nothing to do.
            return;
        }

        if !self.loopback() {
            if let Some(c) = self.rx_deque.pop_back() {
                self.rx_char(c);
            }
        }

        self.next_rx_service = Instant::now() + self.char_delay;
    }

    /// Move the transmitter state machine.
    fn tx_service(&mut self, keyboard: bool) {
        if self.tx_holding_reg.is_none() && self.tx_shift_reg.is_none() {
            // Nothing to do
            return;
        }

        if Instant::now() >= self.next_tx_service {
            // Check for data in the transmitter shift register that's
            // ready to go out to the RS232 output buffer
            if let Some(c) = self.tx_shift_reg {
                trace!("RS232 TX: {:02x}", c);
                if self.loopback() {
                    debug!("RS232 TX: LOOPBACK: Finish transmit character {:02x}", c);
                    self.rx_char(c);
                } else {
                    if keyboard && c == 0x02 {
                        self.stat |= STS_PER;
                    }
                    debug!("RS232 TX: Finish transmit character {:02x}", c);
                    self.tx_deque.push_front(c);
                }

                self.tx_shift_reg = None;
                if self.tx_holding_reg.is_none() {
                    self.stat |= STS_TXR;
                    self.stat |= STS_TXE;
                }
            }

            // Check for data in the holding register that's ready to go
            // out to the shift register.
            if let Some(c) = self.tx_holding_reg {
                self.tx_shift_reg = Some(c);
                // Clear the holding register
                self.tx_holding_reg = None;
                // Ready for a new character
                self.next_tx_service = Instant::now() + self.char_delay;
            }
        }
    }

    fn loopback(&self) -> bool {
        (self.mode[1] & 0xc0) == 0x80
    }

    fn rx_enabled(&self) -> bool {
        (self.conf & CNF_ERX) != 0
    }

    fn enable_tx(&mut self) {
        self.conf |= CNF_ETX;
        if self.tx_holding_reg.is_none() {
            self.stat |= STS_TXR;
        }
        if self.tx_shift_reg.is_none() {
            self.stat |= STS_TXE;
        }
    }

    fn disable_tx(&mut self) {
        self.conf &= !CNF_ETX;
        self.stat &= !(STS_TXR | STS_TXE);
    }

    fn enable_rx(&mut self) {
        self.conf |= CNF_ERX;
        self.stat &= !STS_RXR;
    }

    fn disable_rx(&mut self) {
        self.conf &= !CNF_ERX;
        self.stat &= !STS_RXR;
    }
}

pub struct Duart {
    ports: [Port; 2],
    acr: u8,
    ipcr: u8,
    inprt: u8,
    outprt: u8,
    isr: u8,
    imr: u8,
    // TODO: Interrupts are set manually by tweaking this vector,
    // which doesn't actually exist on the real duart. We should fix
    // that, because DAMN.
    ivec: u8,
    next_vblank: Instant,
}

impl Default for Duart {
    fn default() -> Self {
        Duart::new()
    }
}

/// Compute the delay rate to wait for the next transmit or receive
fn delay_rate(csr_bits: u8, acr_bits: u8) -> Duration {
    const NS_PER_SEC: u32 = 1_000_000_000;
    const BITS_PER_CHAR: u32 = 10;

    let baud_bits: usize = ((csr_bits >> 4) & 0xf) as usize;
    let baud_rate = if acr_bits & 0x80 == 0 {
        BAUD_RATES_A[baud_bits]
    } else {
        BAUD_RATES_B[baud_bits]
    };

    Duration::new(0, NS_PER_SEC / (baud_rate / BITS_PER_CHAR))
}

impl Duart {
    pub fn new() -> Duart {
        Duart {
            ports: [Port::new(), Port::new()],
            acr: 0,
            ipcr: 0x40,
            inprt: 0xb,
            outprt: 0,
            isr: 0,
            imr: 0,
            ivec: 0,
            next_vblank: Instant::now() + Duration::new(0, VERTICAL_BLANK_DELAY),
        }
    }

    pub fn get_interrupt(&mut self) -> Option<u8> {
        if Instant::now() > self.next_vblank {
            self.next_vblank = Instant::now() + Duration::new(0, VERTICAL_BLANK_DELAY);
            self.vertical_blank();
        }

        // Mask in keyboard and RS232 RX interrupts
        if (self.ports[PORT_0].stat & STS_RXR) != 0 {
            self.ivec |= RX_INT;
            self.isr |= ISTS_RAI;
        }

        if (self.ports[PORT_1].stat & STS_RXR) != 0 {
            self.ivec |= KEYBOARD_INT;
            self.isr |= ISTS_RBI;
        }

        if (self.ports[PORT_0].stat & STS_TXR) != 0 {
            self.ivec |= TX_INT;
            self.isr |= ISTS_TAI;
        }

        let val = self.ivec;

        if val == 0 {
            None
        } else {
            Some(val)
        }
    }

    pub fn service(&mut self) {
        self.ports[PORT_0].tx_service(false);
        self.ports[PORT_0].rx_service();
        self.ports[PORT_1].tx_service(true);
        self.ports[PORT_1].rx_service();
    }

    pub fn vertical_blank(&mut self) {
        self.ivec |= MOUSE_BLANK_INT;
        self.ipcr |= 0x40;
        self.isr |= ISTS_IPC;

        if self.inprt & 0x04 == 0 {
            self.ipcr |= 0x40;
        } else {
            self.inprt &= !0x04;
        }
    }

    pub fn output_port(&self) -> u8 {
        // The output port always returns a complement of the bits
        debug!("READ: Output Port: {:02x}", !self.outprt);
        !self.outprt
    }

    /// Queue a single character for processing by the rs232 port.
    pub fn rs232_rx(&mut self, c: u8) {
        self.ports[PORT_0].rx_deque.push_front(c);
    }

    /// Queue a single character for processing by the keyboard port
    pub fn keyboard_rx(&mut self, c: u8) {
        self.ports[PORT_1].rx_deque.push_front(c);
    }

    pub fn rs232_tx(&mut self) -> Option<u8> {
        self.ports[PORT_0].tx_deque.pop_back()
    }

    pub fn keyboard_tx(&mut self) -> Option<u8> {
        self.ports[PORT_1].tx_deque.pop_back()
    }

    pub fn mouse_down(&mut self, button: u8) {
        self.ipcr = 0;
        self.inprt |= 0xb;
        self.isr |= ISTS_IPC;
        self.ivec |= MOUSE_BLANK_INT;
        match button {
            0 => {
                self.ipcr |= 0x80;
                self.inprt &= !(0x08);
            }
            1 => {
                self.ipcr |= 0x20;
                self.inprt &= !(0x02);
            }
            2 => {
                self.ipcr |= 0x10;
                self.inprt &= !(0x01)
            }
            _ => {}
        }
    }

    pub fn mouse_up(&mut self, button: u8) {
        self.ipcr = 0;
        self.inprt |= 0xb;
        self.isr |= ISTS_IPC;
        self.ivec |= MOUSE_BLANK_INT;
        match button {
            0 => {
                self.ipcr |= 0x80;
            }
            1 => {
                self.ipcr |= 0x20;
            }
            2 => {
                self.ipcr |= 0x10;
            }
            _ => {}
        }
    }

    fn handle_command(&mut self, cmd: u8, port_no: usize) {
        let mut port = &mut self.ports[port_no];

        let (tx_ists, rx_ists, dbk_ists) = match port_no {
            PORT_0 => (ISTS_TAI, ISTS_RAI, ISTS_DBA),
            _ => (ISTS_TBI, ISTS_RBI, ISTS_DBB),
        };

        // Enable or disable transmitter. Disable always wins if both
        // are set.
        if cmd & CMD_DTX != 0 {
            debug!("Command: Disable TX");
            port.disable_tx();
            self.ivec &= !TX_INT; // XXX: Rethink interrupt vector setting.
            self.isr &= !tx_ists;
        } else if cmd & CMD_ETX != 0 {
            debug!("Command: Enable TX");
            port.enable_tx();
            self.ivec |= TX_INT; // XXX: Rethink interrupt vector setting
            self.isr |= tx_ists;
        }

        // Enable or disable receiver. Disable always wins, if both are set.
        if cmd & CMD_DRX != 0 {
            debug!("Command: Disable RX");
            port.disable_rx();
            self.isr &= !rx_ists;
            if port_no == PORT_0 {
                self.ivec &= !RX_INT; // XXX: Rethink interrupt vector setting
                self.isr &= !ISTS_RAI;
            } else {
                self.ivec &= !KEYBOARD_INT; // XXX: Rethink interrupt vector setting
                self.isr &= !ISTS_RBI;
            }
        } else if cmd & CMD_ERX != 0 {
            debug!("Command: Enable RX");
            port.enable_rx();
        }

        // Extra commands
        match (cmd >> 4) & 7 {
            CR_RST_MR => {
                debug!("PORT{}: Reset MR Pointer.", port_no);
                port.mode_ptr = 0
            }
            CR_RST_RX => {
                // Reset the channel's receiver as if a hardware reset
                // had been performed. The receiver is disabled and
                // the FIFO is flushed.
                debug!("PORT{}: Reset RX.", port_no);
                port.stat &= !STS_RXR;
                port.conf &= !CNF_ERX;
                port.rx_fifo.clear();
                port.rx_shift_reg = None;
            }
            CR_RST_TX => {
                // Reset the channel's transmitter as if a hardware reset
                // had been performed.
                debug!("PORT{}: Reset TX.", port_no);
                port.stat &= !(STS_TXR | STS_TXE);
                port.conf &= !CNF_ETX;
                port.tx_holding_reg = None;
                port.tx_shift_reg = None;
            }
            CR_RST_ERR => {
                debug!("PORT{}: Reset Error.", port_no);
                port.stat &= !(STS_RXB | STS_FER | STS_PER | STS_OER);
            }
            CR_RST_BRK => {
                // Reset the channel's Delta Break interrupt. Causes
                // the channel's break detect change bit in the
                // interrupt status register to be cleared to 0.
                debug!("PORT{}: Reset Break Interrupt.", port_no);
                self.isr &= !dbk_ists;
            }
            CR_START_BRK => {
                debug!("PORT{}: Start Break.", port_no);
                if port.loopback() {
                    // We only care about a BREAK condition if it's
                    // looping back to te receiver.
                    //
                    // TODO: We may want to expose a BREAK condition
                    // to the outside world at some point.
                    port.stat |= STS_RXB | STS_PER;
                    // Set "Delta Break"
                    self.isr |= dbk_ists;
                }
            }
            CR_STOP_BRK => {
                debug!("PORT{}: Stop Break.", port_no);
                if port.loopback() {
                    // We only care about a BREAK condition if it's
                    // looping back to te receiver.
                    //
                    // Set "Delta Break"
                    self.isr |= dbk_ists;
                }
            }
            _ => {}
        }
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
            MR12A => {
                let mut ctx = &mut self.ports[PORT_0];
                let val = ctx.mode[ctx.mode_ptr];
                ctx.mode_ptr = (ctx.mode_ptr + 1) % 2;
                trace!("READ : MR12A, val={:02x}", val);
                Ok(val)
            }
            CSRA => {
                let val = self.ports[PORT_0].stat;
                trace!("READ : CSRA, val={:02x}", val);
                Ok(val)
            }
            RHRA => {
                let ctx = &mut self.ports[PORT_0];
                self.isr &= !ISTS_RAI;
                self.ivec &= !RX_INT;
                let val = if let Some(c) = ctx.rx_read_char() {
                    c
                } else {
                    0
                };
                debug!("READ : RHRA, val={:02x}", val);
                Ok(val)
            }
            IPCR_ACR => {
                let val = self.ipcr;
                self.ipcr &= !0x0f;
                self.ivec = 0;
                self.isr &= !ISTS_IPC;
                trace!("READ : IPCR_ACR, val={:02x}", val);
                Ok(val)
            }
            ISR_MASK => {
                let val = self.isr;
                trace!("READ : ISR_MASK, val={:02x}", val);
                Ok(val)
            }
            MR12B => {
                let mut ctx = &mut self.ports[PORT_1];
                let val = ctx.mode[ctx.mode_ptr];
                ctx.mode_ptr = (ctx.mode_ptr + 1) % 2;
                trace!("READ : MR12B, val={:02x}", val);
                Ok(val)
            }
            CSRB => {
                let val = self.ports[PORT_1].stat;
                trace!("READ : CSRB, val={:02x}", val);
                Ok(val)
            }
            RHRB => {
                let ctx = &mut self.ports[PORT_1];
                self.isr &= !ISTS_RAI;
                self.ivec &= !KEYBOARD_INT;
                let val = if let Some(c) = ctx.rx_read_char() {
                    c
                } else {
                    0
                };
                debug!("READ : RHRB, val={:02x}", val);
                Ok(val)
            }
            IP_OPCR => {
                let val = self.inprt;
                trace!("READ : IP_OPCR val={:02x}", val);
                Ok(val)
            }
            _ => {
                trace!("READ : UNHANDLED. ADDRESS={:08x}", address);
                Err(BusError::NoDevice(address))
            }
        }
    }

    fn read_half(&mut self, address: usize, access: AccessCode) -> Result<u16, BusError> {
        let b = self.read_byte(address + 2, access)?;
        Ok(u16::from(b))
    }

    fn read_word(&mut self, address: usize, access: AccessCode) -> Result<u32, BusError> {
        let b = self.read_byte(address + 3, access)?;
        Ok(u32::from(b))
    }

    fn write_byte(&mut self, address: usize, val: u8, _access: AccessCode) -> Result<(), BusError> {
        match (address - START_ADDR) as u8 {
            MR12A => {
                trace!("WRITE: MR12A, val={:02x}", val);
                let mut ctx = &mut self.ports[PORT_0];
                ctx.mode[ctx.mode_ptr] = val;
                ctx.mode_ptr = (ctx.mode_ptr + 1) % 2;
            }
            CSRA => {
                trace!("WRITE: CSRA, val={:02x}", val);
                let mut ctx = &mut self.ports[PORT_0];
                ctx.char_delay = delay_rate(val, self.acr);
            }
            CRA => {
                trace!("WRITE: CRA, val={:02x}", val);
                self.handle_command(val, PORT_0);
            }
            THRA => {
                let mut ctx = &mut self.ports[PORT_0];
                debug!("WRITE: THRA, val={:02x}", val);
                ctx.tx_holding_reg = Some(val);
                // TxRDY and TxEMT are both de-asserted on load.
                ctx.stat &= !(STS_TXR | STS_TXE);
                self.isr &= !ISTS_TAI;
            }
            IPCR_ACR => {
                trace!("WRITE: IPCR_ACR, val={:02x}", val);
                self.acr = val;
                // TODO: Update baud rate generator
            }
            ISR_MASK => {
                trace!("WRITE: ISR_MASK, val={:02x}", val);
                self.imr = val;
            }
            MR12B => {
                trace!("WRITE: MR12B, val={:02x}", val);
                let mut ctx = &mut self.ports[PORT_1];
                ctx.mode[ctx.mode_ptr] = val;
                ctx.mode_ptr = (ctx.mode_ptr + 1) % 2;
            }
            CSRB => {
                trace!("WRITE: CSRB, val={:02x}", val);
                let mut ctx = &mut self.ports[PORT_1];
                ctx.char_delay = delay_rate(val, self.acr);
            }
            CRB => {
                trace!("WRITE: CRB, val={:02x}", val);
                self.handle_command(val, PORT_1);
            }
            THRB => {
                debug!("WRITE: THRB, val={:02x}", val);
                // TODO: When OP3 is low, do not send data to
                // the keyboard! It's meant for the printer.
                let mut ctx = &mut self.ports[PORT_1];
                ctx.tx_holding_reg = Some(val);
                // TxRDY and TxEMT are both de-asserted on load.
                ctx.stat &= !(STS_TXR | STS_TXE);
                self.isr &= !ISTS_TBI;
            }
            IP_OPCR => {
                trace!("WRITE: IP_OPCR, val={:02x}", val);
                // Not implemented
            }
            OPBITS_SET => {
                trace!("WRITE: OPBITS_SET, val={:02x}", val);
                self.outprt |= val;
            }
            OPBITS_RESET => {
                trace!("WRITE: OPBITS_RESET, val={:02x}", val);
                self.outprt &= !val;
            }
            _ => {
                trace!("WRITE: UNHANDLED. ADDRESS={:08x}", address);
            }
        };

        Ok(())
    }

    fn write_half(&mut self, address: usize, val: u16, access: AccessCode) -> Result<(), BusError> {
        self.write_byte(address + 2, val as u8, access)
    }

    fn write_word(&mut self, address: usize, val: u32, access: AccessCode) -> Result<(), BusError> {
        self.write_byte(address + 3, val as u8, access)
    }

    fn load(&mut self, _address: usize, _data: &[u8]) -> Result<(), BusError> {
        unimplemented!()
    }
}
