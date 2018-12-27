#![allow(clippy::unreadable_literal)]

use crate::bus::{Bus, AccessCode};
use crate::cpu::Cpu;
use crate::err::BusError;
use crate::rom_hi::HI_ROM;
use crate::rom_lo::LO_ROM;

use libc::*;
use std::ptr;
use std::sync::Mutex;

lazy_static! {
    static ref DMD: Mutex<Dmd> = Mutex::new(Dmd::new());
}

// Return vlaues for the C library
const SUCCESS: c_int = 0;
const ERROR: c_int = 1;
const BUSY: c_int = 2;

pub struct Dmd {
    cpu: Cpu,
    bus: Bus,
}

impl Default for Dmd {
    fn default() -> Self {
        Dmd::new()
    }
}

impl Dmd {
    pub fn new() -> Dmd {
        let cpu = Cpu::new();
        let bus = Bus::new(0x100000);
        Dmd {
            cpu,
            bus,
        }
    }

    pub fn reset(&mut self) -> Result<(), BusError> {
        self.bus.load(0, &LO_ROM)?;
        self.bus.load(0x10000, &HI_ROM)?;
        self.cpu.reset(&mut self.bus)?;

        Ok(())
    }

    pub fn video_ram(&self) -> &[u8] {
        self.bus.video_ram()
    }

    pub fn get_pc(&self) -> u32 {
        self.cpu.get_pc()
    }

    pub fn get_ap(&self) -> u32 {
        self.cpu.get_ap()
    }

    pub fn get_psw(&self) -> u32 {
        self.cpu.get_psw()
    }

    pub fn get_register(&self, reg: u8) -> u32 {
        self.cpu.r[(reg & 0xf) as usize]
    }

    pub fn read(&mut self, addr: usize) -> Option<u32> {
        match self.bus.read_word(addr, AccessCode::AddressFetch) {
            Ok(d) => Some(d),
            _ => None,
        }
    }

    pub fn step(&mut self) {
        self.cpu.step(&mut self.bus);
    }

    pub fn run(&mut self, count: usize) {
        for _ in 0..count {
            self.cpu.step(&mut self.bus);
        }
    }

    pub fn rs232_tx_poll(&mut self) -> Option<u8> {
        self.bus.rs232_tx_poll()
    }

    pub fn kb_tx_poll(&mut self) -> Option<u8> {
        self.bus.kb_tx_poll()
    }

    pub fn rx_char(&mut self, character: u8) {
        self.bus.rx_char(character);
    }

    pub fn rx_keyboard(&mut self, keycode: u8) {
        self.bus.rx_keyboard(keycode);
    }

    pub fn mouse_move(&mut self, x: u16, y: u16) {
        self.bus.mouse_move(x, y);
    }

    pub fn mouse_down(&mut self, button: u8) {
        self.bus.mouse_down(button);
    }

    pub fn mouse_up(&mut self, button: u8) {
        self.bus.mouse_up(button);
    }

    pub fn duart_output(&self) -> u8 {
        self.bus.duart_output()
    }

    pub fn set_nvram(&mut self, nvram: &[u8]) {
        self.bus.set_nvram(nvram);
    }

    pub fn get_nvram(&self) -> &[u8] {
        self.bus.get_nvram()
    }
}

//
// Provide a C interface
//

#[no_mangle]
fn dmd_reset() -> c_int {
    match DMD.lock() {
        Ok(mut dmd) => {
            match dmd.reset() {
                Ok(()) => SUCCESS,
                Err(_) => ERROR
            }
        }
        Err(_) => ERROR
    }
}

#[no_mangle]
fn dmd_video_ram() -> *const u8 {
    match DMD.lock() {
        Ok(dmd) => {
            dmd.video_ram().as_ptr()
        }
        Err(_) => ptr::null()
    }
}

#[no_mangle]
fn dmd_step() -> c_int {
    match DMD.lock() {
        Ok(mut dmd) => {
            dmd.step();
            SUCCESS
        }
        Err(_) => ERROR
    }
}

#[no_mangle]
fn dmd_step_loop(steps: usize) -> c_int {
    match DMD.lock() {
        Ok(mut dmd) => {
            dmd.run(steps);
            SUCCESS
        },
        Err(_) => ERROR
    }
}

#[no_mangle]
fn dmd_get_pc(pc: &mut uint32_t) -> c_int {
    match DMD.lock() {
        Ok(dmd) => {
            *pc = dmd.get_pc();
            SUCCESS
        },
        Err(_) => ERROR
    }
}

#[no_mangle]
fn dmd_get_register(reg: uint8_t, val: &mut uint32_t) -> c_int {
    match DMD.lock() {
        Ok(dmd) => {
            *val = dmd.get_register(reg);
            SUCCESS
        },
        Err(_) => ERROR
    }
}

#[no_mangle]
fn dmd_get_duart_output_port(oport: &mut uint8_t) -> c_int {
    match DMD.lock() {
        Ok(dmd) => {
            *oport = dmd.duart_output();
            SUCCESS
        }
        Err(_) => ERROR
    }
}

#[no_mangle]
fn dmd_rx_char(c: uint8_t) -> c_int {
    match DMD.lock() {
        Ok(mut dmd) => {
            dmd.rx_char(c as u8);
            SUCCESS
        }
        Err(_) => ERROR
    }
}

#[no_mangle]
fn dmd_rx_keyboard(c: uint8_t) -> c_int {
    match DMD.lock() {
        Ok(mut dmd) => {
            dmd.rx_keyboard(c);
            SUCCESS
        }
        Err(_) => ERROR
    }
}

#[no_mangle]
fn dmd_mouse_move(x: uint16_t, y: uint16_t) -> c_int {
    match DMD.lock() {
        Ok(mut dmd) => {
            dmd.mouse_move(x, y);
            SUCCESS
        }
        Err(_) => ERROR
    }
}

#[no_mangle]
fn dmd_mouse_down(button: uint8_t) -> c_int {
    match DMD.lock() {
        Ok(mut dmd) => {
            dmd.mouse_down(button);
            SUCCESS
        }
        Err(_) => ERROR
    }
}

#[no_mangle]
fn dmd_mouse_up(button: uint8_t) -> c_int {
    match DMD.lock() {
        Ok(mut dmd) => {
            dmd.mouse_up(button);
            SUCCESS
        }
        Err(_) => ERROR
    }
}

#[no_mangle]
fn dmd_rs232_tx_poll(tx_char: &mut uint8_t) -> c_int {
    match DMD.lock() {
        Ok(mut dmd) => {
            match dmd.rs232_tx_poll() {
                Some(c) => {
                    *tx_char = c;
                    SUCCESS
                }
                None => BUSY
            }
        }
        Err(_) => ERROR
    }
}

#[no_mangle]
fn dmd_kb_tx_poll(tx_char: &mut uint8_t) -> c_int {
    match DMD.lock() {
        Ok(mut dmd) => {
            match dmd.kb_tx_poll() {
                Some(c) => {
                    *tx_char = c;
                    SUCCESS
                }
                None => BUSY
            }
        }
        Err(_) => ERROR
    }
}

#[no_mangle]
fn dmd_set_nvram(nvram: &[u8; 8192]) -> c_int {
    match DMD.lock() {
        Ok(mut dmd) => {
            dmd.set_nvram(nvram);
            SUCCESS
        }
        Err(_) => ERROR
    }
}

#[no_mangle]
fn dmd_get_nvram(nvram: &mut [u8]) -> c_int {
    match DMD.lock() {
        Ok(dmd) => {
            nvram.clone_from_slice(&dmd.get_nvram());
            SUCCESS
        }
        Err(_) => ERROR
    }
}

#[cfg(test)]
mod tests {
    use crate::dmd::Dmd;

    #[test]
    fn creates_dmd() {
        let mut dmd = Dmd::new();
        dmd.reset().unwrap();
    }

    #[test]
    fn loads_and_reads_nvram() {
        let mut dmd = Dmd::new();

        let mut to_load: [u8; 8192] = [0; 8192];
        to_load[0] = 0x5a;
        to_load[0xfff] = 0xa5;
        to_load[0x1fff] = 0xff;

        let old_nvram = dmd.get_nvram();

        assert_eq!(0, old_nvram[0]);
        assert_eq!(0, old_nvram[0xfff]);
        assert_eq!(0, old_nvram[0x1fff]);

        dmd.set_nvram(&to_load);

        let new_nvram = dmd.get_nvram();

        assert_eq!(0x5a, new_nvram[0]);
        assert_eq!(0xa5, new_nvram[0xfff]);
        assert_eq!(0xff, new_nvram[0x1fff]);
    }
}