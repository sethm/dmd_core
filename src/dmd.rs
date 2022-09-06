#![allow(clippy::unreadable_literal)]

use crate::bus::{AccessCode, Bus};
use crate::cpu::Cpu;
use crate::err::BusError;
use crate::rom_hi::{HI_ROM_V1, HI_ROM_V2};
use crate::rom_lo::{LO_ROM_V1, LO_ROM_V1_LEN, LO_ROM_V2, LO_ROM_V2_LEN};

use libc::*;
use std::ptr;
use std::sync::{Mutex, Once};

lazy_static! {
    pub static ref DMD: Mutex<Dmd> = Mutex::new(Dmd::new());
}

// Return vlaues for the C library
const SUCCESS: c_int = 0;
const ERROR: c_int = 1;
const BUSY: c_int = 2;

static INIT: Once = Once::new();

pub struct Dmd {
    cpu: Cpu,
    bus: Bus,
}

impl Default for Dmd {
    fn default() -> Self {
        Self::new()
    }
}

impl Dmd {
    pub fn new() -> Dmd {
        // Never re-init logging
        INIT.call_once(|| {
            env_logger::init();
        });

        let cpu = Cpu::new();
        let bus = Bus::new(0x100000);
        Dmd {
            cpu,
            bus,
        }
    }

    pub fn reset(&mut self, version: u8) -> Result<(), BusError> {
        match version {
            1 => {
                self.bus.load(0, &LO_ROM_V1)?;
                self.bus.load(LO_ROM_V1_LEN, &HI_ROM_V1)?;
            }
            _ => {
                self.bus.load(0, &LO_ROM_V2)?;
                self.bus.load(LO_ROM_V2_LEN, &HI_ROM_V2)?;
            }
        }

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

    pub fn read_word(&mut self, addr: usize) -> Option<u32> {
        match self.bus.read_word(addr, AccessCode::AddressFetch) {
            Ok(d) => Some(d),
            _ => None,
        }
    }

    pub fn read_byte(&mut self, addr: usize) -> Option<u8> {
        match self.bus.read_byte(addr, AccessCode::AddressFetch) {
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

    pub fn rs232_tx(&mut self) -> Option<u8> {
        self.bus.rs232_tx()
    }

    pub fn keyboard_tx(&mut self) -> Option<u8> {
        self.bus.keyboard_tx()
    }

    pub fn rs232_rx(&mut self, c: u8) {
        self.bus.rs232_rx(c);
    }

    pub fn keyboard_rx(&mut self, keycode: u8) {
        self.bus.keyboard_rx(keycode);
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
fn dmd_init(version: u8) -> c_int {
    match DMD.lock() {
        Ok(mut dmd) => match dmd.reset(version) {
            Ok(()) => SUCCESS,
            Err(_) => ERROR,
        },
        Err(_) => ERROR,
    }
}

#[no_mangle]
fn dmd_video_ram() -> *const u8 {
    match DMD.lock() {
        Ok(dmd) => dmd.video_ram().as_ptr(),
        Err(_) => ptr::null(),
    }
}

#[no_mangle]
fn dmd_step() -> c_int {
    match DMD.lock() {
        Ok(mut dmd) => {
            dmd.step();
            SUCCESS
        }
        Err(_) => ERROR,
    }
}

#[no_mangle]
fn dmd_step_loop(steps: usize) -> c_int {
    match DMD.lock() {
        Ok(mut dmd) => {
            dmd.run(steps);
            SUCCESS
        }
        Err(_) => ERROR,
    }
}

#[no_mangle]
fn dmd_get_pc(pc: &mut u32) -> c_int {
    match DMD.lock() {
        Ok(dmd) => {
            *pc = dmd.get_pc();
            SUCCESS
        }
        Err(_) => ERROR,
    }
}

#[no_mangle]
fn dmd_get_register(reg: u8, val: &mut u32) -> c_int {
    match DMD.lock() {
        Ok(dmd) => {
            *val = dmd.get_register(reg);
            SUCCESS
        }
        Err(_) => ERROR,
    }
}

#[no_mangle]
fn dmd_read_word(addr: u32, val: &mut u32) -> c_int {
    match DMD.lock() {
        Ok(mut dmd) => match dmd.read_word(addr as usize) {
            Some(word) => {
                *val = word;
                SUCCESS
            }
            None => ERROR,
        },
        Err(_) => ERROR,
    }
}

#[no_mangle]
fn dmd_read_byte(addr: u32, val: &mut u8) -> c_int {
    match DMD.lock() {
        Ok(mut dmd) => match dmd.read_byte(addr as usize) {
            Some(byte) => {
                *val = byte;
                SUCCESS
            }
            None => ERROR,
        },
        Err(_) => ERROR,
    }
}

#[no_mangle]
fn dmd_get_duart_output_port(oport: &mut u8) -> c_int {
    match DMD.lock() {
        Ok(dmd) => {
            *oport = dmd.duart_output();
            SUCCESS
        }
        Err(_) => ERROR,
    }
}

#[no_mangle]
fn dmd_mouse_move(x: u16, y: u16) -> c_int {
    match DMD.lock() {
        Ok(mut dmd) => {
            dmd.mouse_move(x, y);
            SUCCESS
        }
        Err(_) => ERROR,
    }
}

#[no_mangle]
fn dmd_mouse_down(button: u8) -> c_int {
    match DMD.lock() {
        Ok(mut dmd) => {
            dmd.mouse_down(button);
            SUCCESS
        }
        Err(_) => ERROR,
    }
}

#[no_mangle]
fn dmd_mouse_up(button: u8) -> c_int {
    match DMD.lock() {
        Ok(mut dmd) => {
            dmd.mouse_up(button);
            SUCCESS
        }
        Err(_) => ERROR,
    }
}

#[no_mangle]
fn dmd_rs232_rx(c: u8) -> c_int {
    match DMD.lock() {
        Ok(mut dmd) => {
            dmd.rs232_rx(c as u8);
            SUCCESS
        }
        Err(_) => ERROR,
    }
}

#[no_mangle]
fn dmd_keyboard_rx(c: u8) -> c_int {
    match DMD.lock() {
        Ok(mut dmd) => {
            dmd.keyboard_rx(c);
            SUCCESS
        }
        Err(_) => ERROR,
    }
}

#[no_mangle]
fn dmd_rs232_tx(tx_char: &mut u8) -> c_int {
    match DMD.lock() {
        Ok(mut dmd) => match dmd.rs232_tx() {
            Some(c) => {
                *tx_char = c;
                SUCCESS
            }
            None => BUSY,
        },
        Err(_) => ERROR,
    }
}

#[no_mangle]
fn dmd_keyboard_tx(tx_char: &mut u8) -> c_int {
    match DMD.lock() {
        Ok(mut dmd) => match dmd.keyboard_tx() {
            Some(c) => {
                *tx_char = c;
                SUCCESS
            }
            None => BUSY,
        },
        Err(_) => ERROR,
    }
}

#[no_mangle]
fn dmd_set_nvram(nvram: &[u8; 8192]) -> c_int {
    match DMD.lock() {
        Ok(mut dmd) => {
            dmd.set_nvram(nvram);
            SUCCESS
        }
        Err(_) => ERROR,
    }
}

#[no_mangle]
fn dmd_get_nvram(nvram: &mut [u8; 8192]) -> c_int {
    match DMD.lock() {
        Ok(dmd) => {
            nvram.clone_from_slice(dmd.get_nvram());
            SUCCESS
        }
        Err(_) => ERROR,
    }
}

#[cfg(test)]
mod tests {
    use crate::dmd::Dmd;

    #[test]
    fn creates_dmd() {
        let mut dmd = Dmd::new();
        dmd.reset(2).unwrap();
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
