use bus::{AccessCode, Bus};
use err::*;
use instr::*;
use std::collections::HashMap;

///
/// PSW Flags
///
#[allow(dead_code)]
const F_ET: u32 = 0x00000003;
#[allow(dead_code)]
const F_TM: u32 = 0x00000004;
const F_ISC: u32 = 0x00000078;
const F_I: u32 = 0x00000080;
#[allow(dead_code)]
const F_R: u32 = 0x00000100;
const F_PM: u32 = 0x00000600;
const F_CM: u32 = 0x00001800;
#[allow(dead_code)]
const F_IPL: u32 = 0x0001e000;
#[allow(dead_code)]
const F_TE: u32 = 0x00020000;
const F_C: u32 = 0x00040000;
const F_V: u32 = 0x00080000;
const F_Z: u32 = 0x00100000;
const F_N: u32 = 0x00200000;
#[allow(dead_code)]
const F_OE: u32 = 0x00400000;
#[allow(dead_code)]
const F_CD: u32 = 0x00800000;
#[allow(dead_code)]
const F_QIE: u32 = 0x01000000;
#[allow(dead_code)]
const F_CFD: u32 = 0x02000000;

///
/// Register Indexes
///
const R_FP: usize = 9;
const R_AP: usize = 10;
const R_PSW: usize = 11;
const R_SP: usize = 12;
const R_PCBP: usize = 13;
#[allow(dead_code)]
const R_ISP: usize = 14;
const R_PC: usize = 15;

#[allow(dead_code)]
#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub enum AddrMode {
    None,
    Absolute,
    AbsoluteDeferred,
    ByteDisplacement,
    ByteDisplacementDeferred,
    HalfwordDisplacement,
    HalfwordDisplacementDeferred,
    WordDisplacement,
    WordDisplacementDeferred,
    APShortOffset,
    FPShortOffset,
    ByteImmediate,
    HalfwordImmediate,
    WordImmediate,
    PositiveLiteral,
    NegativeLiteral,
    Register,
    RegisterDeferred,
    Expanded,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum OpType {
    Lit,
    Src,
    Dest,
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum Data {
    None,
    Byte,
    // a.k.a. UByte
    Half,
    // a.k.a. SHalf
    Word,
    // a.k.a. SWord
    SByte,
    UHalf,
    UWord,
}

#[allow(dead_code)]
#[derive(Eq, PartialEq, Debug, Copy, Clone)]
pub enum CpuMode {
    User,
    Supervisor,
    Executive,
    Kernel,
}

#[derive(Eq, PartialEq, Debug)]
pub struct Operand {
    pub size: u8,
    pub mode: AddrMode,
    data_type: Data,
    expanded_type: Option<Data>,
    pub register: Option<usize>,
    pub embedded: u32,
}

impl Operand {
    fn new(
        size: u8,
        mode: AddrMode,
        data_type: Data,
        expanded_type: Option<Data>,
        register: Option<usize>,
        embedded: u32,
    ) -> Operand {
        Operand {
            size,
            mode,
            data_type,
            expanded_type,
            register,
            embedded,
        }
    }

    fn data_type(&self) -> Data {
        match self.expanded_type {
            Some(t) => t,
            None => self.data_type,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Mnemonic {
    opcode: u16,
    dtype: Data,
    name: &'static str,
    ops: Vec<OpType>,
}

#[allow(dead_code)]
#[derive(Debug, Eq, PartialEq)]
pub struct DecodedInstruction<'a> {
    mnemonic: &'a Mnemonic,
    bytes: u8,
    operands: Vec<Operand>,
}

macro_rules! mn {
    ($opcode:expr, $dtype:expr, $name:expr, $ops:expr) => {
        Mnemonic {
            opcode: $opcode,
            dtype: $dtype,
            name: $name,
            ops: $ops,
        }
    };
}

fn sign_extend_halfword(data: u16) -> u32 {
    ((data as i16) as i32) as u32
}

fn sign_extend_byte(data: u8) -> u32 {
    ((data as i8) as i32) as u32
}

fn add_offset(val: u32, offset: u32) -> u32 {
    ((val as i32).wrapping_add(offset as i32)) as u32
}

lazy_static! {
    static ref MNEMONICS: HashMap<u16, Mnemonic> = {
        let mut m = HashMap::new();

        m.insert(0x00, mn!(0x00, Data::None, "halt", vec!()));
        m.insert(0x02, mn!(0x02, Data::Word, "SPOPRD", vec!(OpType::Lit, OpType::Src)));
        m.insert(0x03, mn!(0x03, Data::Word, "SPOPRD2", vec!(OpType::Lit, OpType::Src, OpType::Dest)));
        m.insert(0x04, mn!(0x04, Data::Word, "MOVAW", vec!(OpType::Src, OpType::Dest)));
        m.insert(0x06, mn!(0x06, Data::Word, "SPOPRT", vec!(OpType::Lit, OpType::Src)));
        m.insert(0x07, mn!(0x07, Data::Word, "SPOPT2", vec!(OpType::Lit, OpType::Src, OpType::Dest)));
        m.insert(0x08, mn!(0x08, Data::None, "RET", vec!()));
        m.insert(0x0C, mn!(0x0C, Data::Word, "MOVTRW", vec!(OpType::Src, OpType::Dest)));
        m.insert(0x10, mn!(0x10, Data::Word, "SAVE", vec!(OpType::Src)));
        m.insert(0x13, mn!(0x13, Data::Word, "SPOPWD", vec!(OpType::Lit, OpType::Dest)));
        m.insert(0x14, mn!(0x14, Data::Byte, "EXTOP", vec!()));
        m.insert(0x17, mn!(0x17, Data::Word, "SPOPWT", vec!(OpType::Lit, OpType::Dest)));
        m.insert(0x18, mn!(0x18, Data::None, "RESTORE", vec!(OpType::Src)));
        m.insert(0x1C, mn!(0x1C, Data::Word, "SWAPWI", vec!(OpType::Dest)));
        m.insert(0x1E, mn!(0x1E, Data::Half, "SWAPHI", vec!(OpType::Dest)));
        m.insert(0x1F, mn!(0x1F, Data::Byte, "SWAPBI", vec!(OpType::Dest)));
        m.insert(0x20, mn!(0x20, Data::Word, "POPW", vec!(OpType::Src)));
        m.insert(0x22, mn!(0x22, Data::Word, "SPOPRS", vec!(OpType::Lit, OpType::Src)));
        m.insert(0x23, mn!(0x23, Data::Word, "SPOPS2", vec!(OpType::Lit, OpType::Src, OpType::Dest)));
        m.insert(0x24, mn!(0x24, Data::Word, "JMP", vec!(OpType::Dest)));
        m.insert(0x27, mn!(0x27, Data::None, "CFLUSH", vec!()));
        m.insert(0x28, mn!(0x28, Data::Word, "TSTW", vec!(OpType::Src)));
        m.insert(0x2A, mn!(0x2A, Data::Half, "TSTH", vec!(OpType::Src)));
        m.insert(0x2B, mn!(0x2B, Data::Byte, "TSTB", vec!(OpType::Src)));
        m.insert(0x2C, mn!(0x2C, Data::Word, "CALL", vec!(OpType::Src, OpType::Dest)));
        m.insert(0x2E, mn!(0x2E, Data::None, "BPT", vec!()));
        m.insert(0x2F, mn!(0x2F, Data::None, "WAIT", vec!()));
        m.insert(0x32, mn!(0x32, Data::Word, "SPOP", vec!(OpType::Lit)));
        m.insert(0x33, mn!(0x33, Data::Word, "SPOPWS", vec!(OpType::Lit, OpType::Dest)));
        m.insert(0x34, mn!(0x34, Data::Word, "JSB", vec!(OpType::Dest)));
        m.insert(0x36, mn!(0x36, Data::Half, "BSBH", vec!(OpType::Lit)));
        m.insert(0x37, mn!(0x37, Data::Byte, "BSBB", vec!(OpType::Lit)));
        m.insert(0x38, mn!(0x38, Data::Word, "BITW", vec!(OpType::Src, OpType::Src)));
        m.insert(0x3A, mn!(0x3A, Data::Half, "BITH", vec!(OpType::Src, OpType::Src)));
        m.insert(0x3B, mn!(0x3B, Data::Byte, "BITB", vec!(OpType::Src, OpType::Src)));
        m.insert(0x3C, mn!(0x3C, Data::Word, "CMPW", vec!(OpType::Src, OpType::Src)));
        m.insert(0x3E, mn!(0x3E, Data::Half, "CMPH", vec!(OpType::Src, OpType::Src)));
        m.insert(0x3F, mn!(0x3F, Data::Byte, "CMPB", vec!(OpType::Src, OpType::Src)));
        m.insert(0x40, mn!(0x40, Data::None, "RGEQ", vec!()));
        m.insert(0x42, mn!(0x42, Data::Half, "BGEH", vec!(OpType::Lit)));
        m.insert(0x43, mn!(0x43, Data::Byte, "BGEB", vec!(OpType::Lit)));
        m.insert(0x44, mn!(0x44, Data::None, "RGTR", vec!()));
        m.insert(0x46, mn!(0x46, Data::Half, "BGH", vec!(OpType::Lit)));
        m.insert(0x47, mn!(0x47, Data::Byte, "BGB", vec!(OpType::Lit)));
        m.insert(0x48, mn!(0x48, Data::None, "RLSS", vec!()));
        m.insert(0x4A, mn!(0x4A, Data::Half, "BLH", vec!(OpType::Lit)));
        m.insert(0x4B, mn!(0x4B, Data::Byte, "BLB", vec!(OpType::Lit)));
        m.insert(0x4C, mn!(0x4C, Data::None, "RLEQ", vec!()));
        m.insert(0x4E, mn!(0x4E, Data::Half, "BLEH", vec!(OpType::Lit)));
        m.insert(0x4F, mn!(0x4F, Data::Byte, "BLEB", vec!(OpType::Lit)));
        m.insert(0x50, mn!(0x50, Data::None, "RGEQU", vec!()));
        m.insert(0x52, mn!(0x52, Data::Half, "BGEUH", vec!(OpType::Lit)));
        m.insert(0x53, mn!(0x53, Data::Byte, "BGEUB", vec!(OpType::Lit)));
        m.insert(0x54, mn!(0x54, Data::None, "RGTRU", vec!()));
        m.insert(0x56, mn!(0x56, Data::Half, "BGUH", vec!(OpType::Lit)));
        m.insert(0x57, mn!(0x57, Data::Byte, "BGUB", vec!(OpType::Lit)));
        m.insert(0x58, mn!(0x58, Data::None, "RLSSU", vec!()));
        m.insert(0x5A, mn!(0x5A, Data::Half, "BLUH", vec!(OpType::Lit)));
        m.insert(0x5B, mn!(0x5B, Data::Byte, "BLUB", vec!(OpType::Lit)));
        m.insert(0x5C, mn!(0x5C, Data::None, "RLEQU", vec!()));
        m.insert(0x5E, mn!(0x5E, Data::Half, "BLEUH", vec!(OpType::Lit)));
        m.insert(0x5F, mn!(0x5F, Data::Byte, "BLEUB", vec!(OpType::Lit)));
        m.insert(0x60, mn!(0x60, Data::None, "RVC", vec!()));
        m.insert(0x62, mn!(0x62, Data::Half, "BVCH", vec!(OpType::Lit)));
        m.insert(0x63, mn!(0x63, Data::Byte, "BVCB", vec!(OpType::Lit)));
        m.insert(0x64, mn!(0x64, Data::None, "RNEQU", vec!()));
        m.insert(0x66, mn!(0x66, Data::Half, "BNEH", vec!(OpType::Lit)));
        m.insert(0x67, mn!(0x67, Data::Byte, "BNEB", vec!(OpType::Lit)));
        m.insert(0x68, mn!(0x68, Data::None, "RVS", vec!()));
        m.insert(0x6A, mn!(0x6A, Data::Half, "BVSH", vec!(OpType::Lit)));
        m.insert(0x6B, mn!(0x6B, Data::Byte, "BVSB", vec!(OpType::Lit)));
        m.insert(0x6C, mn!(0x6C, Data::None, "REQLU", vec!()));
        m.insert(0x6E, mn!(0x6E, Data::Half, "BEH", vec!(OpType::Lit)));
        m.insert(0x6F, mn!(0x6F, Data::Byte, "BEB", vec!(OpType::Lit)));
        m.insert(0x70, mn!(0x70, Data::None, "NOP", vec!()));
        m.insert(0x72, mn!(0x72, Data::None, "NOP3", vec!()));
        m.insert(0x73, mn!(0x73, Data::None, "NOP2", vec!()));
        m.insert(0x74, mn!(0x74, Data::None, "RNEQ", vec!()));
        m.insert(0x76, mn!(0x76, Data::Half, "BNEH", vec!(OpType::Lit)));
        m.insert(0x77, mn!(0x77, Data::Byte, "BNEB", vec!(OpType::Lit)));
        m.insert(0x78, mn!(0x78, Data::None, "RSB", vec!()));
        m.insert(0x7A, mn!(0x7A, Data::Half, "BRH", vec!(OpType::Lit)));
        m.insert(0x7B, mn!(0x7B, Data::Byte, "BRB", vec!(OpType::Lit)));
        m.insert(0x7C, mn!(0x7C, Data::None, "REQL", vec!()));
        m.insert(0x7E, mn!(0x7E, Data::Half, "BEH", vec!(OpType::Lit)));
        m.insert(0x7F, mn!(0x7F, Data::Byte, "BEB", vec!(OpType::Lit)));
        m.insert(0x80, mn!(0x80, Data::Word, "CLRW", vec!(OpType::Dest)));
        m.insert(0x82, mn!(0x82, Data::Half, "CLRH", vec!(OpType::Dest)));
        m.insert(0x83, mn!(0x83, Data::Byte, "CLRB", vec!(OpType::Dest)));
        m.insert(0x84, mn!(0x84, Data::Word, "MOVW", vec!(OpType::Src, OpType::Dest)));
        m.insert(0x86, mn!(0x86, Data::Half, "MOVH", vec!(OpType::Src, OpType::Dest)));
        m.insert(0x87, mn!(0x87, Data::Byte, "MOVB", vec!(OpType::Src, OpType::Dest)));
        m.insert(0x88, mn!(0x88, Data::Word, "MCOMW", vec!(OpType::Src, OpType::Dest)));
        m.insert(0x8A, mn!(0x8A, Data::Half, "MCOMH", vec!(OpType::Src, OpType::Dest)));
        m.insert(0x8B, mn!(0x8B, Data::Byte, "MCOMB", vec!(OpType::Src, OpType::Dest)));
        m.insert(0x8C, mn!(0x8C, Data::Word, "MNEGW", vec!(OpType::Src, OpType::Dest)));
        m.insert(0x8E, mn!(0x8E, Data::Half, "MNEGH", vec!(OpType::Src, OpType::Dest)));
        m.insert(0x8F, mn!(0x8F, Data::Byte, "MNEGB", vec!(OpType::Src, OpType::Dest)));
        m.insert(0x90, mn!(0x90, Data::Word, "INCW", vec!(OpType::Dest)));
        m.insert(0x92, mn!(0x92, Data::Half, "INCH", vec!(OpType::Dest)));
        m.insert(0x93, mn!(0x93, Data::Byte, "INCB", vec!(OpType::Dest)));
        m.insert(0x94, mn!(0x94, Data::Word, "DECW", vec!(OpType::Dest)));
        m.insert(0x96, mn!(0x96, Data::Half, "DECH", vec!(OpType::Dest)));
        m.insert(0x97, mn!(0x97, Data::Byte, "DECB", vec!(OpType::Dest)));
        m.insert(0x9C, mn!(0x9C, Data::Word, "ADDW2", vec!(OpType::Src, OpType::Dest)));
        m.insert(0x9E, mn!(0x9E, Data::Half, "ADDH2", vec!(OpType::Src, OpType::Dest)));
        m.insert(0x9F, mn!(0x9F, Data::Byte, "ADDB2", vec!(OpType::Src, OpType::Dest)));
        m.insert(0xA0, mn!(0xA0, Data::Word, "PUSHW", vec!(OpType::Src)));
        m.insert(0xA4, mn!(0xA4, Data::Word, "MODW2", vec!(OpType::Src, OpType::Dest)));
        m.insert(0xA6, mn!(0xA6, Data::Half, "MODH2", vec!(OpType::Src, OpType::Dest)));
        m.insert(0xA7, mn!(0xA7, Data::Byte, "MODB2", vec!(OpType::Src, OpType::Dest)));
        m.insert(0xA8, mn!(0xA8, Data::Word, "MULW2", vec!(OpType::Src, OpType::Dest)));
        m.insert(0xAA, mn!(0xAA, Data::Half, "MULH2", vec!(OpType::Src, OpType::Dest)));
        m.insert(0xAB, mn!(0xAB, Data::Byte, "MULB2", vec!(OpType::Src, OpType::Dest)));
        m.insert(0xAC, mn!(0xAC, Data::Word, "DIVW2", vec!(OpType::Src, OpType::Dest)));
        m.insert(0xAE, mn!(0xAE, Data::Half, "DIVH2", vec!(OpType::Src, OpType::Dest)));
        m.insert(0xAF, mn!(0xAF, Data::Byte, "DIVB2", vec!(OpType::Src, OpType::Dest)));
        m.insert(0xB0, mn!(0xB0, Data::Word, "ORW2", vec!(OpType::Src, OpType::Dest)));
        m.insert(0xB2, mn!(0xB2, Data::Half, "ORH2", vec!(OpType::Src, OpType::Dest)));
        m.insert(0xB3, mn!(0xB3, Data::Byte, "ORB2", vec!(OpType::Src, OpType::Dest)));
        m.insert(0xB4, mn!(0xB4, Data::Word, "XORW2", vec!(OpType::Src, OpType::Dest)));
        m.insert(0xB6, mn!(0xB6, Data::Half, "XORH2", vec!(OpType::Src, OpType::Dest)));
        m.insert(0xB7, mn!(0xB7, Data::Byte, "XORB2", vec!(OpType::Src, OpType::Dest)));
        m.insert(0xB8, mn!(0xB8, Data::Word, "ANDW2", vec!(OpType::Src, OpType::Dest)));
        m.insert(0xBA, mn!(0xBA, Data::Half, "ANDH2", vec!(OpType::Src, OpType::Dest)));
        m.insert(0xBB, mn!(0xBB, Data::Byte, "ANDB2", vec!(OpType::Src, OpType::Dest)));
        m.insert(0xBC, mn!(0xBC, Data::Word, "SUBW2", vec!(OpType::Src, OpType::Dest)));
        m.insert(0xBE, mn!(0xBE, Data::Half, "SUBH2", vec!(OpType::Src, OpType::Dest)));
        m.insert(0xBF, mn!(0xBF, Data::Byte, "SUBB2", vec!(OpType::Src, OpType::Dest)));
        m.insert(0xC0, mn!(0xC0, Data::Word, "ALSW3", vec!(OpType::Src, OpType::Src, OpType::Dest)));
        m.insert(0xC4, mn!(0xC4, Data::Word, "ARSW3", vec!(OpType::Src, OpType::Src, OpType::Dest)));
        m.insert(0xC6, mn!(0xC6, Data::Half, "ARSH3", vec!(OpType::Src, OpType::Src, OpType::Dest)));
        m.insert(0xC7, mn!(0xC7, Data::Byte, "ARSB3", vec!(OpType::Src, OpType::Src, OpType::Dest)));
        m.insert(0xC8, mn!(0xC8, Data::Word, "INSFW", vec!(OpType::Src, OpType::Src, OpType::Src, OpType::Dest)));
        m.insert(0xCA, mn!(0xCA, Data::Half, "INSFH", vec!(OpType::Src, OpType::Src, OpType::Src, OpType::Dest)));
        m.insert(0xCB, mn!(0xCB, Data::Byte, "INSFB", vec!(OpType::Src, OpType::Src, OpType::Src, OpType::Dest)));
        m.insert(0xCC, mn!(0xCC, Data::Word, "EXTFW", vec!(OpType::Src, OpType::Src, OpType::Src, OpType::Dest)));
        m.insert(0xCE, mn!(0xCE, Data::Half, "EXTFH", vec!(OpType::Src, OpType::Src, OpType::Src, OpType::Dest)));
        m.insert(0xCF, mn!(0xCF, Data::Byte, "EXTFB", vec!(OpType::Src, OpType::Src, OpType::Src, OpType::Dest)));
        m.insert(0xD0, mn!(0xD0, Data::Word, "LLSW3", vec!(OpType::Src, OpType::Src, OpType::Dest)));
        m.insert(0xD2, mn!(0xD2, Data::Half, "LLSH3", vec!(OpType::Src, OpType::Src, OpType::Dest)));
        m.insert(0xD3, mn!(0xD3, Data::Byte, "LLSB3", vec!(OpType::Src, OpType::Src, OpType::Dest)));
        m.insert(0xD4, mn!(0xD4, Data::Word, "LRSW3", vec!(OpType::Src, OpType::Src, OpType::Dest)));
        m.insert(0xD8, mn!(0xD8, Data::Word, "ROTW", vec!(OpType::Src, OpType::Src, OpType::Dest)));
        m.insert(0xDC, mn!(0xDC, Data::Word, "ADDW3", vec!(OpType::Src, OpType::Src, OpType::Dest)));
        m.insert(0xDE, mn!(0xDE, Data::Half, "ADDH3", vec!(OpType::Src, OpType::Src, OpType::Dest)));
        m.insert(0xDF, mn!(0xDF, Data::Byte, "ADDB3", vec!(OpType::Src, OpType::Src, OpType::Dest)));
        m.insert(0xE0, mn!(0xE0, Data::Word, "PUSHAW", vec!(OpType::Src)));
        m.insert(0xE4, mn!(0xE4, Data::Word, "MODW3", vec!(OpType::Src, OpType::Src, OpType::Dest)));
        m.insert(0xE6, mn!(0xE6, Data::Half, "MODH3", vec!(OpType::Src, OpType::Src, OpType::Dest)));
        m.insert(0xE7, mn!(0xE7, Data::Byte, "MODB3", vec!(OpType::Src, OpType::Src, OpType::Dest)));
        m.insert(0xE8, mn!(0xE8, Data::Word, "MULW3", vec!(OpType::Src, OpType::Src, OpType::Dest)));
        m.insert(0xEA, mn!(0xEA, Data::Half, "MULH3", vec!(OpType::Src, OpType::Src, OpType::Dest)));
        m.insert(0xEB, mn!(0xEB, Data::Byte, "MULB3", vec!(OpType::Src, OpType::Src, OpType::Dest)));
        m.insert(0xEC, mn!(0xEC, Data::Word, "DIVW3", vec!(OpType::Src, OpType::Src, OpType::Dest)));
        m.insert(0xEE, mn!(0xEE, Data::Half, "DIVH3", vec!(OpType::Src, OpType::Src, OpType::Dest)));
        m.insert(0xEF, mn!(0xEF, Data::Byte, "DIVB3", vec!(OpType::Src, OpType::Src, OpType::Dest)));
        m.insert(0xF0, mn!(0xF0, Data::Word, "ORW3", vec!(OpType::Src, OpType::Src, OpType::Dest)));
        m.insert(0xF2, mn!(0xF2, Data::Half, "ORH3", vec!(OpType::Src, OpType::Src, OpType::Dest)));
        m.insert(0xF3, mn!(0xF3, Data::Byte, "ORB3", vec!(OpType::Src, OpType::Src, OpType::Dest)));
        m.insert(0xF4, mn!(0xF4, Data::Word, "XORW3", vec!(OpType::Src, OpType::Src, OpType::Dest)));
        m.insert(0xF6, mn!(0xF6, Data::Half, "XORH3", vec!(OpType::Src, OpType::Src, OpType::Dest)));
        m.insert(0xF7, mn!(0xF7, Data::Byte, "XORB3", vec!(OpType::Src, OpType::Src, OpType::Dest)));
        m.insert(0xF8, mn!(0xF8, Data::Word, "ANDW3", vec!(OpType::Src, OpType::Src, OpType::Dest)));
        m.insert(0xFA, mn!(0xFA, Data::Half, "ANDH3", vec!(OpType::Src, OpType::Src, OpType::Dest)));
        m.insert(0xFB, mn!(0xFB, Data::Byte, "ANDB3", vec!(OpType::Src, OpType::Src, OpType::Dest)));
        m.insert(0xFC, mn!(0xFC, Data::Word, "SUBW3", vec!(OpType::Src, OpType::Src, OpType::Dest)));
        m.insert(0xFE, mn!(0xFE, Data::Half, "SUBH3", vec!(OpType::Src, OpType::Src, OpType::Dest)));
        m.insert(0xFF, mn!(0xFF, Data::Byte, "SUBB3", vec!(OpType::Src, OpType::Src, OpType::Dest)));
        m.insert(0x3009, mn!(0x3009, Data::None, "MVERNO", vec!()));
        m.insert(0x300d, mn!(0x300d, Data::None, "ENBVJMP", vec!()));
        m.insert(0x3013, mn!(0x3013, Data::None, "DISVJMP", vec!()));
        m.insert(0x3019, mn!(0x3019, Data::None, "MOVBLW", vec!()));
        m.insert(0x301f, mn!(0x301f, Data::None, "STREND", vec!()));
        m.insert(0x302f, mn!(0x302f, Data::None, "INTACK", vec!()));
        m.insert(0x303f, mn!(0x303f, Data::None, "STRCPY", vec!()));
        m.insert(0x3045, mn!(0x3045, Data::None, "RETG", vec!()));
        m.insert(0x3061, mn!(0x3061, Data::None, "GATE", vec!()));
        m.insert(0x30ac, mn!(0x30ac, Data::None, "CALLPS", vec!()));
        m.insert(0x30c8, mn!(0x30c8, Data::None, "RETPS", vec!()));

        m
    };
}

#[allow(dead_code)]
pub struct Cpu<'a> {
    //
    // Note that we store registers as an array of type u32 because
    // we often need to reference registers by index (0-15) when decoding
    // and executing instructions.
    //
    r: [u32; 16],
    ir: Option<DecodedInstruction<'a>>,
}

#[allow(dead_code)]
impl<'a> Cpu<'a> {
    pub fn new() -> Cpu<'a> {
        Cpu {
            r: [0; 16],
            ir: None,
        }
    }

    /// Reset the CPU.
    pub fn reset(&mut self, bus: &mut Bus) -> Result<(), BusError> {
        //
        // The WE32100 Manual, Page 2-52, describes the reset process
        //
        //  1. Change to physical address mode
        //  2. Fetch the word at physical address 0x80 and store it in
        //     the PCBP register.
        //  3. Fetch the word at the PCB address and store it in the
        //     PSW.
        //  4. Fetch the word at PCB address + 4 bytes and store it
        //     in the PC.
        //  5. Fetch the word at PCB address + 8 bytes and store it
        //     in the SP.
        //  6. Fetch the word at PCB address + 12 bytes and store it
        //     in the PCB, if bit I in PSW is set.
        //

        self.r[R_PCBP] = bus.read_word(0x80, AccessCode::AddressFetch)?;
        self.r[R_PSW] = bus.read_word(self.r[R_PCBP] as usize, AccessCode::AddressFetch)?;
        self.r[R_PC] = bus.read_word(self.r[R_PCBP] as usize + 4, AccessCode::AddressFetch)?;
        self.r[R_SP] = bus.read_word(self.r[R_PCBP] as usize + 8, AccessCode::AddressFetch)?;

        if self.r[R_PSW] & F_I != 0 {
            self.r[R_PSW] &= !F_I;
            self.r[R_PCBP] += 12;
        }

        self.set_isc(3);

        Ok(())
    }

    /// Compute the effective address for an Operand.
    fn effective_address(&self, bus: &mut Bus, op: &Operand) -> Result<u32, CpuError> {
        match op.mode {
            AddrMode::RegisterDeferred => {
                let r = match op.register {
                    Some(v) => v,
                    None => return Err(CpuError::Exception(CpuException::IllegalOpcode)),
                };
                Ok(self.r[r])
            }
            AddrMode::Absolute => Ok(op.embedded),
            AddrMode::AbsoluteDeferred => Ok(bus.read_word(op.embedded as usize, AccessCode::AddressFetch)?),
            AddrMode::FPShortOffset => Ok(add_offset(self.r[R_FP], sign_extend_byte(op.embedded as u8))),
            AddrMode::APShortOffset => Ok(add_offset(self.r[R_AP], sign_extend_byte(op.embedded as u8))),
            AddrMode::WordDisplacement => {
                let r = match op.register {
                    Some(v) => v,
                    None => return Err(CpuError::Exception(CpuException::IllegalOpcode)),
                };
                Ok(add_offset(self.r[r], op.embedded))
            }
            AddrMode::WordDisplacementDeferred => {
                let r = match op.register {
                    Some(v) => v,
                    None => return Err(CpuError::Exception(CpuException::IllegalOpcode)),
                };
                Ok(bus.read_word((add_offset(self.r[r], op.embedded)) as usize, AccessCode::AddressFetch)?)
            }
            AddrMode::HalfwordDisplacement => {
                let r = match op.register {
                    Some(v) => v,
                    None => return Err(CpuError::Exception(CpuException::IllegalOpcode)),
                };
                Ok(add_offset(self.r[r], sign_extend_halfword(op.embedded as u16)))
            }
            AddrMode::HalfwordDisplacementDeferred => {
                let r = match op.register {
                    Some(v) => v,
                    None => return Err(CpuError::Exception(CpuException::IllegalOpcode)),
                };
                Ok(bus.read_word(
                    (add_offset(self.r[r], sign_extend_halfword(op.embedded as u16))) as usize,
                    AccessCode::AddressFetch,
                )?)
            }
            AddrMode::ByteDisplacement => {
                let r = match op.register {
                    Some(v) => v,
                    None => return Err(CpuError::Exception(CpuException::IllegalOpcode)),
                };
                Ok(add_offset(self.r[r], sign_extend_byte(op.embedded as u8)))
            }
            AddrMode::ByteDisplacementDeferred => {
                let r = match op.register {
                    Some(v) => v,
                    None => return Err(CpuError::Exception(CpuException::IllegalOpcode)),
                };
                Ok(bus.read_word(add_offset(self.r[r], sign_extend_byte(op.embedded as u8)) as usize, AccessCode::AddressFetch)?)
            }
            _ => Err(CpuError::Exception(CpuException::IllegalOpcode)),
        }
    }

    /// Read the value pointed at by an Operand
    pub fn read_op(&self, bus: &mut Bus, op: &Operand) -> Result<u32, CpuError> {
        match op.mode {
            AddrMode::Register => {
                let r = match op.register {
                    Some(v) => v,
                    None => return Err(CpuError::Exception(CpuException::IllegalOpcode)),
                };

                match op.data_type() {
                    Data::Word | Data::UWord => Ok(self.r[r]),
                    Data::Half => Ok(sign_extend_halfword(self.r[r] as u16)),
                    Data::UHalf => Ok((self.r[r] as u16) as u32),
                    Data::Byte => Ok((self.r[r] as u8) as u32),
                    Data::SByte => Ok(sign_extend_byte(self.r[r] as u8)),
                    _ => Err(CpuError::Exception(CpuException::IllegalOpcode)),
                }
            }
            AddrMode::PositiveLiteral | AddrMode::NegativeLiteral => Ok(sign_extend_byte(op.embedded as u8)),
            AddrMode::WordImmediate => Ok(op.embedded),
            AddrMode::HalfwordImmediate => Ok(sign_extend_halfword(op.embedded as u16)),
            AddrMode::ByteImmediate => Ok(sign_extend_byte(op.embedded as u8)),
            _ => {
                let eff = self.effective_address(bus, op)?;
                match op.data_type() {
                    Data::UWord | Data::Word => Ok(bus.read_word(eff as usize, AccessCode::InstrFetch)?),
                    Data::Half => Ok(sign_extend_halfword(bus.read_half(eff as usize, AccessCode::InstrFetch)?)),
                    Data::UHalf => Ok(bus.read_half(eff as usize, AccessCode::InstrFetch)? as u32),
                    Data::Byte => Ok(bus.read_byte(eff as usize, AccessCode::InstrFetch)? as u32),
                    Data::SByte => Ok(sign_extend_byte(bus.read_byte(eff as usize, AccessCode::InstrFetch)?)),
                    _ => return Err(CpuError::Exception(CpuException::IllegalOpcode)),
                }
            }
        }
    }

    /// Write a value to the location specified by an Operand
    pub fn write_op(&mut self, bus: &mut Bus, op: &Operand, val: u32) -> Result<(), CpuError> {
        match op.mode {
            AddrMode::Register => match op.register {
                Some(r) => self.r[r] = val,
                None => return Err(CpuError::Exception(CpuException::IllegalOpcode)),
            },
            AddrMode::NegativeLiteral
            | AddrMode::PositiveLiteral
            | AddrMode::ByteImmediate
            | AddrMode::HalfwordImmediate
            | AddrMode::WordImmediate => {
                return Err(CpuError::Exception(CpuException::IllegalOpcode));
            }
            _ => {
                let eff = self.effective_address(bus, op)?;
                match op.data_type() {
                    Data::UWord | Data::Word => bus.write_word(eff as usize, val)?,
                    Data::Half | Data::UHalf => bus.write_half(eff as usize, val as u16)?,
                    Data::Byte | Data::SByte => bus.write_byte(eff as usize, val as u8)?,
                    _ => return Err(CpuError::Exception(CpuException::IllegalOpcode)),
                }
            }
        }
        Ok(())
    }

    fn add(&mut self, bus: &mut Bus, a: u32, b: u32, dst: &Operand) -> Result<(), CpuError> {
        let result: u64 = a as u64 + b as u64;

        self.write_op(bus, dst, result as u32)?;

        self.set_nz_flags(result as u32, dst);

        match dst.data_type {
            Data::Word | Data::UWord => {
                self.set_c_flag(result > 0xffffffff);
                self.set_v_flag((((a ^ !b) & (a ^ result as u32)) & 0x80000000) != 0);
            }
            Data::Half | Data::UHalf => {
                self.set_c_flag(result > 0xffff);
                self.set_v_flag((((a ^ !b) & (a ^ result as u32)) & 0x8000) != 0);
            }
            Data::Byte | Data::SByte => {
                self.set_c_flag(result > 0xff);
                self.set_v_flag((((a ^ !b) & (a ^ result as u32)) & 0x80) != 0);
            }
            _ => {
                return Err(CpuError::Exception(CpuException::IllegalOpcode));
            }
        }

        Ok(())
    }

    fn dispatch(&mut self, bus: &mut Bus) -> Result<i32, CpuError> {
        let instr = self.decode_instruction(bus)?;
        let mut pc_increment: i32 = instr.bytes as i32;

        match instr.mnemonic.opcode {
            NOP => {
                pc_increment = 1;
            }
            NOP2 => {
                pc_increment = 2;
            }
            NOP3 => {
                pc_increment = 3;
            }
            ADDW2 | ADDH2 | ADDB2 => {
                let a = self.read_op(bus, &instr.operands[0])?;
                let b = self.read_op(bus, &instr.operands[1])?;
                self.add(bus, a, b, &instr.operands[1])?;
            }
            ADDW3 | ADDH3 | ADDB3 => {
                let a = self.read_op(bus, &instr.operands[0])?;
                let b = self.read_op(bus, &instr.operands[1])?;
                self.add(bus, a, b, &instr.operands[2])?
            }
            ALSW3 => {
                let src1 = &instr.operands[0];
                let src2 = &instr.operands[1];
                let dst = &instr.operands[2];

                let a = self.read_op(bus, src1)?;
                let b = self.read_op(bus, src2)?;
                let result = (a as u64) << (b & 0x1f);
                self.write_op(bus, dst, result as u32)?;

                self.set_nz_flags(result as u32, dst);
                self.set_c_flag(false);
                self.set_v_flag_op(result as u32, dst);
            }
            ANDW2 | ANDH2 | ANDB2 => {
                let src = &instr.operands[0];
                let dst = &instr.operands[1];

                let a = self.read_op(bus, src)?;
                let b = self.read_op(bus, dst)?;

                let result = a & b;

                self.write_op(bus, dst, result)?;

                self.set_nz_flags(result, dst);
                self.set_c_flag(false);
                self.set_v_flag_op(result, dst);
            }
            ANDW3 | ANDH3 | ANDB3 => {
                let src1 = &instr.operands[0];
                let src2 = &instr.operands[1];
                let dst = &instr.operands[2];

                let a = self.read_op(bus, src1)?;
                let b = self.read_op(bus, src2)?;

                let result = a & b;

                self.write_op(bus, dst, result)?;

                self.set_nz_flags(result, dst);
                self.set_c_flag(false);
                self.set_v_flag_op(result, dst);
            }
            BEH | BEH_D => {
                if self.z_flag() {
                    pc_increment = sign_extend_halfword(instr.operands[0].embedded as u16) as i32;
                }
            }
            BEB | BEB_D => {
                if self.z_flag() {
                    pc_increment = sign_extend_byte(instr.operands[0].embedded as u8) as i32;
                }
            }
            BGH => {
                if !(self.n_flag() || self.z_flag()) {
                    pc_increment = sign_extend_halfword(instr.operands[0].embedded as u16) as i32;
                }
            }
            BGB => {
                if !(self.n_flag() || self.z_flag()) {
                    pc_increment = sign_extend_byte(instr.operands[0].embedded as u8) as i32;
                }
            }
            BGEH => {
                if !self.n_flag() || self.z_flag() {
                    pc_increment = sign_extend_halfword(instr.operands[0].embedded as u16) as i32;
                }
            }
            BGEB => {
                if !self.n_flag() || self.z_flag() {
                    pc_increment = sign_extend_byte(instr.operands[0].embedded as u8) as i32;
                }
            }
            BGEUH => {
                if !self.c_flag() {
                    pc_increment = sign_extend_halfword(instr.operands[0].embedded as u16) as i32;
                }
            }
            BGEUB => {
                if !self.c_flag() {
                    pc_increment = sign_extend_byte(instr.operands[0].embedded as u8) as i32;
                }
            }
            BGUH => {
                if !(self.c_flag() || self.z_flag()) {
                    pc_increment = sign_extend_halfword(instr.operands[0].embedded as u16) as i32;
                }
            }
            BGUB => {
                if !(self.c_flag() || self.z_flag()) {
                    pc_increment = sign_extend_byte(instr.operands[0].embedded as u8) as i32;
                }
            }
            BITW | BITH | BITB => {
                let src1 = &instr.operands[0];
                let src2 = &instr.operands[1];

                let a = self.read_op(bus, src1)?;
                let b = self.read_op(bus, src2)?;
                let result = a & b;

                self.set_nz_flags(result, src2);
                self.set_c_flag(false);
                self.set_v_flag(false);
            }
            BLH => {
                if self.n_flag() && !self.z_flag() {
                    pc_increment = sign_extend_halfword(instr.operands[0].embedded as u16) as i32;
                }
            }
            BLB => {
                if self.n_flag() && !self.z_flag() {
                    pc_increment = sign_extend_byte(instr.operands[0].embedded as u8) as i32;
                }
            }
            BLEH => {
                if self.n_flag() || self.z_flag() {
                    pc_increment = sign_extend_halfword(instr.operands[0].embedded as u16) as i32;
                }
            }
            BLEB => {
                if self.n_flag() || self.z_flag() {
                    pc_increment = sign_extend_byte(instr.operands[0].embedded as u8) as i32;
                }
            }
            BLEUH => {
                if self.c_flag() || self.z_flag() {
                    pc_increment = sign_extend_halfword(instr.operands[0].embedded as u16) as i32;
                }
            }
            BLEUB => {
                if self.c_flag() || self.z_flag() {
                    pc_increment = sign_extend_byte(instr.operands[0].embedded as u8) as i32;
                }
            }
            BLUH => {
                if self.c_flag() {
                    pc_increment = sign_extend_halfword(instr.operands[0].embedded as u16) as i32;
                }
            }
            BLUB => {
                if self.c_flag() {
                    pc_increment = sign_extend_byte(instr.operands[0].embedded as u8) as i32;
                }
            }
            BNEH | BNEH_D => {
                if !self.z_flag() {
                    pc_increment = sign_extend_halfword(instr.operands[0].embedded as u16) as i32;
                }
            }
            BNEB | BNEB_D => {
                if !self.z_flag() {
                    pc_increment = sign_extend_byte(instr.operands[0].embedded as u8) as i32;
                }
            }
            BPT | HALT => {
                // TODO: Breakpoint Trap
            }
            BRH => {
                pc_increment = sign_extend_halfword(instr.operands[0].embedded as u16) as i32;
            }
            BRB => {
                pc_increment = sign_extend_byte(instr.operands[0].embedded as u8) as i32;
            }
            BSBH => {
                let offset = sign_extend_halfword(instr.operands[0].embedded as u16) as i32;
                let return_pc = (self.r[R_PC] as i32 + pc_increment) as u32;
                self.stack_push(bus, return_pc)?;
                pc_increment = offset;
            }
            BSBB => {
                let offset = sign_extend_byte(instr.operands[0].embedded as u8) as i32;
                let return_pc = (self.r[R_PC] as i32 + pc_increment) as u32;
                self.stack_push(bus, return_pc)?;
                pc_increment = offset;
            }
            BVCH => {
                if !self.v_flag() {
                    pc_increment = sign_extend_halfword(instr.operands[0].embedded as u16) as i32;
                }
            }
            BVCB => {
                if !self.v_flag() {
                    pc_increment = sign_extend_byte(instr.operands[0].embedded as u8) as i32;
                }
            }
            BVSH => {
                if self.v_flag() {
                    pc_increment = sign_extend_halfword(instr.operands[0].embedded as u16) as i32;
                }
            }
            BVSB => {
                if self.v_flag() {
                    pc_increment = sign_extend_byte(instr.operands[0].embedded as u8) as i32;
                }
            }
            CALL => {
                let a = self.effective_address(bus, &instr.operands[0])?;
                let b = self.effective_address(bus, &instr.operands[1])?;

                let return_pc = (self.r[R_PC] as i32 + pc_increment) as u32;

                bus.write_word((self.r[R_SP] + 4) as usize, self.r[R_AP])?;
                bus.write_word(self.r[R_SP] as usize, return_pc)?;

                self.r[R_SP] += 8;
                self.r[R_PC] = b;
                self.r[R_AP] = a;

                pc_increment = 0;
            }
            CFLUSH => {}
            CALLPS => {
                // TODO: CALLPS Implementation
            }
            CLRW | CLRH | CLRB => {
                self.write_op(bus, &instr.operands[0], 0)?;
                self.set_n_flag(false);
                self.set_z_flag(true);
                self.set_c_flag(false);
                self.set_v_flag(false);
            }
            CMPW => {
                let a = self.read_op(bus, &instr.operands[0])?;
                let b = self.read_op(bus, &instr.operands[1])?;

                self.set_z_flag(b == a);
                self.set_n_flag((b as i32) < (a as i32));
                self.set_c_flag(b < a);
                self.set_v_flag(false);
            }
            CMPH => {
                let a = self.read_op(bus, &instr.operands[0])?;
                let b = self.read_op(bus, &instr.operands[1])?;

                self.set_z_flag((b as u16) == (a as u16));
                self.set_n_flag((b as i16) < (a as i16));
                self.set_c_flag((b as u16) < (a as u16));
                self.set_v_flag(false);
            }
            CMPB => {
                let a = self.read_op(bus, &instr.operands[0])?;
                let b = self.read_op(bus, &instr.operands[1])?;

                self.set_z_flag((b as u8) == (a as u8));
                self.set_n_flag((b as i8) < (a as i8));
                self.set_c_flag((b as u8) < (a as u8));
                self.set_v_flag(false);
            }
            DECW | DECH | DECB => {
                // TODO: Subtrace
            }
            RET => {
                let a = self.r[R_AP];
                let b = bus.read_word((self.r[R_SP] - 4) as usize, AccessCode::AddressFetch)?;
                let c = bus.read_word((self.r[R_SP] - 8) as usize, AccessCode::AddressFetch)?;

                self.r[R_AP] = b;
                self.r[R_PC] = c;
                self.r[R_SP] = a;

                pc_increment = 0;
            }
            MOVB | MOVH | MOVW => {
                let val = self.read_op(bus, &instr.operands[0])?;
                self.write_op(bus, &instr.operands[1], val)?;
            }
            _ => return Err(CpuError::Exception(CpuException::IllegalOpcode)),
        };

        Ok(pc_increment)
    }

    /// Step the CPU by one instruction.
    pub fn step(&mut self, bus: &mut Bus) {
        // TODO: On CPU Exception or Bus Error, handle each error with the appropriate exception handler routine
        match self.dispatch(bus) {
            Ok(i) => self.r[R_PC] = (self.r[R_PC] as i32 + i) as u32,
            Err(CpuError::Bus(BusError::Alignment)) => {}
            Err(CpuError::Bus(BusError::Permission)) => {}
            Err(CpuError::Bus(BusError::NoDevice)) | Err(CpuError::Bus(BusError::Read)) | Err(CpuError::Bus(BusError::Write)) => {}
            Err(CpuError::Exception(CpuException::IllegalOpcode)) => {}
            Err(CpuError::Exception(CpuException::InvalidDescriptor)) => {}
            Err(_) => {}
        }
    }

    /// Set the CPU's Program Counter to the specified value
    pub fn set_pc(&mut self, val: u32) {
        self.r[R_PC] = val;
    }

    /// Decode a literal Operand type.
    ///
    /// These operands belong to only certain instructions, where a word without
    /// a descriptor byte immediately follows the opcode.
    fn decode_literal_operand(&self, bus: &mut Bus, mn: &Mnemonic, addr: usize) -> Result<Operand, CpuError> {
        match mn.dtype {
            Data::Byte => {
                let b: u8 = bus.read_byte(addr, AccessCode::OperandFetch)?;
                Ok(Operand::new(1, AddrMode::None, Data::Byte, None, None, b as u32))
            }
            Data::Half => {
                let h: u16 = bus.read_half_unaligned(addr, AccessCode::OperandFetch)?;
                Ok(Operand::new(2, AddrMode::None, Data::Half, None, None, h as u32))
            }
            Data::Word => {
                let w: u32 = bus.read_word_unaligned(addr, AccessCode::OperandFetch)?;
                Ok(Operand::new(4, AddrMode::None, Data::Word, None, None, w))
            }
            _ => Err(CpuError::Exception(CpuException::IllegalOpcode)),
        }
    }

    /// Decode a descriptor Operand type.
    fn decode_descriptor_operand(
        &self,
        bus: &mut Bus,
        dtype: Data,
        etype: Option<Data>,
        addr: usize,
        recur: bool,
    ) -> Result<Operand, CpuError> {
        let descriptor_byte: u8 = bus.read_byte(addr, AccessCode::OperandFetch)?;

        let m = (descriptor_byte & 0xf0) >> 4;
        let r = descriptor_byte & 0xf;

        // The descriptor is either 1 or 2 bytes, depending on whether this is a recursive
        // call or not.
        let dsize = if recur {
            2
        } else {
            1
        };

        match m {
            0 | 1 | 2 | 3 => {
                // Positive Literal
                Ok(Operand::new(dsize, AddrMode::PositiveLiteral, dtype, etype, None, descriptor_byte as u32))
            }
            4 => {
                match r {
                    15 => {
                        // Word Immediate
                        let w = bus.read_word_unaligned(addr + 1, AccessCode::OperandFetch)?;
                        Ok(Operand::new(dsize + 4, AddrMode::WordImmediate, dtype, etype, None, w))
                    }
                    _ => {
                        // Register
                        Ok(Operand::new(dsize, AddrMode::Register, dtype, etype, Some(r as usize), 0))
                    }
                }
            }
            5 => {
                match r {
                    15 => {
                        // Halfword Immediate
                        let h = bus.read_half_unaligned(addr + 1, AccessCode::OperandFetch)?;
                        Ok(Operand::new(dsize + 2, AddrMode::HalfwordImmediate, dtype, etype, None, h as u32))
                    }
                    11 => {
                        // Illegal
                        Err(CpuError::Exception(CpuException::IllegalOpcode))
                    }
                    _ => {
                        // Register Deferred Mode
                        Ok(Operand::new(dsize, AddrMode::RegisterDeferred, dtype, etype, Some(r as usize), 0))
                    }
                }
            }
            6 => {
                match r {
                    15 => {
                        // Byte Immediate
                        let b = bus.read_byte(addr + 1, AccessCode::OperandFetch)?;
                        Ok(Operand::new(dsize + 1, AddrMode::ByteImmediate, dtype, etype, None, b as u32))
                    }
                    _ => {
                        // FP Short Offset
                        Ok(Operand::new(dsize, AddrMode::FPShortOffset, dtype, etype, Some(R_FP), r as u32))
                    }
                }
            }
            7 => {
                match r {
                    15 => {
                        // Absolute
                        let w = bus.read_word_unaligned(addr + 1, AccessCode::OperandFetch)?;
                        Ok(Operand::new(dsize + 4, AddrMode::Absolute, dtype, etype, None, w))
                    }
                    _ => {
                        // AP Short Offset
                        Ok(Operand::new(dsize, AddrMode::APShortOffset, dtype, etype, Some(R_AP), r as u32))
                    }
                }
            }
            8 => {
                match r {
                    11 => Err(CpuError::Exception(CpuException::IllegalOpcode)),
                    _ => {
                        // Word Displacement
                        let disp = bus.read_word_unaligned(addr + 1, AccessCode::OperandFetch)?;
                        Ok(Operand::new(dsize + 4, AddrMode::WordDisplacement, dtype, etype, Some(r as usize), disp))
                    }
                }
            }
            9 => {
                match r {
                    11 => Err(CpuError::Exception(CpuException::IllegalOpcode)),
                    _ => {
                        // Word Displacement Deferred
                        let disp = bus.read_word_unaligned(addr + 1, AccessCode::OperandFetch)?;
                        Ok(Operand::new(dsize + 4, AddrMode::WordDisplacementDeferred, dtype, etype, Some(r as usize), disp))
                    }
                }
            }
            10 => {
                match r {
                    11 => Err(CpuError::Exception(CpuException::IllegalOpcode)),
                    _ => {
                        // Halfword Displacement
                        let disp = bus.read_half_unaligned(addr + 1, AccessCode::OperandFetch)?;
                        Ok(Operand::new(dsize + 2, AddrMode::HalfwordDisplacement, dtype, etype, Some(r as usize), disp as u32))
                    }
                }
            }
            11 => {
                match r {
                    11 => Err(CpuError::Exception(CpuException::IllegalOpcode)),
                    _ => {
                        // Halfword Displacement Deferred
                        let disp = bus.read_half_unaligned(addr + 1, AccessCode::OperandFetch)?;
                        Ok(Operand::new(
                            dsize + 2,
                            AddrMode::HalfwordDisplacementDeferred,
                            dtype,
                            etype,
                            Some(r as usize),
                            disp as u32,
                        ))
                    }
                }
            }
            12 => {
                match r {
                    11 => Err(CpuError::Exception(CpuException::IllegalOpcode)),
                    _ => {
                        // Byte Displacement
                        let disp = bus.read_byte(addr + 1, AccessCode::OperandFetch)?;
                        Ok(Operand::new(dsize + 1, AddrMode::ByteDisplacement, dtype, etype, Some(r as usize), disp as u32))
                    }
                }
            }
            13 => {
                match r {
                    11 => Err(CpuError::Exception(CpuException::IllegalOpcode)),
                    _ => {
                        // Byte Displacement Deferred
                        let disp = bus.read_byte(addr + 1, AccessCode::OperandFetch)?;
                        Ok(Operand::new(dsize + 1, AddrMode::ByteDisplacementDeferred, dtype, etype, Some(r as usize), disp as u32))
                    }
                }
            }
            14 => match r {
                0 => self.decode_descriptor_operand(bus, dtype, Some(Data::UWord), addr + 1, true),
                2 => self.decode_descriptor_operand(bus, dtype, Some(Data::UHalf), addr + 1, true),
                3 => self.decode_descriptor_operand(bus, dtype, Some(Data::Byte), addr + 1, true),
                4 => self.decode_descriptor_operand(bus, dtype, Some(Data::Word), addr + 1, true),
                6 => self.decode_descriptor_operand(bus, dtype, Some(Data::Half), addr + 1, true),
                7 => self.decode_descriptor_operand(bus, dtype, Some(Data::SByte), addr + 1, true),
                15 => {
                    let w = bus.read_word_unaligned(addr + 1, AccessCode::OperandFetch)?;
                    Ok(Operand::new(dsize + 4, AddrMode::AbsoluteDeferred, dtype, etype, None, w))
                }
                _ => Err(CpuError::Exception(CpuException::IllegalOpcode)),
            },
            15 => {
                // Negative Literal
                Ok(Operand::new(1, AddrMode::NegativeLiteral, dtype, etype, None, descriptor_byte as u32))
            }
            _ => Err(CpuError::Exception(CpuException::IllegalOpcode)),
        }
    }

    /// Fully decode an Operand
    fn decode_operand(
        &self,
        bus: &mut Bus,
        mn: &Mnemonic,
        ot: &OpType,
        etype: Option<Data>,
        addr: usize,
    ) -> Result<Operand, CpuError> {
        match *ot {
            OpType::Lit => self.decode_literal_operand(bus, mn, addr),
            OpType::Src | OpType::Dest => self.decode_descriptor_operand(bus, mn.dtype, etype, addr, false),
        }
    }

    /// Decode the instruction currently pointed at by the Program Counter.
    /// Returns the number of bytes consumed, or a CpuError.
    fn decode_instruction(&self, bus: &mut Bus) -> Result<DecodedInstruction, CpuError> {
        // The next address to read from is pointed to by the PC
        let mut addr = self.r[R_PC] as usize;
        let initial_addr = addr;

        // Read the first byte of the instruction. Most instructions are only
        // one byte, so this is usually enough.
        let b1 = bus.read_byte(addr, AccessCode::InstrFetch)?;
        addr += 1;

        // Map the Mnemonic to the  opcode we just read. But there's a special
        // case if the value we read was '0x30'. This indicates that the instruction
        // we're reading is a halfword, requiring two bytes.
        let index: u16 = if b1 == 0x30 {
            // Special case for half-word opcodes
            let b2 = bus.read_byte(addr, AccessCode::InstrFetch)?;
            addr += 1;
            ((b1 as u16) << 8) | b2 as u16
        } else {
            b1 as u16
        };

        let mn = MNEMONICS.get(&index);

        // If we found a valid mnemonic, read in and decode all of its operands.
        // Otherwise, we must return a CpuException::IllegalOpcode
        match mn {
            Some(mn) => {
                let mut operands: Vec<Operand> = Vec::new();
                let mut etype: Option<Data> = None;

                for ot in &mn.ops {
                    // Push a decoded operand
                    let o = self.decode_operand(bus, mn, ot, etype, addr)?;
                    etype = o.expanded_type;
                    addr += o.size as usize;
                    operands.push(o);
                }

                let total_bytes = addr - initial_addr;

                Ok(DecodedInstruction {
                    bytes: total_bytes as u8,
                    mnemonic: mn,
                    operands,
                })
            }
            None => Err(CpuError::Exception(CpuException::IllegalOpcode)),
        }
    }

    /// Convenience operations on flags.
    fn set_v_flag_op(&mut self, val: u32, op: &Operand) {
        match op.data_type {
            Data::Word | Data::UWord => self.set_v_flag(false),
            Data::Half | Data::UHalf => self.set_v_flag(val > 0xffff),
            Data::Byte | Data::SByte => self.set_v_flag(val > 0xff),
            Data::None => {
                // Intentionally ignored
            }
        }
    }

    fn set_nz_flags(&mut self, val: u32, op: &Operand) {
        match op.data_type {
            Data::Word | Data::UWord => {
                self.set_n_flag((val & 0x80000000) != 0);
                self.set_z_flag(val == 0);
            }
            Data::Half | Data::UHalf => {
                self.set_n_flag((val & 0x8000) != 0);
                self.set_z_flag((val & 0xffff) == 0);
            }
            Data::Byte | Data::SByte => {
                self.set_n_flag((val & 0x80) != 0);
                self.set_z_flag((val & 0xff) == 0);
            }
            Data::None => {
                // Intentionally ignored
            }
        }
    }

    fn set_c_flag(&mut self, set: bool) {
        if set {
            self.r[R_PSW] |= F_C;
        } else {
            self.r[R_PSW] &= !F_C;
        }
    }

    fn c_flag(&self) -> bool {
        ((self.r[R_PSW] & F_C) >> 18) == 1
    }

    fn set_v_flag(&mut self, set: bool) {
        if set {
            self.r[R_PSW] |= F_V;
        } else {
            self.r[R_PSW] &= !F_V;
        }
    }

    fn v_flag(&self) -> bool {
        ((self.r[R_PSW] & F_V) >> 19) == 1
    }

    fn set_z_flag(&mut self, set: bool) {
        if set {
            self.r[R_PSW] |= F_Z;
        } else {
            self.r[R_PSW] &= !F_Z;
        }
    }

    fn z_flag(&self) -> bool {
        ((self.r[R_PSW] & F_Z) >> 20) == 1
    }

    fn set_n_flag(&mut self, set: bool) {
        if set {
            self.r[R_PSW] |= F_N;
        } else {
            self.r[R_PSW] &= !F_N;
        }
    }

    fn n_flag(&self) -> bool {
        ((self.r[R_PSW] & F_N) >> 21) == 1
    }

    pub fn set_isc(&mut self, val: u32) {
        self.r[R_PSW] &= !F_ISC; // Clear existing value
        self.r[R_PSW] |= (val & 0xf) << 3; // Set new value
    }

    pub fn set_priv_level(&mut self, val: u32) {
        let old_level = (self.r[R_PSW] & F_CM) >> 11;
        self.r[R_PSW] &= !F_PM; // Clear PM
        self.r[R_PSW] |= (old_level & 3) << 9; // Set PM
        self.r[R_PSW] &= !F_CM; // Clear CM
        self.r[R_PSW] |= (val & 3) << 11; // Set CM
    }

    pub fn stack_push(&mut self, bus: &mut Bus, val: u32) -> Result<(), CpuError> {
        bus.write_word(self.r[R_SP] as usize, val)?;
        self.r[R_SP] += 4;
        Ok(())
    }

    pub fn sack_pop(&mut self, bus: &mut Bus) -> Result<u32, CpuError> {
        let result = bus.read_word((self.r[R_SP] - 4) as usize, AccessCode::AddressFetch)?;
        self.r[R_SP] -= 4;
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bus::Bus;
    use mem::Mem;

    /// Helper function to set up and prepare a cpu and bus
    /// with a supplied program.
    fn do_with_program<F>(program: &[u8], test: F)
    where
        F: Fn(&mut Cpu, &mut Bus),
    {
        let mut cpu: Cpu = Cpu::new();
        let mut mem: Mem = Mem::new(0, 0x10000, false);
        let mut bus: Bus = Bus::new(0x10000);
        bus.add_device(&mut mem).unwrap();
        bus.load(0, &program).unwrap();

        test(&mut cpu, &mut bus);
    }

    #[test]
    fn sign_extension() {
        assert_eq!(0xffff8000, sign_extend_halfword(0x8000));
        assert_eq!(0xffffff80, sign_extend_byte(0x80));
    }

    #[test]
    fn can_set_and_clear_nzvc_flags() {
        let mut cpu = Cpu::new();
        cpu.set_c_flag(true);
        assert_eq!(cpu.r[R_PSW], F_C);
        cpu.set_v_flag(true);
        assert_eq!(cpu.r[R_PSW], F_C | F_V);
        cpu.set_z_flag(true);
        assert_eq!(cpu.r[R_PSW], F_C | F_V | F_Z);
        cpu.set_n_flag(true);
        assert_eq!(cpu.r[R_PSW], F_C | F_V | F_Z | F_N);
        cpu.set_c_flag(false);
        assert_eq!(cpu.r[R_PSW], F_V | F_Z | F_N);
        cpu.set_v_flag(false);
        assert_eq!(cpu.r[R_PSW], F_Z | F_N);
        cpu.set_z_flag(false);
        assert_eq!(cpu.r[R_PSW], F_N);
        cpu.set_n_flag(false);
        assert_eq!(cpu.r[R_PSW], 0);
    }

    #[test]
    fn can_set_isc_flag() {
        let mut cpu = Cpu::new();

        for i in 0..15 {
            cpu.set_isc(i);
            assert_eq!(i << 3, cpu.r[R_PSW]);
        }

        cpu.set_isc(16); // Out of range, should fail
        assert_eq!(0, cpu.r[R_PSW]);
    }

    #[test]
    fn decodes_byte_literal_operand() {
        let program: [u8; 2] = [0x4f, 0x06]; // BLEB 0x6

        do_with_program(&program, |cpu, mut bus| {
            let operand = cpu.decode_literal_operand(&mut bus, MNEMONICS.get(&0x4F).unwrap(), 1).unwrap();
            assert_eq!(operand, Operand::new(1, AddrMode::None, Data::Byte, None, None, 6));
        })
    }

    #[test]
    fn decodes_halfword_literal_operand() {
        let program: [u8; 3] = [0x4e, 0xff, 0x0f]; // BLEH 0xfff

        do_with_program(&program, |cpu, mut bus| {
            let operand = cpu.decode_literal_operand(&mut bus, MNEMONICS.get(&0x4e).unwrap(), 1).unwrap();
            assert_eq!(operand, Operand::new(2, AddrMode::None, Data::Half, None, None, 0xfff));
        })
    }

    #[test]
    fn decodes_word_literal_operand() {
        let program: [u8; 5] = [0x32, 0xff, 0x4f, 0x00, 0x00]; // SPOP 0x4fff

        do_with_program(&program, |cpu, mut bus| {
            let operand = cpu.decode_literal_operand(&mut bus, MNEMONICS.get(&0x32).unwrap(), 1).unwrap();
            assert_eq!(operand, Operand::new(4, AddrMode::None, Data::Word, None, None, 0x4fff));
        });
    }

    #[test]
    fn decodes_positive_literal_operand() {
        let program: [u8; 3] = [0x87, 0x04, 0x44]; // MOVB &4,%r4

        do_with_program(&program, |cpu, mut bus| {
            let operand = cpu.decode_descriptor_operand(&mut bus, Data::Byte, None, 1, false).unwrap();
            assert_eq!(operand, Operand::new(1, AddrMode::PositiveLiteral, Data::Byte, None, None, 0x04));
        });
    }

    #[test]
    fn decodes_word_immediate_operand() {
        let program = [0x84, 0x4f, 0x78, 0x56, 0x34, 0x12, 0x43]; // MOVW &0x12345678,%r3

        do_with_program(&program, |cpu, mut bus| {
            let operand = cpu.decode_descriptor_operand(&mut bus, Data::Word, None, 1, false).unwrap();
            assert_eq!(operand, Operand::new(5, AddrMode::WordImmediate, Data::Word, None, None, 0x12345678,));
        });
    }

    #[test]
    fn decodes_register_operand() {
        let program: [u8; 3] = [0x87, 0x04, 0x44]; // MOVB &4,%r4

        do_with_program(&program, |cpu, mut bus| {
            let operand = cpu.decode_descriptor_operand(&mut bus, Data::Byte, None, 2, false).unwrap();
            assert_eq!(operand, Operand::new(1, AddrMode::Register, Data::Byte, None, Some(4), 0));
        });
    }

    #[test]
    fn decodes_halfword_immediate_operand() {
        let program = [0x84, 0x5f, 0x34, 0x12, 0x42]; // MOVW &0x1234,%r2

        do_with_program(&program, |cpu, mut bus| {
            let operand = cpu.decode_descriptor_operand(&mut bus, Data::Word, None, 1, false).unwrap();
            assert_eq!(operand, Operand::new(3, AddrMode::HalfwordImmediate, Data::Word, None, None, 0x1234,));
        });
    }

    #[test]
    fn decodes_register_deferred_operand() {
        let program: [u8; 3] = [0x86, 0x52, 0x41]; // MOVH (%r2),%r1

        do_with_program(&program, |cpu, mut bus| {
            let operand = cpu.decode_descriptor_operand(&mut bus, Data::Half, None, 1, false).unwrap();
            assert_eq!(operand, Operand::new(1, AddrMode::RegisterDeferred, Data::Half, None, Some(2), 0));
        });
    }

    #[test]
    fn decodes_byte_immediate_operand() {
        let program: [u8; 4] = [0x84, 0x6f, 0x28, 0x46]; // MOVW &40,%r6

        do_with_program(&program, |cpu, mut bus| {
            let operand = cpu.decode_descriptor_operand(&mut bus, Data::Word, None, 1, false).unwrap();
            assert_eq!(operand, Operand::new(2, AddrMode::ByteImmediate, Data::Word, None, None, 40));
        });
    }

    #[test]
    fn decodes_fp_short_offset_operand() {
        let program: [u8; 3] = [0x84, 0x6C, 0x40]; // MOVW 12(%fp),%r0

        do_with_program(&program, |cpu, mut bus| {
            let operand = cpu.decode_descriptor_operand(&mut bus, Data::Word, None, 1, false).unwrap();
            assert_eq!(operand, Operand::new(1, AddrMode::FPShortOffset, Data::Word, None, Some(R_FP), 12));
        });
    }

    #[test]
    fn decodes_absolute_operand() {
        let program: [u8; 7] = [0x87, 0x7f, 0x00, 0x01, 0x00, 0x00, 0x40]; // MOVB $0x100, %r0

        do_with_program(&program, |cpu, mut bus| {
            let operand = cpu.decode_descriptor_operand(&mut bus, Data::Byte, None, 1, false).unwrap();
            assert_eq!(operand, Operand::new(5, AddrMode::Absolute, Data::Byte, None, None, 0x00000100));
        });
    }

    #[test]
    fn decodes_absolute_deferred_operand() {
        let program = [0x87, 0xef, 0x00, 0x01, 0x00, 0x00, 0x40]; // MOVB *$0x100,%r0

        do_with_program(&program, |cpu, mut bus| {
            let operand = cpu.decode_descriptor_operand(&mut bus, Data::Byte, None, 1, false).unwrap();
            assert_eq!(operand, Operand::new(5, AddrMode::AbsoluteDeferred, Data::Byte, None, None, 0x00000100));
        });
    }

    #[test]
    fn decodes_ap_short_offset_operand() {
        let program: [u8; 3] = [0x84, 0x74, 0x43]; // MOVW 4(%ap),%r3

        do_with_program(&program, |cpu, mut bus| {
            let operand = cpu.decode_descriptor_operand(&mut bus, Data::Word, None, 1, false).unwrap();
            assert_eq!(operand, Operand::new(1, AddrMode::APShortOffset, Data::Word, None, Some(R_AP), 4));
        });
    }

    #[test]
    fn decodes_word_displacement_operand() {
        let program: [u8; 7] = [0x87, 0x82, 0x34, 0x12, 0x00, 0x00, 0x44]; // MOVB 0x1234(%r2),%r4

        do_with_program(&program, |cpu, mut bus| {
            let operand = cpu.decode_descriptor_operand(&mut bus, Data::Byte, None, 1, false).unwrap();
            assert_eq!(operand, Operand::new(5, AddrMode::WordDisplacement, Data::Byte, None, Some(2), 0x1234,));
        });
    }

    #[test]
    fn decodes_word_displacement_deferred_operand() {
        let program: [u8; 7] = [0x87, 0x92, 0x50, 0x40, 0x00, 0x00, 0x40]; // MOVB *0x4050(%r2),%r0

        do_with_program(&program, |cpu, mut bus| {
            let operand = cpu.decode_descriptor_operand(&mut bus, Data::Byte, None, 1, false).unwrap();
            assert_eq!(operand, Operand::new(5, AddrMode::WordDisplacementDeferred, Data::Byte, None, Some(2), 0x4050,));
        });
    }

    #[test]
    fn decodes_halfword_displacement_operand() {
        let program: [u8; 5] = [0x87, 0xa2, 0x34, 0x12, 0x44]; // MOVB 0x1234(%r2),%r4

        do_with_program(&program, |cpu, mut bus| {
            let operand = cpu.decode_descriptor_operand(&mut bus, Data::Byte, None, 1, false).unwrap();
            assert_eq!(operand, Operand::new(3, AddrMode::HalfwordDisplacement, Data::Byte, None, Some(2), 0x1234,));
        });
    }

    #[test]
    fn decodes_halfword_displacement_deferred_operand() {
        let program: [u8; 5] = [0x87, 0xb2, 0x50, 0x40, 0x40]; // MOVB *0x4050(%r2),%r0

        do_with_program(&program, |cpu, mut bus| {
            let operand = cpu.decode_descriptor_operand(&mut bus, Data::Byte, None, 1, false).unwrap();
            assert_eq!(operand, Operand::new(3, AddrMode::HalfwordDisplacementDeferred, Data::Byte, None, Some(2), 0x4050,));
        });
    }

    #[test]
    fn decodes_byte_displacement_operand() {
        let program: [u8; 4] = [0x87, 0xc1, 0x06, 0x40]; // MOVB 6(%r1),%r0

        do_with_program(&program, |cpu, mut bus| {
            let operand = cpu.decode_descriptor_operand(&mut bus, Data::Byte, None, 1, false).unwrap();
            assert_eq!(operand, Operand::new(2, AddrMode::ByteDisplacement, Data::Byte, None, Some(1), 6));
        });
    }

    #[test]
    fn decodes_byte_displacement_deferred_operand() {
        let program: [u8; 4] = [0x87, 0xd2, 0x30, 0x43]; // MOVB *0x30(%r2),%r3

        do_with_program(&program, |cpu, mut bus| {
            let operand = cpu.decode_descriptor_operand(&mut bus, Data::Byte, None, 1, false).unwrap();
            assert_eq!(operand, Operand::new(2, AddrMode::ByteDisplacementDeferred, Data::Byte, None, Some(2), 0x30));
        });
    }

    #[test]
    fn decodes_expanded_type_operand() {
        let program: [u8; 6] = [0x87, 0xe7, 0x40, 0xe2, 0xc1, 0x04]; // MOVB {sbyte}%r0,{uhalf}4(%r1)

        do_with_program(&program, |cpu, mut bus| {
            let op1 = cpu.decode_descriptor_operand(&mut bus, Data::Byte, None, 1, false).unwrap();
            let op2 = cpu.decode_descriptor_operand(&mut bus, Data::Byte, None, 3, false).unwrap();

            assert_eq!(op1, Operand::new(2, AddrMode::Register, Data::Byte, Some(Data::SByte), Some(0), 0,));
            assert_eq!(op2, Operand::new(3, AddrMode::ByteDisplacement, Data::Byte, Some(Data::UHalf), Some(1), 4,));
        });
    }

    #[test]
    fn decodes_negative_literal_operand() {
        let program: [u8; 3] = [0x87, 0xff, 0x40]; // MOVB &-1,%r0

        do_with_program(&program, |cpu, mut bus| {
            let operand = cpu.decode_descriptor_operand(&mut bus, Data::Byte, None, 1, false).unwrap();
            assert_eq!(operand, Operand::new(1, AddrMode::NegativeLiteral, Data::Byte, None, None, 0xff));
        });
    }

    #[test]
    fn decodes_halfword_instructions() {
        let program = [0x30, 0x0d]; // ENBVJMP
        do_with_program(&program, |cpu, bus| {
            let instr = cpu.decode_instruction(bus).unwrap();
            assert_eq!(
                instr,
                DecodedInstruction {
                    bytes: 2,
                    mnemonic: MNEMONICS.get(&0x300d).unwrap(),
                    operands: vec![],
                }
            );
        })
    }

    #[test]
    fn decodes_instructions() {
        let program: [u8; 10] = [
            0x87, 0xe7, 0x40, 0xe2, 0xc1, 0x04, // MOVB {sbyte}%r0,{uhalf}4(%r1)
            0x87, 0xd2, 0x30, 0x43, // MOVB *0x30(%r2),%r3
        ];

        do_with_program(&program, |cpu, bus| {
            {
                cpu.set_pc(0);
                let inst = cpu.decode_instruction(bus).unwrap();
                let expected_operands = vec![
                    Operand::new(2, AddrMode::Register, Data::Byte, Some(Data::SByte), Some(0), 0),
                    Operand::new(3, AddrMode::ByteDisplacement, Data::Byte, Some(Data::UHalf), Some(1), 4),
                ];
                assert_eq!(
                    inst,
                    DecodedInstruction {
                        bytes: 6,
                        mnemonic: MNEMONICS.get(&0x87).unwrap(),
                        operands: expected_operands,
                    }
                );
            }
            {
                cpu.set_pc(6);
                let inst = cpu.decode_instruction(bus).unwrap();
                let expected_operands = vec![
                    Operand::new(2, AddrMode::ByteDisplacementDeferred, Data::Byte, None, Some(2), 0x30),
                    Operand::new(1, AddrMode::Register, Data::Byte, None, Some(3), 0),
                ];
                assert_eq!(
                    inst,
                    DecodedInstruction {
                        bytes: 4,
                        mnemonic: MNEMONICS.get(&0x87).unwrap(),
                        operands: expected_operands,
                    }
                );
            }
        })
    }

    #[test]
    fn reads_register_operand_data() {
        {
            let program = [0x87, 0xe7, 0x40, 0xe2, 0x41]; // MOVB {sbyte}%r0,{uhalf}%r1
            do_with_program(&program, |cpu, mut bus| {
                cpu.r[0] = 0xff;
                let op = cpu.decode_descriptor_operand(&mut bus, Data::Byte, None, 1, false).unwrap();
                assert_eq!(0xffffffff, cpu.read_op(bus, &op).unwrap());
            });
        }

        {
            let program = [0x87, 0x40, 0x41]; // MOVB %r0,%r1
            do_with_program(&program, |cpu, mut bus| {
                cpu.r[0] = 0xff;
                let op = cpu.decode_descriptor_operand(&mut bus, Data::Byte, None, 1, false).unwrap();
                assert_eq!(0xff, cpu.read_op(bus, &op).unwrap());
            });
        }
    }

    #[test]
    fn reads_positive_literal_operand_data() {
        let program = [0x87, 0x04, 0x44];
        do_with_program(&program, |cpu, mut bus| {
            let op = cpu.decode_descriptor_operand(&mut bus, Data::Byte, None, 1, false).unwrap();
            assert_eq!(4, cpu.read_op(bus, &op).unwrap() as i8);
        });
    }

    #[test]
    fn reads_negative_literal_operand_data() {
        let program = [0x87, 0xff, 0x44];
        do_with_program(&program, |cpu, mut bus| {
            let op = cpu.decode_descriptor_operand(&mut bus, Data::Byte, None, 1, false).unwrap();
            assert_eq!(-1, cpu.read_op(bus, &op).unwrap() as i8);
        });
    }

    #[test]
    fn reads_word_immediate_operand_data() {
        let program = [0x84, 0x4f, 0x78, 0x56, 0x34, 0x12, 0x43]; // MOVW &0x12345678,%r3
        do_with_program(&program, |cpu, mut bus| {
            let op = cpu.decode_descriptor_operand(&mut bus, Data::Word, None, 1, false).unwrap();
            assert_eq!(0x12345678, cpu.read_op(bus, &op).unwrap())
        });
    }

    #[test]
    fn reads_halfword_immediate_operand_data() {
        let program = [0x84, 0x5f, 0x34, 0x12, 0x42]; // MOVW &0x1234,%r2
        do_with_program(&program, |cpu, mut bus| {
            let op = cpu.decode_descriptor_operand(&mut bus, Data::Word, None, 1, false).unwrap();
            assert_eq!(0x1234, cpu.read_op(bus, &op).unwrap())
        });
    }

    #[test]
    fn reads_negative_halfword_immediate_operand_data() {
        let program = [0x84, 0x5f, 0x00, 0x80, 0x42]; // MOVW &0x8000,%r2
        do_with_program(&program, |cpu, mut bus| {
            let op = cpu.decode_descriptor_operand(&mut bus, Data::Word, None, 1, false).unwrap();
            assert_eq!(0xffff8000, cpu.read_op(bus, &op).unwrap())
        });
    }

    #[test]
    fn reads_byte_immediate_operand_data() {
        let program = [0x84, 0x6f, 0x28, 0x42]; // MOVW &40,%r2
        do_with_program(&program, |cpu, mut bus| {
            let op = cpu.decode_descriptor_operand(&mut bus, Data::Word, None, 1, false).unwrap();
            assert_eq!(40, cpu.read_op(bus, &op).unwrap())
        });
    }

    #[test]
    fn reads_negative_byte_immediate_operand_data() {
        let program = [0x84, 0x6f, 0xff, 0x42]; // MOVW &-1,%r2
        do_with_program(&program, |cpu, mut bus| {
            let op = cpu.decode_descriptor_operand(&mut bus, Data::Word, None, 1, false).unwrap();
            assert_eq!(-1, cpu.read_op(bus, &op).unwrap() as i32)
        });
    }

    #[test]
    fn reads_absolute_operand_data() {
        let program = [0x87, 0x7f, 0x00, 0x01, 0x00, 0x00, 0x04]; // MOVB $0x100,%r0
        do_with_program(&program, |cpu, mut bus| {
            bus.write_byte(0x100, 0x5a).unwrap();
            let op = cpu.decode_descriptor_operand(&mut bus, Data::Byte, None, 1, false).unwrap();
            assert_eq!(0x5a, cpu.read_op(bus, &op).unwrap());
        });
    }

    #[test]
    fn reads_absolute_deferred_operand_data() {
        let program = [0x87, 0xef, 0x00, 0x01, 0x00, 0x00, 0x41]; // MOVB *$0x100,%r0
        do_with_program(&program, |cpu, mut bus| {
            bus.write_word(0x100, 0x300).unwrap();
            bus.write_byte(0x300, 0x1f).unwrap();
            let op = cpu.decode_descriptor_operand(&mut bus, Data::Byte, None, 1, false).unwrap();
            assert_eq!(0x1f, cpu.read_op(bus, &op).unwrap());
        });
    }

    #[test]
    fn reads_byte_displacement_operand_data() {
        let program = [
            0x87, 0xc1, 0x06, 0x40, // MOVB 6(%r1),%r0
            0x87, 0xc1, 0xfe, 0x40, // MOVB -2(%r1),%r0
        ];
        do_with_program(&program, |cpu, mut bus| {
            cpu.r[1] = 0x300;
            bus.write_byte(0x306, 0x1f).unwrap();
            bus.write_byte(0x2fe, 0xc5).unwrap();
            let op1 = cpu.decode_descriptor_operand(&mut bus, Data::Byte, None, 1, false).unwrap();
            let op2 = cpu.decode_descriptor_operand(&mut bus, Data::Byte, None, 5, false).unwrap();
            assert_eq!(0x1f, cpu.read_op(bus, &op1).unwrap());
            assert_eq!(0xc5, cpu.read_op(bus, &op2).unwrap());
        });
    }

    #[test]
    fn reads_byte_displacement_deferred_operand_data() {
        let program = [0x87, 0xd2, 0x30, 0x43]; // MOVB *0x30(%r2),%r3
        do_with_program(&program, |cpu, mut bus| {
            cpu.r[2] = 0x300;
            bus.write_word(0x330, 0x1000).unwrap();
            bus.write_byte(0x1000, 0x5a).unwrap();
            let op = cpu.decode_descriptor_operand(&mut bus, Data::Byte, None, 1, false).unwrap();
            assert_eq!(0x5a, cpu.read_op(bus, &op).unwrap());
        })
    }

    #[test]
    fn reads_halword_displacement_operand_data() {
        let program = [0x87, 0xa2, 0x01, 0x11, 0x48]; // MOVB 0x1101(%r2),%r8
        do_with_program(&program, |cpu, mut bus| {
            cpu.r[2] = 0x300;
            bus.write_byte(0x1401, 0x1f).unwrap();
            let op = cpu.decode_descriptor_operand(&mut bus, Data::Byte, None, 1, false).unwrap();
            assert_eq!(0x1f, cpu.read_op(bus, &op).unwrap());
        });
    }

    #[test]
    fn reads_halfword_displacement_deferred_operand_data() {
        let program = [0x87, 0xb2, 0x00, 0x02, 0x46]; // MOVB *0x200(%r2),%r6
        do_with_program(&program, |cpu, mut bus| {
            cpu.r[2] = 0x300;
            bus.write_word(0x500, 0x1000).unwrap();
            bus.write_byte(0x1000, 0x5a).unwrap();
            let op = cpu.decode_descriptor_operand(&mut bus, Data::Byte, None, 1, false).unwrap();
            assert_eq!(0x5a, cpu.read_op(bus, &op).unwrap());
        })
    }

    #[test]
    fn reads_word_displacement_operand_data() {
        let program = [0x87, 0x82, 0x01, 0x11, 0x00, 0x00, 0x48]; // MOVB 0x1101(%r2),%r8
        do_with_program(&program, |cpu, mut bus| {
            cpu.r[2] = 0x300;
            bus.write_byte(0x1401, 0x1f).unwrap();
            let op = cpu.decode_descriptor_operand(&mut bus, Data::Byte, None, 1, false).unwrap();
            assert_eq!(0x1f, cpu.read_op(bus, &op).unwrap());
        });
    }

    #[test]
    fn reads_word_displacement_deferred_operand_data() {
        let program = [0x87, 0x92, 0x00, 0x02, 0x00, 0x00, 0x46]; // MOVB *0x200(%r2),%r6
        do_with_program(&program, |cpu, mut bus| {
            cpu.r[2] = 0x300;
            bus.write_word(0x500, 0x1000).unwrap();
            bus.write_byte(0x1000, 0x5a).unwrap();
            let op = cpu.decode_descriptor_operand(&mut bus, Data::Byte, None, 1, false).unwrap();
            assert_eq!(0x5a, cpu.read_op(bus, &op).unwrap());
        })
    }

    #[test]
    fn reads_ap_short_offset_operand_data() {
        let program = [0x84, 0x74, 0x43]; // MOVW 4(%ap),%r3
        do_with_program(&program, |cpu, mut bus| {
            cpu.r[R_AP] = 0x1000;
            bus.write_word(0x1004, 0x12345678).unwrap();
            let op = cpu.decode_descriptor_operand(&mut bus, Data::Word, None, 1, false).unwrap();
            assert_eq!(0x12345678, cpu.read_op(bus, &op).unwrap());
        });
    }

    #[test]
    fn reads_fp_short_offset_operand_data() {
        let program = [0x84, 0x6c, 0x40]; // MOVW 12(%fp),%r0
        do_with_program(&program, |cpu, mut bus| {
            cpu.r[R_FP] = 0x1000;
            bus.write_word(0x100c, 0x12345678).unwrap();
            let op = cpu.decode_descriptor_operand(&mut bus, Data::Word, None, 1, false).unwrap();
            assert_eq!(0x12345678, cpu.read_op(bus, &op).unwrap());
        });
    }

    #[test]
    fn writes_register_operand_data() {
        let program = [0x40];
        do_with_program(&program, |cpu, mut bus| {
            cpu.r[0] = 0;
            let op = cpu.decode_descriptor_operand(&mut bus, Data::Byte, None, 0, false).unwrap();
            cpu.write_op(bus, &op, 0x5a).unwrap();
            assert_eq!(0x5a, cpu.r[0]);
        });
    }

    #[test]
    fn movw_acceptance() {
        let program = [
            0x84, 0x01, 0x40, // MOVW &1,%r0
            0x84, 0xff, 0x41, // MOVW &-1,%r1
            0x84, 0xff, 0x42, // MOVW &0xff,%r2
            0x84, 0x5f, 0xff, 0x01, 0x43, // MOVW &0x1ff,%r3
            0x84, 0x4f, 0x78, 0x56, 0x34, 0x12, 0x44, // MOVW &0x12345678,%r4
        ];
        do_with_program(&program, |cpu, mut bus| {
            cpu.step(&mut bus);
            assert_eq!(cpu.r[0], 1);
            cpu.step(&mut bus);
            assert_eq!(cpu.r[1] as i32, -1);
            cpu.step(&mut bus);
            assert_eq!(cpu.r[2] as i32, -1);
            cpu.step(&mut bus);
            assert_eq!(cpu.r[3], 0x1ff);
            cpu.step(&mut bus);
            assert_eq!(cpu.r[4], 0x12345678);
        });
    }

    #[test]
    fn movh_acceptance() {
        let program = [
            0x86, 0x01, 0x40, // MOVH &1,%r0
            0x86, 0xff, 0x41, // MOVH &-1,%r1
            0x86, 0xff, 0x42, // MOVH &0xff,%r2
            0x86, 0x5f, 0xff, 0x01, 0x43, // MOVH &0x1ff,%r3
            0x86, 0x5f, 0x00, 0x80, 0x44, // MOVH &0x8000,%r4
            0x86, 0x7f, 0x00, 0x01, 0x00, 0x00, 0x40, // MOVH $0x100,%r0
            0x86, 0xef, 0x00, 0x02, 0x00, 0x00, 0x41, // MOVH *$0x200,%r1
            0x86, 0xc1, 0x06, 0x42, // MOVH 6(%r1),%r2
        ];
        do_with_program(&program, |cpu, mut bus| {
            // Setup
            bus.write_word(0x100, 0x12345678).unwrap();
            bus.write_word(0x200, 0x2000).unwrap();
            bus.write_word(0x2000, 0x3000).unwrap();
            bus.write_half(0x3006, 0xabcd).unwrap();

            cpu.step(&mut bus);
            assert_eq!(1, cpu.r[0]);
            cpu.step(&mut bus);
            assert_eq!(-1, cpu.r[1] as i32);
            cpu.step(&mut bus);
            assert_eq!(-1, cpu.r[2] as i32);
            cpu.step(&mut bus);
            assert_eq!(0x1ff, cpu.r[3]);
            cpu.step(&mut bus);
            assert_eq!(0xffff8000, cpu.r[4]);
            cpu.step(&mut bus);
            assert_eq!(0x5678, cpu.r[0]);
            cpu.step(&mut bus);
            assert_eq!(0x3000, cpu.r[1]);
            cpu.step(&mut bus);
            assert_eq!(0xffffabcd, cpu.r[2]);
        });
    }

    #[test]
    fn movb_acceptance() {
        let program = [
            0x87, 0x01, 0x40, // MOVB &1,%r0
            0x87, 0xff, 0x41, // MOVB &-1,%r1
            0x87, 0xff, 0x42, // MOVB &0xff,%r2
            0x87, 0x1f, 0x43, // MOVB &0x1f,%r3
            0x87, 0x7f, 0x00, 0x01, 0x00, 0x00, 0x40, // MOVB $0x100,%r0
            0x87, 0xef, 0x00, 0x02, 0x00, 0x00, 0x41, // MOVB *$0x200,%r1
            0x87, 0xc6, 0x05, 0x42, // MOVB 5(%r6),%r2
            0x87, 0xd6, 0x08, 0x43, // MOVB *8(%r6),%r3
            0x87, 0xc6, 0xff, 0x44, // MOVB -1(%r6),%r4
        ];
        do_with_program(&program, |cpu, mut bus| {
            // Setup
            bus.write_byte(0x100, 0x5a).unwrap();
            bus.write_word(0x200, 0x300).unwrap();
            bus.write_byte(0x300, 0xa5).unwrap();
            bus.write_byte(0x3005, 0xe0).unwrap();
            bus.write_word(0x3008, 0x280).unwrap();
            bus.write_byte(0x280, 0x2f).unwrap();
            bus.write_byte(0x2fff, 0xba).unwrap();
            cpu.r[6] = 0x3000;

            cpu.step(&mut bus);
            assert_eq!(1, cpu.r[0]);
            cpu.step(&mut bus);
            assert_eq!(-1, cpu.r[1] as i32);
            cpu.step(&mut bus);
            assert_eq!(-1, cpu.r[2] as i32);
            cpu.step(&mut bus);
            assert_eq!(0x1f, cpu.r[3]);
            cpu.step(&mut bus);
            assert_eq!(0x5a, cpu.r[0]);
            cpu.step(&mut bus);
            assert_eq!(0xa5, cpu.r[1]);
            cpu.step(&mut bus);
            assert_eq!(0xe0, cpu.r[2]);
            cpu.step(&mut bus);
            assert_eq!(0x2f, cpu.r[3]);
            cpu.step(&mut bus);
            assert_eq!(0xba, cpu.r[4]);
        });
    }

    #[test]
    fn add_acceptance() {
        let program = [
            0x9c, 0x5f, 0x00, 0x01, 0x40, // ADDW2 &0x100,%r0
            0x9e, 0x5f, 0xff, 0x01, 0x41, // ADDH2 &0x1ff,%r1
            0x9f, 0xff, 0x42, // ADDB2 &0xff,%r2
            0x9f, 0xff, 0x43, // ADDB2 &0xff,%r3
        ];
        do_with_program(&program, |cpu, mut bus| {
            // Setup
            cpu.r[0] = 0x1f;
            cpu.r[1] = 0x3fff;
            cpu.r[2] = 0x2;
            cpu.r[3] = 0x1;
            cpu.step(&mut bus);
            assert_eq!(0x11f, cpu.r[0]);
            assert!(!cpu.c_flag());
            assert!(!cpu.z_flag());
            cpu.step(&mut bus);
            assert_eq!(0x41fe, cpu.r[1]);
            assert!(!cpu.c_flag());
            assert!(!cpu.z_flag());
            cpu.step(&mut bus);
            assert_eq!(0x1, cpu.r[2]);
            assert!(cpu.c_flag());
            assert!(!cpu.z_flag());
            cpu.step(&mut bus);
            assert_eq!(0, cpu.r[3]);
            assert!(cpu.c_flag());
            assert!(cpu.z_flag());
        });
    }

    #[test]
    fn alsw3_acceptance() {
        let program = [
            0xc0, 0x01, 0x01, 0x40, // ALSW3 &1,&1,%r0
            0xc0, 0x40, 0x01, 0x40, // ALSW3 %r0,&1,%r0
            0xc0, 0x40, 0x01, 0x40, // ALSW3 %r0,&1,%r0
            0xc0, 0x40, 0x01, 0x40, // ALSW3 %r0,&1,%r0
            0xc0, 0x40, 0x01, 0x40, // ALSW3 %r0,&1,%r0
            0xc0, 0x40, 0x01, 0x40, // ALSW3 %r0,&1,%r0
            0xc0, 0x40, 0x01, 0x40, // ALSW3 %r0,&1,%r0
            0xc0, 0x40, 0x01, 0x40, // ALSW3 %r0,&1,%r0
            0xc0, 0x40, 0x01, 0x40, // ALSW3 %r0,&1,%r0
            0xc0, 0x40, 0x01, 0x40, // ALSW3 %r0,&1,%r0
            0xc0, 0x40, 0x01, 0x40, // ALSW3 %r0,&1,%r0
            0xc0, 0x40, 0x01, 0x40, // ALSW3 %r0,&1,%r0
            0xc0, 0x40, 0x01, 0x40, // ALSW3 %r0,&1,%r0
            0xc0, 0x40, 0x01, 0x40, // ALSW3 %r0,&1,%r0
            0xc0, 0x40, 0x01, 0x40, // ALSW3 %r0,&1,%r0
            0xc0, 0x40, 0x01, 0x40, // ALSW3 %r0,&1,%r0
            0xc0, 0x4f, 0x00, 0x00, 0x00, 0x80, 0x01, 0x40, // ALSW3 &0x80000000,&1,%r0
        ];
        do_with_program(&program, |cpu, mut bus| {
            cpu.step(&mut bus);
            assert_eq!(0x02, cpu.r[0]);
            cpu.step(&mut bus);
            assert_eq!(0x04, cpu.r[0]);
            cpu.step(&mut bus);
            assert_eq!(0x08, cpu.r[0]);
            cpu.step(&mut bus);
            assert_eq!(0x10, cpu.r[0]);
            cpu.step(&mut bus);
            assert_eq!(0x20, cpu.r[0]);
            cpu.step(&mut bus);
            assert_eq!(0x40, cpu.r[0]);
            cpu.step(&mut bus);
            assert_eq!(0x80, cpu.r[0]);
            cpu.step(&mut bus);
            assert_eq!(0x100, cpu.r[0]);
            cpu.step(&mut bus);
            assert_eq!(0x200, cpu.r[0]);
            cpu.step(&mut bus);
            assert_eq!(0x400, cpu.r[0]);
            cpu.step(&mut bus);
            assert_eq!(0x800, cpu.r[0]);
            cpu.step(&mut bus);
            assert_eq!(0x1000, cpu.r[0]);
            cpu.step(&mut bus);
            assert_eq!(0x2000, cpu.r[0]);
            cpu.step(&mut bus);
            assert_eq!(0x4000, cpu.r[0]);
            cpu.step(&mut bus);
            assert_eq!(0x8000, cpu.r[0]);
            cpu.step(&mut bus);
            assert_eq!(0x10000, cpu.r[0]);
            cpu.step(&mut bus);
            assert_eq!(0, cpu.r[0]);
        });
    }

    #[test]
    fn andw_acceptance() {
        let program = [
            0xb8, 0x4f, 0xff, 0x00, 0xff, 0xff, 0x40, // ANDW2 &0xffff00ff,%r0
            0xba, 0x5f, 0x0f, 0xff, 0x41, // ANDH2 &0xff0f,%r2
            0xbb, 0x0f, 0x42, // ANDB2 &0x0f,%r3
        ];
        do_with_program(&program, |cpu, mut bus| {
            // Setup
            cpu.r[0] = 0x12345678;
            cpu.r[1] = 0x1234;
            cpu.r[2] = 0x12;

            cpu.step(&mut bus);
            assert_eq!(0x12340078, cpu.r[0]);
            cpu.step(&mut bus);
            assert_eq!(0x1204, cpu.r[1]);
            cpu.step(&mut bus);
            assert_eq!(0x02, cpu.r[2]);
        });
    }

    #[test]
    fn beb_acceptance() {
        let program = [
            0x6f, 0x04, // BEB &4
            0x70, // NOP
            0x70, // NOP
            0x6f, 0xff, // BEB &-1
        ];
        do_with_program(&program, |cpu, mut bus| {
            cpu.set_z_flag(true);
            cpu.step(&mut bus);
            assert_eq!(4, cpu.r[R_PC]);
            cpu.step(&mut bus);
            assert_eq!(3, cpu.r[R_PC]);
        });
        do_with_program(&program, |cpu, mut bus| {
            cpu.set_z_flag(false);
            cpu.step(&mut bus);
            assert_eq!(2, cpu.r[R_PC]);
            cpu.step(&mut bus);
            cpu.step(&mut bus);
            cpu.step(&mut bus);
            assert_eq!(6, cpu.r[R_PC]);
        });
    }

    #[test]
    fn beh_acceptance() {
        let program = [
            0x6e, 0x0a, 0x00, // BEH &10
            0x6e, 0xfd, 0xff, // BEH &-3
        ];
        do_with_program(&program, |cpu, mut bus| {
            cpu.set_z_flag(true);
            cpu.step(&mut bus);
            assert_eq!(10, cpu.r[R_PC]);
            cpu.r[R_PC] = 3;
            cpu.step(&mut bus);
            assert_eq!(0, cpu.r[R_PC]);
        });
        do_with_program(&program, |cpu, mut bus| {
            cpu.set_z_flag(false);
            cpu.step(&mut bus);
            assert_eq!(3, cpu.r[R_PC]);
            cpu.step(&mut bus);
            assert_eq!(6, cpu.r[R_PC]);
        });
    }

}
