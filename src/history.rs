use cpu::DecodedInstruction;
use cpu::Operand;
use cpu::AddrMode;

///
/// A very simple fixed-size ring buffer to record CPU history.
///

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct HistoryEntry {
    pub pc: u32,
    pub text: String,
}

impl HistoryEntry {
    fn decode_operand(op: &Operand) -> String {
        match op.mode {
            AddrMode::Absolute => format!("&0x{:x}", op.embedded),
            AddrMode::AbsoluteDeferred => format!("*&0x{:x}", op.embedded),
            AddrMode::APShortOffset => format!("{}(%ap)", op.embedded as i8),
            AddrMode::FPShortOffset => format!("{}(%fp)", op.embedded as i8),
            AddrMode::ByteDisplacement => {
                match op.register {
                    Some(r) => match r {
                        9 => format!("{}(%fp)", op.embedded as i8),
                        10 => format!("{}(%ap)", op.embedded as i8),
                        11 => format!("{}(%psw)", op.embedded as i8),
                        12 => format!("{}(%sp)", op.embedded as i8),
                        13 => format!("{}(%pcbp)", op.embedded as i8),
                        14 => format!("{}(%isp)", op.embedded as i8),
                        15 => format!("{}(%pc)", op.embedded as i8),
                        _ => format!("{}(%r{})", op.embedded as i8, r),
                    }
                    None => "???".to_owned()
                }
            }
            AddrMode::ByteDisplacementDeferred => {
                match op.register {
                    Some(r) => match r {
                        9 => format!("*{}(%fp)", op.embedded as i8),
                        10 => format!("*{}(%ap)", op.embedded as i8),
                        11 => format!("*{}(%psw)", op.embedded as i8),
                        12 => format!("*{}(%sp)", op.embedded as i8),
                        13 => format!("*{}(%pcbp)", op.embedded as i8),
                        14 => format!("*{}(%isp)", op.embedded as i8),
                        15 => format!("*{}(%pc)", op.embedded as i8),
                        _ => format!("*{}(%r{})", op.embedded as i8, r),
                    }
                    None => "???".to_owned()
                }
            }
            AddrMode::HalfwordDisplacement => {
                match op.register {
                    Some(r) => match r {
                        9 => format!("{}(%fp)", op.embedded as i16),
                        10 => format!("{}(%ap)", op.embedded as i16),
                        11 => format!("{}(%psw)", op.embedded as i16),
                        12 => format!("{}(%sp)", op.embedded as i16),
                        13 => format!("{}(%pcbp)", op.embedded as i16),
                        14 => format!("{}(%isp)", op.embedded as i16),
                        15 => format!("{}(%pc)", op.embedded as i16),
                        _ => format!("{}(%r{})", op.embedded as i16, r),
                    }
                    None => "???".to_owned()
                }
            }
            AddrMode::HalfwordDisplacementDeferred => {
                match op.register {
                    Some(r) => match r {
                        9 => format!("*{}(%fp)", op.embedded as i16),
                        10 => format!("*{}(%ap)", op.embedded as i16),
                        11 => format!("*{}(%psw)", op.embedded as i16),
                        12 => format!("*{}(%sp)", op.embedded as i16),
                        13 => format!("*{}(%pcbp)", op.embedded as i16),
                        14 => format!("*{}(%isp)", op.embedded as i16),
                        15 => format!("*{}(%pc)", op.embedded as i16),
                        _ => format!("*{}(%r{})", op.embedded as i16, r),
                    }
                    None => "???".to_owned()
                }
            }
            AddrMode::WordDisplacement => {
                match op.register {
                    Some(r) => match r {
                        9 => format!("{}(%fp)", op.embedded as i32),
                        10 => format!("{}(%ap)", op.embedded as i32),
                        11 => format!("{}(%psw)", op.embedded as i32),
                        12 => format!("{}(%sp)", op.embedded as i32),
                        13 => format!("{}(%pcbp)", op.embedded as i32),
                        14 => format!("{}(%isp)", op.embedded as i32),
                        15 => format!("{}(%pc)", op.embedded as i32),
                        _ => format!("{}(%r{})", op.embedded as i32, r),
                    }
                    None => "???".to_owned()
                }
            }
            AddrMode::WordDisplacementDeferred => {
                match op.register {
                    Some(r) => match r {
                        9 => format!("*{}(%fp)", op.embedded as i32),
                        10 => format!("*{}(%ap)", op.embedded as i32),
                        11 => format!("*{}(%psw)", op.embedded as i32),
                        12 => format!("*{}(%sp)", op.embedded as i32),
                        13 => format!("*{}(%pcbp)", op.embedded as i32),
                        14 => format!("*{}(%isp)", op.embedded as i32),
                        15 => format!("*{}(%pc)", op.embedded as i32),
                        _ => format!("*{}(%r{})", op.embedded as i32, r),
                    }
                    None => "???".to_owned()
                }
            }
            AddrMode::Register => {
                match op.register {
                    Some(r) => match r {
                        9 => "%fp".to_owned(),
                        10 => "%ap".to_owned(),
                        11 => "%psw".to_owned(),
                        12 => "%sp".to_owned(),
                        13 => "%pcbp".to_owned(),
                        14 => "%isp".to_owned(),
                        15 => "%pc".to_owned(),
                        _ => format!("%r{}", r),
                    }
                    None => "???".to_owned()
                }
            }
            _ => format!("0x{:x}", op.embedded)
        }
    }

    fn decode_instruction(instr: &DecodedInstruction, pc: u32) -> String {
        let mut decoded = String::new();

        decoded.push_str(format!("{:08x}:\t\t{}", pc, instr.name).as_str());

        if !instr.operands.is_empty() {
            decoded.push_str("\t");
        }

        let mut op_vec = vec!();

        for op in &instr.operands {
            op_vec.push(HistoryEntry::decode_operand(&op));
        }

        decoded.push_str(op_vec.join(",").as_str());

        decoded
    }

    pub fn new(instr: &DecodedInstruction, pc: u32) -> HistoryEntry {
        HistoryEntry {
            pc,
            text: HistoryEntry::decode_instruction(instr, pc),
        }
    }
}

pub struct History {
    pub capacity: u32,
    pub index: u32,
    pub read_ptr: u32,
    pub history: Vec<HistoryEntry>,
}

impl History {
    pub fn new(capacity: u32) -> History {
        History {
            capacity,
            index: 0,
            read_ptr: 0,
            history: Vec::with_capacity(capacity as usize),
        }
    }

    pub fn push(&mut self, entry: HistoryEntry) {
        if self.history.len() < self.capacity as usize {
            self.history.push(entry);
        } else {
            self.history[self.index as usize] = entry;
        }

        self.index = (self.index + 1) % self.capacity;

        if self.index == (self.read_ptr + 1) % self.capacity {
            self.read_ptr = (self.read_ptr + 1) % self.capacity;
        }
    }

    pub fn len(&self) -> u32 {
        self.history.len() as u32
    }

    pub fn capacity(&self) -> u32 {
        self.capacity
    }
}

impl Iterator for History {
    type Item = String;

    fn next(&mut self) -> Option<String> {
        if self.history.len() == 0 {
            return None
        }

        let entry = &self.history[self.read_ptr as usize];
        let entry_text = entry.text.as_str();

        self.read_ptr = (self.read_ptr + 1) % self.capacity;

        Some(entry_text.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_history_with_initial_capacity() {
        let history = History::new(1024);
        assert_eq!(1024, history.capacity());
    }

    #[test]
    fn pushes_back() {
        let mut history = History::new(3);
        assert_eq!(0, history.len());
        assert_eq!(0, history.index);
        history.push(HistoryEntry { text: "FOO".to_owned(), pc: 0 });
        assert_eq!(1, history.len());
        assert_eq!(1, history.index);
        history.push(HistoryEntry { text: "BAR".to_owned(), pc: 0 });
        assert_eq!(2, history.len());
        assert_eq!(2, history.index);
        history.push(HistoryEntry { text: "BAZ".to_owned(), pc: 0 });
        assert_eq!(3, history.len());
        assert_eq!(0, history.index);
        history.push(HistoryEntry { text: "QUUX".to_owned(), pc: 0 });
        assert_eq!(3, history.len());
        assert_eq!(1, history.index);
        history.push(HistoryEntry { text: "FLATCH".to_owned(), pc: 0 });
        assert_eq!(3, history.len());
        assert_eq!(2, history.index);

        assert_eq!("BAZ", history.next().unwrap());
        assert_eq!("QUUX", history.next().unwrap());
        assert_eq!("FLATCH", history.next().unwrap());
        assert_eq!("BAZ", history.next().unwrap());
        assert_eq!("QUUX", history.next().unwrap());
        assert_eq!("FLATCH", history.next().unwrap());
    }
}