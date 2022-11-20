use thiserror::Error;

const FIFO_LEN: usize = 3;

/// A simple circular buffer with three slots, used as a
/// DUART character FIFO
pub struct FifoQueue {
    buf: [u8; 3],
    read_ptr: usize,
    write_ptr: usize,
    len: usize,
}

#[derive(Error, Debug, Eq, PartialEq)]
pub enum FifoError {
    #[error("fifo full")]
    Overflow,
    #[error("fifo under-run")]
    Underrun,
}

impl FifoQueue {
    pub fn new() -> Self {
        FifoQueue {
            buf: [0; FIFO_LEN],
            read_ptr: 0,
            write_ptr: 0,
            len: 0,
        }
    }

    pub fn push(&mut self, c: u8) -> Result<(), FifoError> {
        if self.len == FIFO_LEN {
            Err(FifoError::Overflow)
        } else {
            self.buf[self.write_ptr] = c;
            self.write_ptr = (self.write_ptr + 1) % FIFO_LEN;
            self.len += 1;
            Ok(())
        }
    }

    pub fn pop(&mut self) -> Result<u8, FifoError> {
        if self.len == 0 {
            Err(FifoError::Underrun)
        } else {
            let c = self.buf[self.read_ptr];
            self.read_ptr = (self.read_ptr + 1) % FIFO_LEN;
            self.len -= 1;
            Ok(c)
        }
    }

    pub fn clear(&mut self) {
        self.read_ptr = 0;
        self.write_ptr = 0;
        self.len = 0;
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn is_full(&self) -> bool {
        self.len == FIFO_LEN
    }

    pub fn len(&self) -> usize {
        self.len
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn pops_in_order() {
        let mut f: FifoQueue = FifoQueue::new();

        assert_eq!(Ok(()), f.push(1));
        assert_eq!(Ok(()), f.push(2));
        assert_eq!(Ok(()), f.push(3));
        assert_eq!(Ok(1), f.pop());
        assert_eq!(Ok(2), f.pop());
        assert_eq!(Ok(3), f.pop());
    }

    #[test]
    fn popping_when_empty_returns_underrun_error() {
        let mut f: FifoQueue = FifoQueue::new();

        assert_eq!(0, f.len());
        assert_eq!(Err(FifoError::Underrun), f.pop());

        assert_eq!(Ok(()), f.push(42));
        assert_eq!(1, f.len());
        assert_eq!(Ok(42), f.pop());
        assert_eq!(Err(FifoError::Underrun), f.pop());
    }

    #[test]
    fn pushing_when_full_returns_overflow_error() {
        let mut f: FifoQueue = FifoQueue::new();

        assert_eq!(0, f.len());
        assert_eq!(Ok(()), f.push(0xff));
        assert_eq!(1, f.len());
        assert_eq!(Ok(()), f.push(0xfe));
        assert_eq!(2, f.len());
        assert_eq!(Ok(()), f.push(0xfd));
        assert_eq!(3, f.len());
        assert_eq!(Err(FifoError::Overflow), f.push(0xfc));
        assert_eq!(3, f.len());
    }
}
