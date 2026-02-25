use std::io;

pub trait BlockReader {
    fn read_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()>;
    fn len(&self) -> u64;
}

pub struct MemImage {
    data: Vec<u8>,
}

impl MemImage {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }
}

impl BlockReader for MemImage {
    fn read_at(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        let start = usize::try_from(offset).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "offset overflow"))?;
        let end = start
            .checked_add(out.len())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "range overflow"))?;
        if end > self.data.len() {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "out-of-bounds read"));
        }
        out.copy_from_slice(&self.data[start..end]);
        Ok(())
    }

    fn len(&self) -> u64 {
        self.data.len() as u64
    }
}
