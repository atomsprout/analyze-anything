//! Streaming decompression with a declared output size and an exact stream boundary.

use std::io::{self, Read};

use flate2::{Decompress, FlushDecompress, Status};

pub(crate) struct Inflate<'a> {
    input: &'a [u8],
    decoder: Decompress,
    expected: u64,
    ended: bool,
}

impl<'a> Inflate<'a> {
    pub fn new(input: &'a [u8], expected: u64, zlib: bool) -> Self {
        Self { input, decoder: Decompress::new(zlib), expected, ended: false }
    }
}

impl Read for Inflate<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.ended || output.is_empty() {
                return Ok(0);
            }
            let input_before = self.decoder.total_in();
            let output_before = self.decoder.total_out();
            let start = usize::try_from(input_before).map_err(|_| io::Error::other("compressed input offset overflow"))?;
            let remaining = self.input.get(start..).ok_or_else(|| io::Error::other("compressed input offset outside entry"))?;
            let status = self.decoder.decompress(remaining, output, FlushDecompress::None).map_err(io::Error::other)?;
            if self.decoder.total_out() > self.expected {
                return Err(io::Error::other("decompressed content exceeds its declared size"));
            }
            let produced =
                usize::try_from(self.decoder.total_out() - output_before).map_err(|_| io::Error::other("output size overflow"))?;
            if status == Status::StreamEnd {
                if self.decoder.total_out() != self.expected || self.decoder.total_in() != self.input.len() as u64 {
                    return Err(io::Error::other("compressed stream extent or output size differs from its declaration"));
                }
                self.ended = true;
            } else if produced == 0 && self.decoder.total_in() == input_before {
                return Err(io::Error::other("compressed stream is truncated or cannot progress"));
            }
            // Consuming a header without producing bytes is not EOF. Continue until data or a real end.
            if produced == 0 && !self.ended {
                continue;
            }
            return Ok(produced);
        }
    }
}
