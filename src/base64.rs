use alloc::vec::Vec;
use alloc::vec;

/// A codepoint in base64.
///
/// This is not an enum for compactness reasons -- it is desirable that
/// `sizeof([Code; 256])` is 256 bytes.
///
/// Ideally rust would support limited range integer types, then we could
/// write:
/// ```text
/// enum Code { Value(LimitedUint<0, 64>), Invalid, Skip, Pad }
/// ```
/// Which would be preferable and achieve an equivalant layout.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Code(u8);

/// Value should not appear in input.
const INVALID: Code = Code(128);

/// Value is allowed to appear in input, and is skipped over.
const SKIP: Code = Code(129);

/// Value means padding.
const PAD: Code = Code(130);

#[doc(hidden)]
pub trait Alphabet {
    fn decode_table(&self) -> &'static [Code; 256];
}

/// The standard base64 alphabet specified by [RFC4648].
///
/// Whitespace and non-alphabet characters are rejected.
///
/// [RFC4648]: https://datatracker.ietf.org/doc/html/rfc4648#section-4
pub struct Standard;

impl Alphabet for Standard {
    fn decode_table(&self) -> &'static [Code; 256] {
        &[
            // '\x00'..'\x0f'
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            // '\x10'..'\x1f'
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            // ' '..'/'
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            Code(62),
            INVALID,
            INVALID,
            INVALID,
            Code(63),
            // '0'..'?'
            Code(52),
            Code(53),
            Code(54),
            Code(55),
            Code(56),
            Code(57),
            Code(58),
            Code(59),
            Code(60),
            Code(61),
            INVALID,
            INVALID,
            INVALID,
            PAD,
            INVALID,
            INVALID,
            // '@'..'O'
            INVALID,
            Code(0),
            Code(1),
            Code(2),
            Code(3),
            Code(4),
            Code(5),
            Code(6),
            Code(7),
            Code(8),
            Code(9),
            Code(10),
            Code(11),
            Code(12),
            Code(13),
            Code(14),
            // 'P'..'_'
            Code(15),
            Code(16),
            Code(17),
            Code(18),
            Code(19),
            Code(20),
            Code(21),
            Code(22),
            Code(23),
            Code(24),
            Code(25),
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            // '`'..'o'
            INVALID,
            Code(26),
            Code(27),
            Code(28),
            Code(29),
            Code(30),
            Code(31),
            Code(32),
            Code(33),
            Code(34),
            Code(35),
            Code(36),
            Code(37),
            Code(38),
            Code(39),
            Code(40),
            // 'p'..'\x7f'
            Code(41),
            Code(42),
            Code(43),
            Code(44),
            Code(45),
            Code(46),
            Code(47),
            Code(48),
            Code(49),
            Code(50),
            Code(51),
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            // '\x80'..'\x8f'
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            // '\x90'..'\x9f'
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            // '\xa0'..'\xaf'
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            // '\xb0'..'\xbf'
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            // '\xc0'..'\xcf'
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            // '\xd0'..'\xdf'
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            // '\xe0'..'\xef'
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            // '\xf0'..'\xff'
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
        ]
    }
}

/// The PEM base64 alphabet specified by [RFC7468].
///
/// Whitespace is allowed and ignored.
///
/// [RFC7468]: https://datatracker.ietf.org/doc/html/rfc7468#section-3
pub struct Pem;

impl Alphabet for Pem {
    fn decode_table(&self) -> &'static [Code; 256] {
        &[
            // '\x00'..'\x0f'
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            SKIP,
            SKIP,
            SKIP,
            SKIP,
            SKIP,
            INVALID,
            INVALID,
            // '\x10'..'\x1f'
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            // ' '..'/'
            SKIP,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            Code(62),
            INVALID,
            INVALID,
            INVALID,
            Code(63),
            // '0'..'?'
            Code(52),
            Code(53),
            Code(54),
            Code(55),
            Code(56),
            Code(57),
            Code(58),
            Code(59),
            Code(60),
            Code(61),
            INVALID,
            INVALID,
            INVALID,
            PAD,
            INVALID,
            INVALID,
            // '@'..'O'
            INVALID,
            Code(0),
            Code(1),
            Code(2),
            Code(3),
            Code(4),
            Code(5),
            Code(6),
            Code(7),
            Code(8),
            Code(9),
            Code(10),
            Code(11),
            Code(12),
            Code(13),
            Code(14),
            // 'P'..'_'
            Code(15),
            Code(16),
            Code(17),
            Code(18),
            Code(19),
            Code(20),
            Code(21),
            Code(22),
            Code(23),
            Code(24),
            Code(25),
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            // '`'..'o'
            INVALID,
            Code(26),
            Code(27),
            Code(28),
            Code(29),
            Code(30),
            Code(31),
            Code(32),
            Code(33),
            Code(34),
            Code(35),
            Code(36),
            Code(37),
            Code(38),
            Code(39),
            Code(40),
            // 'p'..'\x7f'
            Code(41),
            Code(42),
            Code(43),
            Code(44),
            Code(45),
            Code(46),
            Code(47),
            Code(48),
            Code(49),
            Code(50),
            Code(51),
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            // '\x80'..'\x8f'
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            // '\x90'..'\x9f'
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            // '\xa0'..'\xaf'
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            // '\xb0'..'\xbf'
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            // '\xc0'..'\xcf'
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            // '\xd0'..'\xdf'
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            // '\xe0'..'\xef'
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            // '\xf0'..'\xff'
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
            INVALID,
        ]
    }
}

/// Incremental decoder.
pub struct Decoder {
    table: &'static [Code; 256],
    quad: Quad,
    state: State,
}

impl Decoder {
    /// Make a new incremental decoder with the given [`Alphabet`].
    pub fn new(alphabet: impl Alphabet) -> Self {
        Self {
            table: alphabet.decode_table(),
            quad: Quad::new(),
            state: State::Data,
        }
    }

    /// Process base64-encoded input bytes and obtained decoded output bytes.
    ///
    /// This should be called with every chunk of input except the last;
    /// the last should be supplied to `finish()`.
    ///
    /// `input` should contain the input data, it can be any size.
    ///
    /// `output` should have space to write the output data.  [`decode_len_estimate`]
    /// can be used to calculate an upper bound for how much space is needed for a
    /// given input length.
    ///
    /// It fails with `Error::OutputDoesNotFit` if `output` is too short.
    ///
    /// It fails with `Error::InvalidInput` if `input` contains an invalid byte
    /// according to the given `alphabet`.
    ///
    /// It succeeds with the number of bytes written to the start of `output`.
    pub fn update(&mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Error> {
        self.process(input, output, false)
    }

    /// Process base64-encoded input bytes and obtained decoded output bytes.
    ///
    /// This has the same semantics as `update()`.  It should be called last
    /// on any given `Decoder`.  It may be called with empty input.
    pub fn finish(mut self, input: &[u8], output: &mut [u8]) -> Result<usize, Error> {
        self.process(input, output, true)
    }

    fn process(&mut self, input: &[u8], output: &mut [u8], last: bool) -> Result<usize, Error> {
        let mut offs = 0;
        for (i, inp) in input.iter().enumerate() {
            match (self.state, self.table[*inp as usize]) {
                (_, SKIP) => continue,
                (State::Data, PAD) => {
                    self.state = State::Pad1;
                }
                (State::Pad1, PAD) => {
                    self.state = State::Pad2;
                }
                (State::Data, Code(v)) => self.quad.add(v),
                (_, INVALID) | (State::Pad1, _) | (State::Pad2, _) => {
                    return Err(Error::InvalidInput { at_offset: i })
                }
            }

            if self.quad.complete() {
                offs += self.quad.emit(&mut output[offs..])?;
            }
        }

        if last {
            let pad = match self.state {
                State::Data => 0,
                State::Pad1 => 1,
                State::Pad2 => 2,
            };
            offs += self
                .quad
                .emit_final(pad, &mut output[offs..])?;
        }

        Ok(offs)
    }
}

/// Estimate how many output bytes are required for an input of `input_len`.
///
/// The actual output length may be less than this, but will not be more.
pub const fn decode_len_estimate(input_len: usize) -> usize {
    ((input_len + 3) / 4) * 3
}

/// A one-shot base64 decode that writes to an output slice.
///
/// This returns the number of bytes written to the beginning of the slice.
///
/// It fails with `Error::OutputDoesNotFit` if `output` is too short.
///
/// It fails with `Error::InvalidInput` if `input` contains an invalid byte
/// according to the given `alphabet`.
pub fn decode(alphabet: impl Alphabet, input: &[u8], output: &mut [u8]) -> Result<usize, Error> {
    Decoder::new(alphabet).finish(input, output)
}

/// A one-shot base64 decode that returns a Vec
///
/// It does not fail with `Error::OutputDoesNotFit`.
///
/// It fails with `Error::InvalidInput` if `input` contains an invalid byte
/// according to the given `alphabet`.
pub fn decode_into_vec(alphabet: impl Alphabet, input: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = vec![0u8; decode_len_estimate(input.len())];
    let len = decode(alphabet, input, &mut out[..])?;
    out.truncate(len);
    Ok(out)
}

/// How this module reports errors.
#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// The output slice is too short.
    OutputDoesNotFit,

    /// The input contains and invalid byte according to the alphabet in use.
    InvalidInput {
        /// Offset where the invalid byte occured in the current input.
        ///
        /// `at_offset` relates to the current input (not the whole input).  This
        /// detail only matters in incremental mode (using a [`Decoder`] directly.)
        at_offset: usize
    },
}

#[derive(Debug, Copy, Clone)]
enum State {
    Data,
    Pad1,
    Pad2,
}

#[derive(Debug)]
struct Quad {
    codes: [u8; 4],
    used: usize,
}

impl Quad {
    fn new() -> Self {
        Self {
            codes: [0u8; 4],
            used: 0,
        }
    }

    fn add(&mut self, v: u8) {
        self.codes[self.used] = v;
        self.used += 1;
    }

    #[inline]
    fn complete(&self) -> bool {
        self.used == 4
    }

    #[inline]
    fn convert(&mut self) -> Triple {
        debug_assert!(self.used == 4);
        let a = self.codes[0];
        let b = self.codes[1];
        let c = self.codes[2];
        let d = self.codes[3];
        self.used = 0;
        Triple(
            [
                a << 2 | b >> 4,
                ((b & 0xf) << 4) | (c >> 2),
                (c & 0x3) << 6 | d,
            ],
            3,
        )
    }

    #[inline]
    fn emit_pad(&mut self, out: &mut [u8], pad: usize) -> Result<usize, Error> {
        let len = 3 - pad;
        let t = self.convert();

        match out.get_mut(..len) {
            Some(chunk) => {
                chunk.copy_from_slice(&t.as_ref()[..len]);
                Ok(len)
            }
            None => Err(Error::OutputDoesNotFit),
        }
    }

    #[inline]
    fn emit(&mut self, out: &mut [u8]) -> Result<usize, Error> {
        self.emit_pad(out, 0)
    }

    #[inline]
    fn emit_final(&mut self, pad: usize, out: &mut [u8]) -> Result<usize, Error> {
        for _ in 0..pad {
            self.add(0);
        }

        match (self.used, pad) {
            // valid explicit padding
            (4, 2) | (4, 1) | (4, 0) => self.emit_pad(out, pad),

            // one padding implied by length
            (3, 0) => {
                self.add(0);
                self.emit_pad(out, 1)
            }

            // two padding implied by length
            (2, 0) => {
                self.add(0);
                self.add(0);
                self.emit_pad(out, 2)
            }

            // no data, nothing to emit
            (0, _) => Ok(0),

            (_, _) => Err(Error::InvalidInput { at_offset: 0 }),
        }
    }
}

struct Triple([u8; 3], usize);

impl AsRef<[u8]> for Triple {
    fn as_ref(&self) -> &[u8] {
        &self.0[..self.1]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{print, vec};

    #[test]
    fn basic_decode() {
        assert_eq!(
            &b"hello world\n"[..],
            &decode_into_vec(Standard, b"aGVsbG8gd29ybGQK").unwrap()
        );
        assert_eq!(
            &b"hell"[..],
            &decode_into_vec(Standard, b"aGVsbA==").unwrap()
        );
        assert_eq!(
            &b"hello"[..],
            &decode_into_vec(Standard, b"aGVsbG8=").unwrap()
        );
    }

    #[test]
    fn padding_in_middle() {
        let mut out = [0u8; 32];
        assert_eq!(
            decode(Standard, b"a=VsbA==", &mut out),
            Err(Error::InvalidInput { at_offset: 2 })
        );
    }

    #[test]
    fn unpadded() {
        assert_eq!(decode_into_vec(Standard, b"").unwrap(), vec![]);
        assert_eq!(
            decode_into_vec(Standard, b"a"),
            Err(Error::InvalidInput { at_offset: 0 })
        );
        assert_eq!(decode_into_vec(Standard, b"aa").unwrap(), vec![0x69]);
        assert_eq!(decode_into_vec(Standard, b"aaa").unwrap(), vec![0x69, 0xa6]);
        assert_eq!(
            decode_into_vec(Standard, b"aaaa").unwrap(),
            vec![0x69, 0xa6, 0x9a]
        );
    }

    #[test]
    fn in_place() {
        let mut buf = [0u8; 8];
        assert_eq!(Ok(0), decode(Standard, b"", &mut buf[..0]));
        assert_eq!(Ok(1), decode(Standard, b"AA", &mut buf[..1]));
        assert_eq!(&buf[..1], &[0]);
        assert_eq!(Ok(2), decode(Standard, b"AAA", &mut buf[..2]));
        assert_eq!(&buf[..2], &[0, 0]);
        assert_eq!(Ok(3), decode(Standard, b"AAAA", &mut buf[..3]));
        assert_eq!(&buf[..3], &[0, 0, 0]);
        assert_eq!(Ok(8), decode(Standard, b"AAAAAAAAAAA", &mut buf[..]));
        assert_eq!(&buf[..], &[0; 8]);

        assert_eq!(
            Err(Error::OutputDoesNotFit),
            decode(Standard, b"AA", &mut buf[..0])
        );
        assert_eq!(
            Err(Error::OutputDoesNotFit),
            decode(Standard, b"AAAAAAA", &mut buf[..4])
        );
    }

    #[test]
    fn pem() {
        assert_eq!(
            decode_into_vec(Pem, b"\x0b\x0cAAAA\n\tAAAA\n AA==\r\n").unwrap(),
            vec![0u8; 7]
        );
    }

    #[test]
    fn incremental() {
        let input = b"CkxpZmUncyBidXQgYSB3YWxraW5nIHNoYWRvdywgYSBwb29yIHBsYXllcgpUaGF0IHN0cnV0cyBhbmQgZnJldHMgaGlzIGhvdXIgdXBvbiB0aGUgc3RhZ2UKQW5kIHRoZW4gaXMgaGVhcmQgbm8gbW9yZTogaXQgaXMgYSB0YWxlClRvbGQgYnkgYW4gaWRpb3QsIGZ1bGwgb2Ygc291bmQgYW5kIGZ1cnksClNpZ25pZnlpbmcgbm90aGluZy4=";

        let mut decoder = Decoder::new(Standard);
        for b in input.iter() {
            let mut output = [0u8; 4];
            let len = decoder
                .update(&[*b], &mut output)
                .unwrap();

            print!("{}", std::str::from_utf8(&output[..len]).unwrap());
        }

        let mut output = [0u8; 4];
        let len = decoder
            .finish(b"", &mut output)
            .unwrap();
        print!("{}", std::str::from_utf8(&output[..len]).unwrap());
    }
}
