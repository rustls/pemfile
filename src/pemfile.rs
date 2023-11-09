use alloc::borrow::ToOwned;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
#[cfg(feature = "std")]
use core::iter;
use core::ops::ControlFlow;
#[cfg(feature = "std")]
use std::io::{self, ErrorKind};

use pki_types::{
    CertificateDer, CertificateRevocationListDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer,
    PrivateSec1KeyDer,
};

/// The contents of a single recognised block in a PEM file.
#[non_exhaustive]
#[derive(Debug, PartialEq)]
pub enum Item {
    /// A DER-encoded x509 certificate.
    ///
    /// Appears as "CERTIFICATE" in PEM files.
    X509Certificate(CertificateDer<'static>),

    /// A DER-encoded plaintext RSA private key; as specified in PKCS #1/RFC 3447
    ///
    /// Appears as "RSA PRIVATE KEY" in PEM files.
    Pkcs1Key(PrivatePkcs1KeyDer<'static>),

    /// A DER-encoded plaintext private key; as specified in PKCS #8/RFC 5958
    ///
    /// Appears as "PRIVATE KEY" in PEM files.
    Pkcs8Key(PrivatePkcs8KeyDer<'static>),

    /// A Sec1-encoded plaintext private key; as specified in RFC 5915
    ///
    /// Appears as "EC PRIVATE KEY" in PEM files.
    Sec1Key(PrivateSec1KeyDer<'static>),

    /// A Certificate Revocation List; as specified in RFC 5280
    ///
    /// Appears as "X509 CRL" in PEM files.
    Crl(CertificateRevocationListDer<'static>),
}

/// Errors that may arise when parsing the contents of a PEM file
#[derive(Debug, PartialEq)]
pub enum Error {
    /// a section is missing its "END marker" line
    MissingSectionEnd {
        /// the expected "END marker" line that was not found
        end_marker: Vec<u8>,
    },

    /// syntax error found in the line that starts a new section
    IllegalSectionStart {
        /// line that contains the syntax error
        line: Vec<u8>,
    },

    /// base64 decode error
    Base64Decode(String),
}

/// Extract and decode the next PEM section from `input`
///
/// - `Ok(None)` is returned if there is no PEM section to read from `input`
/// - Syntax errors and decoding errors produce a `Err(...)`
/// - Otherwise each decoded section is returned with a `Ok(Some((Item::..., remainder)))` where
///   `remainder` is the part of the `input` that follows the returned section
pub fn read_one_from_slice(mut input: &[u8]) -> Result<Option<(Item, &[u8])>, Error> {
    let mut b64buf = Vec::with_capacity(1024);
    let mut section = None::<(Vec<_>, Vec<_>)>;

    loop {
        let next_line = if let Some(index) = input.iter().position(|byte| *byte == b'\n') {
            let (line, newline_plus_remainder) = input.split_at(index);
            input = &newline_plus_remainder[1..];
            Some(line)
        } else {
            None
        };

        match read_one_impl(next_line, &mut section, &mut b64buf)? {
            ControlFlow::Continue(()) => continue,
            ControlFlow::Break(item) => return Ok(item.map(|item| (item, input))),
        }
    }
}

/// Extract and decode the next PEM section from `rd`.
///
/// - Ok(None) is returned if there is no PEM section read from `rd`.
/// - Underlying IO errors produce a `Err(...)`
/// - Otherwise each decoded section is returned with a `Ok(Some(Item::...))`
///
/// You can use this function to build an iterator, for example:
/// `for item in iter::from_fn(|| read_one(rd).transpose()) { ... }`
#[cfg(feature = "std")]
pub fn read_one(rd: &mut dyn io::BufRead) -> Result<Option<Item>, io::Error> {
    let mut b64buf = Vec::with_capacity(1024);
    let mut section = None::<(Vec<_>, Vec<_>)>;
    let mut line = Vec::with_capacity(80);

    loop {
        line.clear();
        let len = read_until_newline(rd, &mut line)?;

        let next_line = if len == 0 {
            None
        } else {
            Some(line.as_slice())
        };

        match read_one_impl(next_line, &mut section, &mut b64buf) {
            Ok(ControlFlow::Break(opt)) => return Ok(opt),
            Ok(ControlFlow::Continue(())) => continue,
            Err(e) => {
                return Err(match e {
                    Error::MissingSectionEnd { end_marker } => io::Error::new(
                        ErrorKind::InvalidData,
                        format!(
                            "section end {:?} missing",
                            String::from_utf8_lossy(&end_marker)
                        ),
                    ),

                    Error::IllegalSectionStart { line } => io::Error::new(
                        ErrorKind::InvalidData,
                        format!(
                            "illegal section start: {:?}",
                            String::from_utf8_lossy(&line)
                        ),
                    ),

                    Error::Base64Decode(err) => io::Error::new(ErrorKind::InvalidData, err),
                });
            }
        }
    }
}

fn read_one_impl(
    next_line: Option<&[u8]>,
    section: &mut Option<(Vec<u8>, Vec<u8>)>,
    b64buf: &mut Vec<u8>,
) -> Result<ControlFlow<Option<Item>, ()>, Error> {
    let line = if let Some(line) = next_line {
        line
    } else {
        // EOF
        return match section.take() {
            Some((_, end_marker)) => Err(Error::MissingSectionEnd { end_marker }),
            None => Ok(ControlFlow::Break(None)),
        };
    };

    if line.starts_with(b"-----BEGIN ") {
        let (mut trailer, mut pos) = (0, line.len());
        for (i, &b) in line.iter().enumerate().rev() {
            match b {
                b'-' => {
                    trailer += 1;
                    pos = i;
                }
                b'\n' | b'\r' | b' ' => continue,
                _ => break,
            }
        }

        if trailer != 5 {
            return Err(Error::IllegalSectionStart {
                line: line.to_vec(),
            });
        }

        let ty = &line[11..pos];
        let mut end = Vec::with_capacity(10 + 4 + ty.len());
        end.extend_from_slice(b"-----END ");
        end.extend_from_slice(ty);
        end.extend_from_slice(b"-----");
        *section = Some((ty.to_owned(), end));
        return Ok(ControlFlow::Continue(()));
    }

    if let Some((section_type, end_marker)) = section.as_ref() {
        if line.starts_with(end_marker) {
            let der = base64::ENGINE
                .decode(&b64buf)
                .map_err(|err| Error::Base64Decode(format!("{err:?}")))?;

            let item = match section_type.as_slice() {
                b"CERTIFICATE" => Some(Item::X509Certificate(der.into())),
                b"RSA PRIVATE KEY" => Some(Item::Pkcs1Key(der.into())),
                b"PRIVATE KEY" => Some(Item::Pkcs8Key(der.into())),
                b"EC PRIVATE KEY" => Some(Item::Sec1Key(der.into())),
                b"X509 CRL" => Some(Item::Crl(der.into())),
                _ => {
                    *section = None;
                    b64buf.clear();
                    None
                }
            };

            if item.is_some() {
                return Ok(ControlFlow::Break(item));
            }
        }
    }

    if section.is_some() {
        let mut trim = 0;
        for &b in line.iter().rev() {
            match b {
                b'\n' | b'\r' | b' ' => trim += 1,
                _ => break,
            }
        }
        b64buf.extend(&line[..line.len() - trim]);
    }

    Ok(ControlFlow::Continue(()))
}

// Ported from https://github.com/rust-lang/rust/blob/91cfcb021935853caa06698b759c293c09d1e96a/library/std/src/io/mod.rs#L1990 and
// modified to look for our accepted newlines.
#[cfg(feature = "std")]
fn read_until_newline<R: io::BufRead + ?Sized>(
    r: &mut R,
    buf: &mut Vec<u8>,
) -> std::io::Result<usize> {
    let mut read = 0;
    loop {
        let (done, used) = {
            let available = match r.fill_buf() {
                Ok(n) => n,
                Err(ref e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            };
            match available
                .iter()
                .copied()
                .position(|b| b == b'\n' || b == b'\r')
            {
                Some(i) => {
                    buf.extend_from_slice(&available[..=i]);
                    (true, i + 1)
                }
                None => {
                    buf.extend_from_slice(available);
                    (false, available.len())
                }
            }
        };
        r.consume(used);
        read += used;
        if done || used == 0 {
            return Ok(read);
        }
    }
}

/// Extract and return all PEM sections by reading `rd`.
#[cfg(feature = "std")]
pub fn read_all(rd: &mut dyn io::BufRead) -> impl Iterator<Item = Result<Item, io::Error>> + '_ {
    iter::from_fn(move || read_one(rd).transpose())
}

mod base64 {
    use base64::alphabet::STANDARD;
    use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig};
    use base64::engine::DecodePaddingMode;
    pub(super) use base64::engine::Engine;

    pub(super) const ENGINE: GeneralPurpose = GeneralPurpose::new(
        &STANDARD,
        GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
    );
}
use self::base64::Engine;
