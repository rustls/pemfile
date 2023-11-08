use std::io::{self, ErrorKind};
use std::iter;

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

/// Extract and decode the next PEM section from `rd`.
///
/// - Ok(None) is returned if there is no PEM section read from `rd`.
/// - Underlying IO errors produce a `Err(...)`
/// - Otherwise each decoded section is returned with a `Ok(Some(Item::...))`
///
/// You can use this function to build an iterator, for example:
/// `for item in iter::from_fn(|| read_one(rd).transpose()) { ... }`
pub fn read_one(rd: &mut dyn io::BufRead) -> Result<Option<Item>, io::Error> {
    let mut b64buf = Vec::with_capacity(1024);
    let mut section = None::<(Vec<_>, Vec<_>)>;
    let mut line = Vec::with_capacity(80);

    loop {
        line.clear();
        let len = read_until_newline(rd, &mut line)?;

        if len == 0 {
            // EOF
            return match section {
                Some((_, end_marker)) => Err(io::Error::new(
                    ErrorKind::InvalidData,
                    format!(
                        "section end {:?} missing",
                        String::from_utf8_lossy(&end_marker)
                    ),
                )),
                None => Ok(None),
            };
        }

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
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    format!(
                        "illegal section start: {:?}",
                        String::from_utf8_lossy(&line)
                    ),
                ));
            }

            let ty = &line[11..pos];
            let mut end = Vec::with_capacity(10 + 4 + ty.len());
            end.extend_from_slice(b"-----END ");
            end.extend_from_slice(ty);
            end.extend_from_slice(b"-----");
            section = Some((ty.to_owned(), end));
            continue;
        }

        if let Some((section_type, end_marker)) = section.as_ref() {
            if line.starts_with(end_marker) {
                let der = base64::ENGINE
                    .decode(&b64buf)
                    .map_err(|err| io::Error::new(ErrorKind::InvalidData, err))?;

                match section_type.as_slice() {
                    b"CERTIFICATE" => return Ok(Some(Item::X509Certificate(der.into()))),
                    b"RSA PRIVATE KEY" => return Ok(Some(Item::Pkcs1Key(der.into()))),
                    b"PRIVATE KEY" => return Ok(Some(Item::Pkcs8Key(der.into()))),
                    b"EC PRIVATE KEY" => return Ok(Some(Item::Sec1Key(der.into()))),
                    b"X509 CRL" => return Ok(Some(Item::Crl(der.into()))),
                    _ => {
                        section = None;
                        b64buf.clear();
                    }
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
    }
}

// Ported from https://github.com/rust-lang/rust/blob/91cfcb021935853caa06698b759c293c09d1e96a/library/std/src/io/mod.rs#L1990 and
// modified to look for our accepted newlines.
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
