use std::io::{self, ErrorKind};

use base64;

/// The contents of a single recognised block in a PEM file.
#[non_exhaustive]
#[derive(Debug, PartialEq)]
pub enum Item {
    /// A DER-encoded x509 certificate.
    X509Certificate(Vec<u8>),

    /// A DER-encoded plaintext RSA private key; as specified in PKCS#1/RFC3447
    RSAKey(Vec<u8>),

    /// A DER-encoded plaintext private key; as specified in PKCS#8/RFC5958
    PKCS8Key(Vec<u8>),

    /// A Sec1-encoded plaintext private key; as specified in RFC5915
    ECKey(Vec<u8>),
}

impl Item {
    fn from_start_line(start_line: &str, der: Vec<u8>) -> Option<Item> {
        match start_line {
            "CERTIFICATE" => Some(Item::X509Certificate(der)),
            "RSA PRIVATE KEY" => Some(Item::RSAKey(der)),
            "PRIVATE KEY" => Some(Item::PKCS8Key(der)),
            "EC PRIVATE KEY" => Some(Item::ECKey(der)),
            _ => None,
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
pub fn read_one(rd: &mut dyn io::BufRead) -> Result<Option<Item>, io::Error> {
    let mut b64buf = String::with_capacity(1024);
    let mut section = None;
    let mut line = String::with_capacity(80);

    loop {
        line.clear();
        let len = rd.read_line(&mut line)?;

        if len == 0 {
            // EOF
            return match section {
                Some((_, end_marker)) => Err(io::Error::new(
                    ErrorKind::InvalidData,
                    format!("section end {:?} missing", end_marker),
                )),
                None => Ok(None),
            };
        }

        if line.starts_with("-----BEGIN ") {
            let trailer = line[11..].find("-----").ok_or_else(|| {
                io::Error::new(
                    ErrorKind::InvalidData,
                    format!("illegal section start: {:?}", line),
                )
            })?;

            let ty = &line[11..11 + trailer];
            section = Some((ty.to_string(), format!("-----END {}-----", ty).to_string()));
            continue;
        }

        if let Some((section_type, end_marker)) = section.as_ref() {
            if line.starts_with(end_marker) {
                let der = base64::decode(&b64buf)
                    .map_err(|err| io::Error::new(ErrorKind::InvalidData, err))?;

                if let Some(item) = Item::from_start_line(&section_type, der) {
                    return Ok(Some(item));
                } else {
                    section = None;
                    b64buf.clear();
                }
            }
        }

        if section.is_some() {
            b64buf.push_str(line.trim());
        }
    }
}

/// Extract and return all PEM sections by reading `rd`.
pub fn read_all(rd: &mut dyn io::BufRead) -> Result<Vec<Item>, io::Error> {
    let mut v = Vec::<Item>::new();

    loop {
        match read_one(rd)? {
            None => return Ok(v),
            Some(item) => v.push(item),
        }
    }
}
