//! # rustls-pemfile
//! A basic parser for .pem files containing cryptographic keys and certificates.
//!
//! The input to this crate is a .pem file containing potentially many sections,
//! and the output is those sections as alleged DER-encodings.  This crate does
//! not decode the actual DER-encoded keys/certificates.
//!
//! ## Quick start
//! Starting with an `io::BufRead` containing the file to be read:
//! - Use `read_all()` to ingest the whole file, then work through the contents in-memory, or,
//! - Use `read_one()` to stream through the file, processing the items as found, or,
//! - Use `certs()` to extract just the certificates (silently discarding other sections), and
//!   similarly for `rsa_private_keys()` and `pkcs8_private_keys()`.
//!
//! ## Example code
//! ```
//! use std::iter;
//! use rustls_pemfile::{Item, read_one};
//! # let mut reader = std::io::BufReader::new(&b"junk\n-----BEGIN RSA PRIVATE KEY-----\nqw\n-----END RSA PRIVATE KEY-----\n"[..]);
//! // Assume `reader` is any std::io::BufRead implementor
//! for item in iter::from_fn(|| read_one(&mut reader).transpose()) {
//!     match item.unwrap() {
//!         Item::X509Certificate(cert) => println!("certificate {:?}", cert),
//!         Item::Crl(crl) => println!("certificate revocation list: {:?}", crl),
//!         Item::Pkcs1Key(key) => println!("rsa pkcs1 key {:?}", key),
//!         Item::Pkcs8Key(key) => println!("pkcs8 key {:?}", key),
//!         Item::Sec1Key(key) => println!("sec1 ec key {:?}", key),
//!         _ => println!("unhandled item"),
//!     }
//! }
//! ```

// Require docs for public APIs, deny unsafe code, etc.
#![forbid(unsafe_code, unused_must_use, unstable_features)]
#![deny(
    trivial_casts,
    trivial_numeric_casts,
    missing_docs,
    unused_import_braces,
    unused_extern_crates,
    unused_qualifications
)]

#[cfg(test)]
mod tests;

/// --- Main crate APIs:
mod pemfile;
pub use pemfile::{read_all, read_one, Item};
use pki_types::{
    CertificateDer, CertificateRevocationListDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer,
    PrivateSec1KeyDer,
};

/// --- Legacy APIs:
use std::io;
use std::iter;

/// Return an iterator over certificates from `rd`.
///
/// Filters out any PEM sections that are not certificates and yields errors if a problem
/// occurs while trying to extract a certificate.
pub fn certs(
    rd: &mut dyn io::BufRead,
) -> impl Iterator<Item = Result<CertificateDer<'static>, io::Error>> + '_ {
    iter::from_fn(move || read_one(rd).transpose()).filter_map(|item| match item {
        Ok(Item::X509Certificate(cert)) => Some(Ok(cert)),
        Err(err) => Some(Err(err)),
        _ => None,
    })
}

/// Return an iterator certificate revocation lists (CRLs) from `rd`.
///
/// Filters out any PEM sections that are not CRLs and yields errors if a problem occurs
/// while trying to extract a CRL.
pub fn crls(
    rd: &mut dyn io::BufRead,
) -> impl Iterator<Item = Result<CertificateRevocationListDer<'static>, io::Error>> + '_ {
    iter::from_fn(move || read_one(rd).transpose()).filter_map(|item| match item {
        Ok(Item::Crl(crl)) => Some(Ok(crl)),
        Err(err) => Some(Err(err)),
        _ => None,
    })
}

/// Return an iterator over RSA private keys from `rd`.
///
/// Filters out any PEM sections that are not RSA private keys and yields errors if a problem
/// occurs while trying to extract an RSA private key.
pub fn rsa_private_keys(
    rd: &mut dyn io::BufRead,
) -> impl Iterator<Item = Result<PrivatePkcs1KeyDer<'static>, io::Error>> + '_ {
    iter::from_fn(move || read_one(rd).transpose()).filter_map(|item| match item {
        Ok(Item::Pkcs1Key(key)) => Some(Ok(key)),
        Err(err) => Some(Err(err)),
        _ => None,
    })
}

/// Return an iterator over PKCS8-encoded private keys from `rd`.
///
/// Filters out any PEM sections that are not PKCS8-encoded private keys and yields errors if a
/// problem occurs while trying to extract an RSA private key.
pub fn pkcs8_private_keys(
    rd: &mut dyn io::BufRead,
) -> impl Iterator<Item = Result<PrivatePkcs8KeyDer<'static>, io::Error>> + '_ {
    iter::from_fn(move || read_one(rd).transpose()).filter_map(|item| match item {
        Ok(Item::Pkcs8Key(key)) => Some(Ok(key)),
        Err(err) => Some(Err(err)),
        _ => None,
    })
}

/// Return an iterator over SEC1-encoded EC private keys from `rd`.
///
/// Filters out any PEM sections that are not SEC1-encoded EC private keys and yields errors if a
/// problem occurs while trying to extract a SEC1-encoded EC private key.
pub fn ec_private_keys(
    rd: &mut dyn io::BufRead,
) -> impl Iterator<Item = Result<PrivateSec1KeyDer<'static>, io::Error>> + '_ {
    iter::from_fn(move || read_one(rd).transpose()).filter_map(|item| match item {
        Ok(Item::Sec1Key(key)) => Some(Ok(key)),
        Err(err) => Some(Err(err)),
        _ => None,
    })
}
