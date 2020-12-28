# rustls-pemfile
This is a very basic parser for PEM-encodings commonly used for storing keys and certificates at rest.

It doesn't support reading encrypted keys: the cryptography standardised for this is typically very
poor and doing so doesn't address a meaningful threat model.

[![Build Status](https://github.com/rustls/pemfile/workflows/rustls-pemfile/badge.svg)](https://github.com/rustls/pemfile/actions)
[![Crate](https://img.shields.io/crates/v/rustls-pemfile.svg)](https://crates.io/crates/rustls-pemfile)
[![Documentation](https://docs.rs/rustls-pemfile/badge.svg)](https://docs.rs/rustls-pemfile/)

# Release history
- 0.1.0 (2020-xx-xx)
  * Initial release.

# License
rustls-pemfile is distributed under the following three licenses:

- Apache License version 2.0.
- MIT license.
- ISC license.

These are included as LICENSE-APACHE, LICENSE-MIT and LICENSE-ISC
respectively.  You may use this software under the terms of any
of these licenses, at your option.

