x509-util
=========

Simply a convenience crate to make generating an X509 Certificate simpler with
[x509-cert](https://docs.rs/x509-cert) until [these sort of
initiatives](https://github.com/RustCrypto/formats/issues/700) are complete.

This crate was created quite quickly with limited purpose in mind, it may or
may not be useful to you. Error handling is... coarse, at best.

## Why have you done this?

The [x509-cert](https://docs.rs/x509-cert) crate works great to parse X509
certificates in a quite performant manner, but due to the borrow-heavy nature
of the crate, generating new certificates can be burdensome.

This crate defines a few wrappers to make interfacing with the `x509-cert`
crate simpler as well as a CLI. To ease the ownership pain, the library leans
on [bumpalo](https://docs.rs/bumpalo) to provide simple arena-like allocation
for `x509-cert`'s underlying storage. The crate also has simple "happy-path"
entrypoints for the various types required to construct an X509 certificate.

## How do?

Check out the `examples` directory for how to use the library.

As for the CLI:

```
$ cargo install --path x509
$ x509 --help
```

## License

Copyright 2022 Luke Cycon.

This work is dual-licensed under Apache 2.0 and MIT.
You can choose between one of them if you use this work.

`SPDX-License-Identifier: MIT OR Apache-2.0`
