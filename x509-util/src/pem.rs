use std::path::Path;

use spki::Document;
use x509_cert::Certificate;

use crate::error::Error;

pub trait PemOperations {
    const HEADER: &'static str;

    fn to_pem(&self) -> Result<String, Error>;
    fn write_pem_file(&self, path: impl AsRef<Path>) -> Result<(), Error>;
}

impl<'a> PemOperations for Certificate<'a> {
    const HEADER: &'static str = "CERTIFICATE";

    fn to_pem(&self) -> Result<String, Error> {
        Ok(Document::encode_msg(self)?.to_pem(Self::HEADER, pkcs8::LineEnding::CRLF)?)
    }

    fn write_pem_file(&self, path: impl AsRef<Path>) -> Result<(), Error> {
        Ok(Document::encode_msg(self)?.write_pem_file(
            path,
            Self::HEADER,
            pkcs8::LineEnding::CRLF,
        )?)
    }
}
