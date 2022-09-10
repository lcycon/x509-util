use ecdsa::signature::Signer;
use pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey};
use rand_core::OsRng;
use std::path::Path;
use std::result::Result;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SignerError {
    #[error("SPKI error: {0}")]
    Spki(#[from] spki::Error),
    #[error("PKCS8 error: {0}")]
    Pkcs8(#[from] pkcs8::Error),
    #[error("FS error: {0}")]
    Fs(#[from] std::io::Error),
    #[error("x509-util error: {0}")]
    X509Util(#[from] x509_util::error::Error),
}

pub trait EcKey {
    fn write_pkcs8_der_file(&self, path: &Path) -> Result<(), SignerError>;

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, SignerError>;

    fn pubkey_bytes(&self) -> Result<Vec<u8>, SignerError>;
}

macro_rules! ec_impl {
    ($struct: ident, $crt: ident) => {
        pub struct $struct {
            key: $crt::ecdsa::SigningKey,
            pubkey: $crt::ecdsa::VerifyingKey,
        }

        impl $struct {
            pub fn random() -> Self {
                let key = $crt::ecdsa::SigningKey::random(&mut OsRng);
                let pubkey = key.verifying_key();

                Self { key, pubkey }
            }

            pub fn read_pkcs8_der_file(path: impl AsRef<Path>) -> Result<Self, SignerError> {
                let key = $crt::ecdsa::SigningKey::read_pkcs8_pem_file(path)?;
                let pubkey = key.verifying_key();

                Ok(Self { key, pubkey })
            }
        }

        impl EcKey for $struct {
            fn write_pkcs8_der_file(&self, path: &Path) -> Result<(), SignerError> {
                Ok(self.key.write_pkcs8_der_file(path)?)
            }
            fn sign(&self, data: &[u8]) -> Result<Vec<u8>, SignerError> {
                Ok(self.key.sign(data.as_ref()).to_der().as_bytes().to_vec())
            }
            fn pubkey_bytes(&self) -> Result<Vec<u8>, SignerError> {
                Ok(self.pubkey.to_public_key_der()?.as_bytes().to_vec())
            }
        }
    };
}

#[cfg(feature = "p256")]
ec_impl!(P256Signer, p256);
#[cfg(feature = "p384")]
ec_impl!(P384Signer, p384);
