use std::path::Path;

use rsa::{
    pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey},
    rand_core::OsRng,
    RsaPrivateKey, RsaPublicKey,
};
use sha2::Digest;
use spki::{AlgorithmIdentifier, SubjectPublicKeyInfo};
use thiserror::Error;
use x509_util::{algorithm_identifier, prelude::Context, signer::Signer};

use crate::cli::{HashMode, RSASigningMode};

#[derive(Debug, Error)]
pub enum SignerError {
    #[error("SPKI error: {0}")]
    Spki(#[from] spki::Error),
    #[error("RSA error: {0}")]
    Rsa(rsa::errors::Error),
    #[error("RSA internal error. This is usually because you have selected an RSA key size too small for the hash mode.")]
    RsaInternal(rsa::errors::Error),
    #[error("x509-util error: {0}")]
    X509Util(#[from] x509_util::error::Error),
}

// Custom `From` implementation for the `rsa` crate's error so we can annotate
// a certain failure case with extra info
impl From<rsa::errors::Error> for SignerError {
    fn from(v: rsa::errors::Error) -> Self {
        match v {
            rsa::errors::Error::Internal => Self::RsaInternal(v),
            _ => Self::Rsa(v),
        }
    }
}

pub struct RsaSigner {
    mode: RSASigningMode,
    hash_mode: HashMode,
    key: RsaPrivateKey,
    pubkey: RsaPublicKey,
}

impl RsaSigner {
    pub fn random(
        mode: RSASigningMode,
        hash_mode: HashMode,
        bit_size: usize,
    ) -> rsa::errors::Result<Self> {
        let key = RsaPrivateKey::new(&mut OsRng, bit_size)?;
        let pubkey = key.to_public_key();

        Ok(RsaSigner {
            mode,
            hash_mode,
            key,
            pubkey,
        })
    }

    pub fn from_key(key: RsaPrivateKey, mode: RSASigningMode, hash_mode: HashMode) -> Self {
        let pubkey = key.to_public_key();

        RsaSigner {
            mode,
            hash_mode,
            key,
            pubkey,
        }
    }

    pub fn write_pkcs8_der_file(&self, path: impl AsRef<Path>) -> Result<(), rsa::pkcs8::Error> {
        self.key.write_pkcs8_der_file(path)
    }

    pub fn read_pkcs8_der_file(
        path: impl AsRef<Path>,
        mode: RSASigningMode,
        hash_mode: HashMode,
    ) -> Result<Self, rsa::pkcs8::Error> {
        let key = RsaPrivateKey::read_pkcs8_der_file(path)?;

        Ok(Self::from_key(key, mode, hash_mode))
    }

    fn digest_data(&self, data: impl AsRef<[u8]>) -> Vec<u8> {
        match self.hash_mode {
            HashMode::SHA256 => sha2::Sha256::digest(data).to_vec(),
            HashMode::SHA384 => sha2::Sha384::digest(data).to_vec(),
            HashMode::SHA512 => sha2::Sha512::digest(data).to_vec(),
        }
    }

    fn as_padding_scheme(&self) -> rsa::PaddingScheme {
        match (self.mode, self.hash_mode) {
            (RSASigningMode::Pkcs1v15, HashMode::SHA256) => {
                rsa::PaddingScheme::new_pkcs1v15_sign::<sha2::Sha256>()
            }
            (RSASigningMode::Pkcs1v15, HashMode::SHA384) => {
                rsa::PaddingScheme::new_pkcs1v15_sign::<sha2::Sha384>()
            }
            (RSASigningMode::Pkcs1v15, HashMode::SHA512) => {
                rsa::PaddingScheme::new_pkcs1v15_sign::<sha2::Sha512>()
            }
            (RSASigningMode::Pss, HashMode::SHA256) => {
                rsa::PaddingScheme::new_pss::<sha2::Sha256>()
            }
            (RSASigningMode::Pss, HashMode::SHA384) => {
                rsa::PaddingScheme::new_pss::<sha2::Sha384>()
            }
            (RSASigningMode::Pss, HashMode::SHA512) => {
                rsa::PaddingScheme::new_pss::<sha2::Sha512>()
            }
        }
    }
}

#[async_trait::async_trait]
impl Signer for RsaSigner {
    type Err = SignerError;

    async fn sign<T: AsRef<[u8]> + Send>(&self, data: T) -> Result<Vec<u8>, Self::Err> {
        let digest = self.digest_data(data);

        Ok(self.key.sign(self.as_padding_scheme(), &digest)?)
    }

    async fn signature_algorithm(&self) -> Result<AlgorithmIdentifier<'static>, Self::Err> {
        let result = match (self.mode, self.hash_mode) {
            (RSASigningMode::Pkcs1v15, HashMode::SHA256) => {
                algorithm_identifier::RSA_SSA_PKCS1_V15_SHA256
            }
            (RSASigningMode::Pkcs1v15, HashMode::SHA384) => {
                algorithm_identifier::RSA_SSA_PKCS1_V15_SHA384
            }
            (RSASigningMode::Pkcs1v15, HashMode::SHA512) => {
                algorithm_identifier::RSA_SSA_PKCS1_V15_SHA512
            }
            (RSASigningMode::Pss, HashMode::SHA256) => *algorithm_identifier::RSA_SSA_PSS_SHA256,
            (RSASigningMode::Pss, HashMode::SHA384) => *algorithm_identifier::RSA_SSA_PSS_SHA384,
            (RSASigningMode::Pss, HashMode::SHA512) => *algorithm_identifier::RSA_SSA_PSS_SHA512,
        };

        Ok(result)
    }

    async fn subject_public_key_info<'a, 'b>(
        &'a self,
        context: &'b Context,
    ) -> Result<SubjectPublicKeyInfo<'b>, Self::Err> {
        let spki_doc = self.pubkey.to_public_key_der()?;
        let bytes = spki_doc.as_ref();

        Ok(x509_util::subject_public_key_info::SubjectPublicKeyInfo::from_der(context, bytes)?)
    }
}
