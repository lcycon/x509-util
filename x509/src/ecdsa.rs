use std::path::Path;

use color_eyre::{eyre::bail, Result};
use spki::{AlgorithmIdentifier, SubjectPublicKeyInfo};
use x509_util::{algorithm_identifier, prelude::Context, signer::Signer};

use crate::cli::{EcdsaCurve, SigningArgs};

mod signer;

#[cfg(feature = "p256")]
use self::signer::P256Signer;
#[cfg(feature = "p384")]
use self::signer::P384Signer;
use self::signer::{EcKey, SignerError};

struct EcSigner {
    curve: EcdsaCurve,
    inner: Box<dyn EcKey + Send + Sync>,
}

#[async_trait::async_trait]
impl Signer for EcSigner {
    type Err = SignerError;

    async fn sign<T: AsRef<[u8]> + Send>(&self, data: T) -> Result<Vec<u8>, Self::Err> {
        self.inner.sign(data.as_ref())
    }

    async fn signature_algorithm(&self) -> Result<AlgorithmIdentifier<'static>, Self::Err> {
        Ok(match self.curve {
            #[cfg(feature = "p256")]
            EcdsaCurve::P256 => algorithm_identifier::ECDSA_WITH_SHA256,
            #[cfg(feature = "p384")]
            EcdsaCurve::P384 => algorithm_identifier::ECDSA_WITH_SHA384,
        })
    }

    async fn subject_public_key_info<'a, 'b>(
        &'a self,
        context: &'b Context,
    ) -> Result<SubjectPublicKeyInfo<'b>, Self::Err> {
        let data = self.inner.pubkey_bytes()?;

        Ok(x509_util::subject_public_key_info::SubjectPublicKeyInfo::from_der(context, &data)?)
    }
}

fn read_key_to_signer(path: impl AsRef<Path>, curve: EcdsaCurve) -> Result<EcSigner, SignerError> {
    let result: Box<dyn EcKey + Send + Sync> = match curve {
        #[cfg(feature = "p256")]
        EcdsaCurve::P256 => Box::new(P256Signer::read_pkcs8_der_file(path)?),
        #[cfg(feature = "p384")]
        EcdsaCurve::P384 => Box::new(P384Signer::read_pkcs8_der_file(path)?),
    };

    Ok(EcSigner {
        curve,
        inner: result,
    })
}

fn new_signer(path: impl AsRef<Path>, curve: EcdsaCurve) -> Result<EcSigner, SignerError> {
    let result: Box<dyn EcKey + Send + Sync> = match curve {
        #[cfg(feature = "p256")]
        EcdsaCurve::P256 => Box::new(P256Signer::random()),
        #[cfg(feature = "p384")]
        EcdsaCurve::P384 => Box::new(P384Signer::random()),
    };

    result.write_pkcs8_der_file(path.as_ref())?;

    Ok(EcSigner {
        curve,
        inner: result,
    })
}

pub fn get_signer(curve: EcdsaCurve, args: &SigningArgs) -> Result<impl Signer> {
    if let Some(ref key_path) = args.key.key {
        Ok(read_key_to_signer(key_path, curve)?)
    } else if let Some(ref new_key_path) = args.key.new_key {
        Ok(new_signer(new_key_path, curve)?)
    } else {
        bail!("This should never happen, this is a bug")
    }
}
