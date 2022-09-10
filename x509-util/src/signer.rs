use std::error::Error as StdError;

use async_trait::async_trait;

use der::{asn1::BitStringRef, Encode};
use spki::{AlgorithmIdentifier, SubjectPublicKeyInfo};
use x509_cert::{Certificate, TbsCertificate};

use crate::{
    context::{Alloc, Context},
    error::Error,
};

#[async_trait]
pub trait Signer {
    type Err: StdError + Send + Sync + 'static;

    /// For ECDSA signatures, this function must return a DER encoded signature,
    /// according to [RFC3279 Section 2.2.3](https://www.rfc-editor.org/rfc/rfc3279#section-2.2.3)
    async fn sign<T: AsRef<[u8]> + Send>(&self, data: T) -> Result<Vec<u8>, Self::Err>;

    async fn signature_algorithm(&self) -> Result<AlgorithmIdentifier<'static>, Self::Err>;
    async fn subject_public_key_info<'a, 'b>(
        &'a self,
        context: &'b Context,
    ) -> Result<SubjectPublicKeyInfo<'b>, Self::Err>;
}

#[async_trait]
pub trait Signable<'a> {
    type Output;
    type Err: From<der::Error>;

    async fn sign<'b, S: Signer + Sync + Send>(
        &'b self,
        context: &'a Context,
        signer: &S,
    ) -> Result<Self::Output, Self::Err>;
}

#[async_trait]
impl<'a> Signable<'a> for TbsCertificate<'a> {
    type Output = Certificate<'a>;
    type Err = crate::error::Error;

    async fn sign<'b, S: Signer + Sync + Send>(
        &'b self,
        context: &'a Context,
        signer: &S,
    ) -> Result<Self::Output, Self::Err> {
        let bytes = self.to_vec()?;

        let to_err = |e: <S as Signer>::Err| {
            Error::ErrorSigning(Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
        };

        let sig = signer
            .sign(bytes)
            .await
            .map_err(to_err)?
            .alloc_into(context);
        let signature = BitStringRef::from_bytes(sig)?;

        let signature_algorithm = signer.signature_algorithm().await.map_err(to_err)?;

        let cert = Certificate {
            tbs_certificate: self.clone(),
            signature_algorithm,
            signature,
        };

        Ok(cert)
    }
}
