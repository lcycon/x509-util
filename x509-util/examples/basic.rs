use async_trait::async_trait;
use chrono::{Datelike, TimeZone};
use p384::ecdsa::{signature::Signer as P384Signer, SigningKey, VerifyingKey};
use pkcs8::EncodePublicKey;
use rsa::{rand_core::OsRng, RsaPrivateKey};
use sha2::Sha512;
use spki::{self, AlgorithmIdentifier};
use tokio::main;
use x509_cert::{ext::pkix::KeyUsages, Certificate, TbsCertificate};

use x509_util::prelude::*;

struct KeyPair {
    key: SigningKey,
    public_key: VerifyingKey,
}

impl KeyPair {
    pub fn random() -> Self {
        let private = SigningKey::random(&mut OsRng);
        let public = private.verifying_key();

        KeyPair {
            key: private,
            public_key: public,
        }
    }
}

#[async_trait]
impl Signer for KeyPair {
    type Err = std::io::Error;

    async fn sign<T: AsRef<[u8]> + Send>(&self, data: T) -> Result<Vec<u8>, Self::Err> {
        Ok(self.key.sign(data.as_ref()).to_der().as_bytes().to_vec())
    }

    async fn signature_algorithm(&self) -> Result<AlgorithmIdentifier<'static>, Self::Err> {
        Ok(x509_util::algorithm_identifier::ECDSA_WITH_SHA384)
    }

    async fn subject_public_key_info<'a, 'b>(
        &'a self,
        context: &'b Context,
    ) -> Result<spki::SubjectPublicKeyInfo<'b>, Self::Err> {
        let bytes = self.public_key.to_public_key_der().unwrap().to_vec();

        Ok(SubjectPublicKeyInfo::from_der(context, &bytes).unwrap())
    }
}

struct RsaKeyPair {
    key: rsa::pkcs1v15::SigningKey<Sha512>,
    public_key: rsa::pkcs1v15::VerifyingKey<Sha512>,
}

impl RsaKeyPair {
    pub fn random() -> Self {
        let private: rsa::pkcs1v15::SigningKey<Sha512> =
            RsaPrivateKey::new(&mut OsRng, 2048).unwrap().into();
        let public = (&private).into();

        RsaKeyPair {
            key: private,
            public_key: public,
        }
    }
}

#[async_trait]
impl Signer for RsaKeyPair {
    type Err = std::io::Error;

    async fn sign<T: AsRef<[u8]> + Send>(&self, data: T) -> Result<Vec<u8>, Self::Err> {
        Ok(self.key.sign(data.as_ref()).to_vec())
    }

    async fn signature_algorithm(&self) -> Result<AlgorithmIdentifier<'static>, Self::Err> {
        Ok(x509_util::algorithm_identifier::RSA_SSA_PKCS1_V15_SHA512)
    }

    async fn subject_public_key_info<'a, 'b>(
        &'a self,
        context: &'b Context,
    ) -> Result<spki::SubjectPublicKeyInfo<'b>, Self::Err> {
        let pubkey_doc = self.public_key.to_public_key_der().unwrap();
        let bytes = pubkey_doc.as_ref();

        Ok(SubjectPublicKeyInfo::from_der(context, bytes).unwrap())
    }
}

#[main]
async fn main() {
    // A `Context` stores memory allocations that can be later referenced via `x509-cert` types.
    // Internally, it uses `bumpalo` to arena allocate byte slices.
    let context = Context::new();

    let (ca_keypair, ca_cert) = ca(&context).await;

    let (_, _) = leaf(&context, &ca_keypair, ca_cert).await;
}

async fn ca(context: &Context) -> (KeyPair, Certificate) {
    let key_pair: KeyPair = KeyPair::random();

    let now = chrono::Utc::now();
    let not_before = chrono::Utc
        .with_ymd_and_hms(now.year(), 1, 1, 0, 0, 0)
        .unwrap();
    let not_after = not_before.clone().with_year(now.year() + 10).unwrap();
    let validity: Validity = (not_before..not_after).into();

    let name = Name::from_pairs(context, &[("C", "US"), ("ST", "CA"), ("CN", "ca")]).unwrap();

    let subject_pubkey_info = key_pair.subject_public_key_info(context).await.unwrap();

    let extensions = vec![
        Extensions::basic_constraints(context, true, true, Some(1)).unwrap(),
        Extensions::key_usage(context, true, &[KeyUsages::KeyCertSign]).unwrap(),
        Extensions::authority_key_identifier(context, false, subject_pubkey_info).unwrap(),
        Extensions::subject_key_identifier(context, false, subject_pubkey_info).unwrap(),
    ];

    let tbs_cert = TbsCertificate {
        version: x509_cert::Version::V3,
        serial_number: x509_util::random_serial(context).unwrap(),
        signature: x509_util::algorithm_identifier::ECDSA_WITH_SHA384,
        issuer: name.clone(),
        validity: (&validity).try_into().unwrap(),
        subject: name,

        subject_public_key_info: subject_pubkey_info,

        issuer_unique_id: None,
        subject_unique_id: None,

        extensions: Some(extensions),
    };

    let cert = tbs_cert.sign(context, &key_pair).await.unwrap();

    cert.write_pem_file("ca.pem").unwrap();

    (key_pair, cert)
}

async fn leaf<'a>(
    context: &'a Context,
    ca_keypair: &KeyPair,
    ca: Certificate<'a>,
) -> (RsaKeyPair, Certificate<'a>) {
    let key_pair: RsaKeyPair = RsaKeyPair::random();

    let now = chrono::Utc::now();
    let not_before = chrono::Utc
        .with_ymd_and_hms(now.year(), 1, 1, 0, 0, 0)
        .unwrap();
    let not_after = not_before.clone().with_year(now.year() + 10).unwrap();
    let validity: Validity = (not_before..not_after).into();

    let name = Name::from_pairs(context, &[("C", "US"), ("ST", "CA"), ("CN", "leafy")]).unwrap();

    let subject_pubkey_info = key_pair.subject_public_key_info(context).await.unwrap();
    let ca_pubkey_info = ca_keypair.subject_public_key_info(context).await.unwrap();

    let extensions = vec![
        Extensions::basic_constraints(context, true, true, None).unwrap(),
        Extensions::key_usage(context, true, &[KeyUsages::KeyCertSign]).unwrap(),
        Extensions::authority_key_identifier(context, false, ca_pubkey_info).unwrap(),
        Extensions::subject_key_identifier(context, false, subject_pubkey_info).unwrap(),
    ];

    let tbs_cert = TbsCertificate {
        version: x509_cert::Version::V3,
        serial_number: x509_util::random_serial(context).unwrap(),
        signature: ca_keypair.signature_algorithm().await.unwrap(),
        issuer: ca.tbs_certificate.subject,
        validity: (&validity).try_into().unwrap(),
        subject: name,

        subject_public_key_info: subject_pubkey_info,

        issuer_unique_id: None,
        subject_unique_id: None,

        extensions: Some(extensions),
    };

    let cert = tbs_cert.sign(context, ca_keypair).await.unwrap();

    cert.write_pem_file("leaf.pem").unwrap();

    (key_pair, cert)
}
