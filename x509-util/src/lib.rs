use context::Alloc;
use der::asn1::UIntRef;

pub use x509_cert;

pub mod algorithm_identifier;
pub mod context;
pub mod error;
pub mod extensions;
pub mod name;
pub mod pem;
pub mod prelude;
mod rsa_pss_params;
pub mod signer;
pub mod subject_public_key_info;
pub mod validity;

pub fn random_serial(context: &context::Context) -> error::Result<UIntRef> {
    let serial_1: u128 = rand::random();
    let serial_2: u128 = rand::random();

    let bytes = [serial_1.to_ne_bytes(), serial_2.to_ne_bytes()]
        .concat()
        .alloc_into(context);

    Ok(UIntRef::new(bytes)?)
}
