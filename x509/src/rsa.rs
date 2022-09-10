use crate::cli::{HashMode, RSAKeySize, RSASigningMode, SigningArgs};

use color_eyre::{eyre::bail, Result};
use x509_util::prelude::Signer;

use self::signer::RsaSigner;

pub mod signer;

pub fn get_signer(
    size: RSAKeySize,
    mode: RSASigningMode,
    hash_mode: Option<HashMode>,
    args: &SigningArgs,
) -> Result<impl Signer> {
    let hash_mode = hash_mode.unwrap_or(match size {
        RSAKeySize::RSA1024 => HashMode::SHA256,
        RSAKeySize::RSA2048 => HashMode::SHA256,
        RSAKeySize::RSA3072 => HashMode::SHA384,
        RSAKeySize::RSA4096 => HashMode::SHA512,
    });

    if let Some(ref key_path) = args.key.key {
        Ok(RsaSigner::read_pkcs8_der_file(key_path, mode, hash_mode)?)
    } else if let Some(ref new_key_path) = args.key.new_key {
        let signer = RsaSigner::random(mode, hash_mode, size.bits())?;
        signer.write_pkcs8_der_file(new_key_path)?;
        Ok(signer)
    } else {
        bail!("This should never happen, this is a bug")
    }
}
