use sha1::{Digest, Sha1};

use spki::der::Decode;

use crate::{
    context::{Alloc, Context},
    error::Result,
};

pub struct SubjectPublicKeyInfo;

impl SubjectPublicKeyInfo {
    pub fn from_der<'a, 'b>(
        context: &'a Context,
        bytes: &'b [u8],
    ) -> Result<spki::SubjectPublicKeyInfo<'a>> {
        Ok(spki::SubjectPublicKeyInfo::from_der(
            bytes.alloc_into(context),
        )?)
    }

    pub fn as_key_identifier(subjpubkey: spki::SubjectPublicKeyInfo) -> Vec<u8> {
        let bytes = subjpubkey.subject_public_key;

        let mut hasher = Sha1::new();
        hasher.update(bytes);

        hasher.finalize().to_vec()
    }
}
