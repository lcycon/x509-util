use const_oid::db::rfc5912::ID_MGF_1;
use der::Encode;
use pkcs1::{RsaPssParams, TrailerField};
use spki::AlgorithmIdentifier;

const SALT_LEN_32: u8 = 32;
const SALT_LEN_48: u8 = 48;
const SALT_LEN_64: u8 = 64;

const SHA2_256: AlgorithmIdentifier<'static> = AlgorithmIdentifier {
    oid: const_oid::db::rfc5912::ID_SHA_256,
    parameters: None,
};

const SHA2_384: AlgorithmIdentifier<'static> = AlgorithmIdentifier {
    oid: const_oid::db::rfc5912::ID_SHA_384,
    parameters: None,
};

const SHA2_512: AlgorithmIdentifier<'static> = AlgorithmIdentifier {
    oid: const_oid::db::rfc5912::ID_SHA_512,
    parameters: None,
};

lazy_static::lazy_static! {
    static ref SHA2_256_BYTES: Vec<u8> = SHA2_256.to_vec().unwrap();
    static ref SHA2_384_BYTES: Vec<u8> = SHA2_384.to_vec().unwrap();
    static ref SHA2_512_BYTES: Vec<u8> = SHA2_512.to_vec().unwrap();

    static ref MGF1_SHA256: AlgorithmIdentifier<'static> = AlgorithmIdentifier {
        oid: ID_MGF_1,
        parameters: Some(SHA2_256_BYTES.as_slice().try_into().unwrap()),
    };

    static ref MGF1_SHA384: AlgorithmIdentifier<'static> = AlgorithmIdentifier {
        oid: ID_MGF_1,
        parameters: Some(SHA2_384_BYTES.as_slice().try_into().unwrap()),
    };

    static ref MGF1_SHA512: AlgorithmIdentifier<'static> = AlgorithmIdentifier {
        oid: ID_MGF_1,
        parameters: Some(SHA2_512_BYTES.as_slice().try_into().unwrap()),
    };

    pub static ref PSS_MGF1_SHA256: RsaPssParams<'static> = RsaPssParams { hash: SHA2_256, mask_gen: *MGF1_SHA256, salt_len: SALT_LEN_32, trailer_field: TrailerField::BC };
    pub static ref PSS_MGF1_SHA256_DER: Vec<u8> = PSS_MGF1_SHA256.to_vec().unwrap();

    pub static ref PSS_MGF1_SHA384: RsaPssParams<'static> = RsaPssParams { hash: SHA2_384, mask_gen: *MGF1_SHA384, salt_len: SALT_LEN_48, trailer_field: TrailerField::BC };
    pub static ref PSS_MGF1_SHA384_DER: Vec<u8> = PSS_MGF1_SHA384.to_vec().unwrap();

    pub static ref PSS_MGF1_SHA512: RsaPssParams<'static> = RsaPssParams { hash: SHA2_512, mask_gen: *MGF1_SHA512, salt_len: SALT_LEN_64, trailer_field: TrailerField::BC };
    pub static ref PSS_MGF1_SHA512_DER: Vec<u8> = PSS_MGF1_SHA512.to_vec().unwrap();
}
