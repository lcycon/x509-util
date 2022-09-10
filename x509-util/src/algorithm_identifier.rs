pub const ECDSA_WITH_SHA256: spki::AlgorithmIdentifier<'static> = spki::AlgorithmIdentifier {
    oid: const_oid::db::rfc5912::ECDSA_WITH_SHA_256,
    parameters: None,
};

pub const ECDSA_WITH_SHA384: spki::AlgorithmIdentifier<'static> = spki::AlgorithmIdentifier {
    oid: const_oid::db::rfc5912::ECDSA_WITH_SHA_384,
    parameters: None,
};

pub const ECDSA_WITH_SHA512: spki::AlgorithmIdentifier<'static> = spki::AlgorithmIdentifier {
    oid: const_oid::db::rfc5912::ECDSA_WITH_SHA_512,
    parameters: None,
};

pub const RSA_SSA_PKCS1_V15_SHA256: spki::AlgorithmIdentifier<'static> =
    spki::AlgorithmIdentifier {
        oid: const_oid::db::rfc5912::SHA_256_WITH_RSA_ENCRYPTION,
        parameters: None,
    };

pub const RSA_SSA_PKCS1_V15_SHA384: spki::AlgorithmIdentifier<'static> =
    spki::AlgorithmIdentifier {
        oid: const_oid::db::rfc5912::SHA_384_WITH_RSA_ENCRYPTION,
        parameters: None,
    };

pub const RSA_SSA_PKCS1_V15_SHA512: spki::AlgorithmIdentifier<'static> =
    spki::AlgorithmIdentifier {
        oid: const_oid::db::rfc5912::SHA_512_WITH_RSA_ENCRYPTION,
        parameters: None,
    };

lazy_static::lazy_static! {
    pub static ref RSA_SSA_PSS_SHA256: spki::AlgorithmIdentifier<'static> = spki::AlgorithmIdentifier {
        oid: const_oid::db::rfc5912::ID_RSASSA_PSS,
        parameters: Some(crate::rsa_pss_params::PSS_MGF1_SHA256_DER.as_slice().try_into().unwrap()),
    };

    pub static ref RSA_SSA_PSS_SHA384: spki::AlgorithmIdentifier<'static> = spki::AlgorithmIdentifier {
        oid: const_oid::db::rfc5912::ID_RSASSA_PSS,
        parameters: Some(crate::rsa_pss_params::PSS_MGF1_SHA384_DER.as_slice().try_into().unwrap()),
    };

    pub static ref RSA_SSA_PSS_SHA512: spki::AlgorithmIdentifier<'static> = spki::AlgorithmIdentifier {
        oid: const_oid::db::rfc5912::ID_RSASSA_PSS,
        parameters: Some(crate::rsa_pss_params::PSS_MGF1_SHA512_DER.as_slice().try_into().unwrap()),
    };
}
