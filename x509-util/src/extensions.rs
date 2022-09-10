use der::{asn1::OctetStringRef, Encode};
use flagset::FlagSet;
use x509_cert::ext::{self, pkix::KeyUsages};

use crate::{
    context::{Alloc, Context},
    error::{Error, Result},
    subject_public_key_info::SubjectPublicKeyInfo,
};

pub struct Extensions;

impl Extensions {
    pub fn basic_constraints(
        context: &Context,
        critical: bool,
        ca: bool,
        path_len_constraint: Option<u8>,
    ) -> Result<ext::Extension> {
        let extn_value = ext::pkix::BasicConstraints {
            ca,
            path_len_constraint,
        }
        .to_vec()?
        .alloc_into(context);

        Ok(ext::Extension {
            extn_id: const_oid::db::rfc5280::ID_CE_BASIC_CONSTRAINTS,
            critical,
            extn_value,
        })
    }

    pub fn key_usage<'a>(
        context: &'a Context,
        critical: bool,
        usages: &'_ [KeyUsages],
    ) -> Result<ext::Extension<'a>> {
        let flagset = usages
            .iter()
            .map(|u| FlagSet::from(*u))
            .reduce(|a, b| a | b)
            .ok_or(Error::FailedEncodingFlagset)?;

        Ok(ext::Extension {
            extn_id: const_oid::db::rfc5280::ID_CE_KEY_USAGE,
            critical,
            extn_value: flagset.to_vec()?.as_slice().alloc_into(context),
        })
    }

    pub fn subject_key_identifier<'a>(
        context: &'a Context,
        critical: bool,
        pubkey_info: spki::SubjectPublicKeyInfo<'_>,
    ) -> Result<ext::Extension<'a>> {
        let ident = SubjectPublicKeyInfo::as_key_identifier(pubkey_info);
        let octets = OctetStringRef::new(&ident)?;
        let bytes = ext::pkix::SubjectKeyIdentifier(octets).to_vec()?;

        Ok(ext::Extension {
            extn_id: const_oid::db::rfc5280::ID_CE_SUBJECT_KEY_IDENTIFIER,
            critical,
            extn_value: bytes.alloc_into(context),
        })
    }

    pub fn authority_key_identifier<'a>(
        context: &'a Context,
        critical: bool,
        pubkey_info: spki::SubjectPublicKeyInfo<'_>,
    ) -> Result<ext::Extension<'a>> {
        let ident = SubjectPublicKeyInfo::as_key_identifier(pubkey_info);
        let octets = OctetStringRef::new(&ident)?;
        let bytes = ext::pkix::AuthorityKeyIdentifier {
            key_identifier: Some(octets),
            authority_cert_issuer: None,
            authority_cert_serial_number: None,
        }
        .to_vec()?;

        Ok(ext::Extension {
            extn_id: const_oid::db::rfc5280::ID_CE_AUTHORITY_KEY_IDENTIFIER,
            critical,
            extn_value: bytes.alloc_into(context),
        })
    }
}
