use der::asn1::Utf8StringRef;
use x509_cert::{
    attr::{AttributeType, AttributeTypeAndValue},
    name::{RdnSequence, RelativeDistinguishedName},
};

use crate::{
    context::{Alloc, Context},
    error::Result,
};

pub struct Name;

impl Name {
    pub fn from_pairs<'a, T: AsRef<str>, U: AsRef<str>>(
        context: &'a Context,
        pairs: &[(T, U)],
    ) -> Result<x509_cert::name::Name<'a>> {
        let mut rdns = Vec::with_capacity(pairs.len());

        for (key, val) in pairs.iter() {
            let value: Utf8StringRef =
                Utf8StringRef::new(val.as_ref().as_bytes().alloc_into(context))?;

            if let Some(key) = get_attribute_type(key.as_ref()) {
                let atv = AttributeTypeAndValue {
                    oid: key,
                    value: value.into(),
                };

                rdns.push(RelativeDistinguishedName([atv].try_into()?));
            }
        }

        Ok(RdnSequence(rdns))
    }
}

fn get_attribute_type(key: &str) -> Option<AttributeType> {
    match key {
        "C" => Some(const_oid::db::rfc4519::C),
        "ST" => Some(const_oid::db::rfc4519::ST),
        "L" => Some(const_oid::db::rfc4519::L),
        "O" => Some(const_oid::db::rfc4519::O),
        "OU" => Some(const_oid::db::rfc4519::OU),
        "CN" => Some(const_oid::db::rfc4519::CN),
        _ => None,
    }
}
