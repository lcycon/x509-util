use x509_util::x509_cert::ext::pkix::KeyUsages;

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum KeyUsage {
    DigitalSignature,
    NonRepudiation,
    KeyEncipherment,
    DataEncipherment,
    KeyAgreement,
    KeyCertSign,
    CRLSign,
    EncipherOnly,
    DecipherOnly,
}

impl From<KeyUsages> for KeyUsage {
    fn from(usage: KeyUsages) -> Self {
        match usage {
            KeyUsages::DigitalSignature => KeyUsage::DigitalSignature,
            KeyUsages::NonRepudiation => KeyUsage::NonRepudiation,
            KeyUsages::KeyEncipherment => KeyUsage::KeyEncipherment,
            KeyUsages::DataEncipherment => KeyUsage::DataEncipherment,
            KeyUsages::KeyAgreement => KeyUsage::KeyAgreement,
            KeyUsages::KeyCertSign => KeyUsage::KeyCertSign,
            KeyUsages::CRLSign => KeyUsage::CRLSign,
            KeyUsages::EncipherOnly => KeyUsage::EncipherOnly,
            KeyUsages::DecipherOnly => KeyUsage::DecipherOnly,
        }
    }
}

impl From<&KeyUsage> for KeyUsages {
    fn from(usage: &KeyUsage) -> Self {
        match usage {
            KeyUsage::DigitalSignature => KeyUsages::DigitalSignature,
            KeyUsage::NonRepudiation => KeyUsages::NonRepudiation,
            KeyUsage::KeyEncipherment => KeyUsages::KeyEncipherment,
            KeyUsage::DataEncipherment => KeyUsages::DataEncipherment,
            KeyUsage::KeyAgreement => KeyUsages::KeyAgreement,
            KeyUsage::KeyCertSign => KeyUsages::KeyCertSign,
            KeyUsage::CRLSign => KeyUsages::CRLSign,
            KeyUsage::EncipherOnly => KeyUsages::EncipherOnly,
            KeyUsage::DecipherOnly => KeyUsages::DecipherOnly,
        }
    }
}
