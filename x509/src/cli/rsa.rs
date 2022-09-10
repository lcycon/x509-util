#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum RSAKeySize {
    RSA1024,
    RSA2048,
    RSA3072,
    RSA4096,
}

impl RSAKeySize {
    pub fn bits(&self) -> usize {
        match self {
            RSAKeySize::RSA1024 => 1024,
            RSAKeySize::RSA2048 => 2048,
            RSAKeySize::RSA3072 => 3072,
            RSAKeySize::RSA4096 => 4096,
        }
    }
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum RSASigningMode {
    Pkcs1v15,
    Pss,
}
