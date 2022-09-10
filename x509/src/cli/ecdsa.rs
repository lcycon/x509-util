#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum EcdsaCurve {
    #[cfg(feature = "p256")]
    P256,
    #[cfg(feature = "p384")]
    P384,
}
