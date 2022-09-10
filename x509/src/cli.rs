use std::path::PathBuf;

use chrono::{DateTime, Utc};
use clap::{Args, Parser, Subcommand, ValueHint};

use crate::name::OwnedName;

#[cfg(feature = "ecdsa")]
mod ecdsa;
#[cfg(feature = "rsa")]
mod rsa;
mod usage;

#[cfg(feature = "ecdsa")]
pub use self::ecdsa::EcdsaCurve;
#[cfg(feature = "rsa")]
pub use self::rsa::{RSAKeySize, RSASigningMode};
pub use self::usage::KeyUsage;

#[derive(Debug, Parser)]
#[clap(version)]
pub struct Cli {
    #[clap(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Args)]
#[clap(group(
    clap::ArgGroup::new("ca_key").required(true)
))]
pub struct KeySelector {
    #[clap(long, group = "ca_key", value_hint = ValueHint::FilePath, help = "Create a new key at the given path")]
    pub new_key: Option<PathBuf>,
    #[clap(short, long, group = "ca_key", value_hint = ValueHint::FilePath, help = "Use existing key at the given path")]
    pub key: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct Validity {
    #[clap(long, value_hint = ValueHint::Other)]
    pub not_before: DateTime<Utc>,
    #[clap(long, value_hint = ValueHint::Other)]
    pub not_after: DateTime<Utc>,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    Generate,
    SelfSign {
        #[clap(subcommand)]
        command: SelfSignVariants,
    },
    Sign,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum HashMode {
    SHA256,
    SHA384,
    SHA512,
}

#[derive(Debug, Args)]
pub struct SigningArgs {
    #[clap(short, long, value_hint = ValueHint::FilePath)]
    pub output: Option<PathBuf>,
    #[clap(flatten)]
    pub key: KeySelector,
    #[clap(flatten)]
    pub validity: Validity,
    #[clap(short, long, value_hint = ValueHint::Other, help = "Subject/Issuer in the form of C=US,ST=CA,L=\"San Francisco\"")]
    pub name: OwnedName,
    #[clap(long)]
    pub ca: bool,
    #[clap(long, value_hint = ValueHint::Other)]
    pub ca_pathlen: Option<u8>,
    #[clap(
        long,
        value_enum,
        value_delimiter = ',',
        help = "X509v3 KeyUsage extension values"
    )]
    pub usages: Option<Vec<KeyUsage>>,
}

#[derive(Debug, Subcommand)]
pub enum SelfSignVariants {
    #[cfg(feature = "rsa")]
    Rsa {
        #[clap(long, value_enum)]
        size: RSAKeySize,
        #[clap(long, value_enum)]
        mode: RSASigningMode,
        #[clap(long, value_enum)]
        hash_mode: Option<HashMode>,
        #[clap(flatten)]
        signing_args: SigningArgs,
    },
    #[cfg(feature = "ecdsa")]
    Ecdsa {
        #[clap(long, value_enum)]
        curve: EcdsaCurve,
        #[clap(flatten)]
        signing_args: SigningArgs,
    },
}
