#[macro_use]
extern crate lalrpop_util;

use clap::CommandFactory;
use clap::Parser;
use color_eyre::eyre::bail;
use color_eyre::eyre::Result;
use tracing_subscriber::EnvFilter;

mod cert;
mod cli;
#[cfg(feature = "ecdsa")]
mod ecdsa;
mod name;
#[cfg(feature = "rsa")]
mod rsa;

#[tokio::main]
async fn main() -> Result<()> {
    color_eyre::install()?;

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let cli = cli::Cli::parse();

    match cli.command {
        cli::Commands::Generate => {
            let mut app = cli::Cli::into_app();
            let data = xdg::BaseDirectories::new()?.get_data_home();
            let dir = data.join("fish/vendor_completions.d");

            std::fs::create_dir_all(dir.clone())?;

            let mut writer = std::fs::File::create(dir.join("x509.fish"))?;

            clap_complete::generate(clap_complete::shells::Fish, &mut app, "x509", &mut writer);

            Ok(())
        }
        #[cfg(feature = "rsa")]
        cli::Commands::SelfSign {
            command:
                cli::SelfSignVariants::Rsa {
                    size,
                    mode,
                    hash_mode,
                    signing_args,
                },
        } => {
            let signer = rsa::get_signer(size, mode, hash_mode, &signing_args)?;

            cert::self_sign(signer, &signing_args).await
        }
        #[cfg(feature = "ecdsa")]
        cli::Commands::SelfSign {
            command:
                cli::SelfSignVariants::Ecdsa {
                    curve,
                    signing_args,
                },
        } => {
            let signer = ecdsa::get_signer(curve, &signing_args)?;

            cert::self_sign(signer, &signing_args).await
        }
        #[allow(unreachable_patterns)] // Just in case someone compiles with all providers disabled
        cli::Commands::SelfSign { .. } => {
            bail!("Unsupported signing mode, this shouldn't be possible")
        }
        cli::Commands::Sign => todo!(),
    }
}
