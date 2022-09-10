use color_eyre::Result;
use x509_util::{
    prelude::{Context, Extensions, PemOperations},
    signer::{Signable, Signer},
    validity::Validity,
    x509_cert::TbsCertificate,
};

use crate::cli::SigningArgs;

pub async fn self_sign<S: Signer + Send + Sync>(signer: S, args: &SigningArgs) -> Result<()> {
    let context = Context::new();

    let name = args.name.to_x509_name(&context)?;
    let validity: Validity = (args.validity.not_before..args.validity.not_after).into();
    let spki = signer.subject_public_key_info(&context).await?;

    let mut extensions = vec![
        Extensions::basic_constraints(&context, args.ca, true, args.ca_pathlen)?,
        Extensions::authority_key_identifier(&context, false, spki)?,
        Extensions::subject_key_identifier(&context, false, spki)?,
    ];

    if let Some(ref usages) = args.usages {
        let usages: Vec<_> = usages.iter().map(Into::into).collect();

        let extension = Extensions::key_usage(&context, true, &usages)?;

        extensions.push(extension);
    }

    let tbs_certificate = TbsCertificate {
        version: x509_util::x509_cert::Version::V3,
        serial_number: x509_util::random_serial(&context)?,
        signature: signer.signature_algorithm().await?,
        issuer: name.clone(),
        validity: (&validity).try_into()?,
        subject: name,
        subject_public_key_info: spki,
        extensions: Some(extensions),

        issuer_unique_id: None,
        subject_unique_id: None,
    };

    let certificate = tbs_certificate.sign(&context, &signer).await?;

    if let Some(ref output_path) = args.output {
        certificate.write_pem_file(output_path)?;
    } else {
        let certificate_pem = certificate.to_pem()?;
        println!("{}", certificate_pem);
    }

    Ok(())
}
