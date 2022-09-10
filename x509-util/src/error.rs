use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("Failed encoding flagset")]
    FailedEncodingFlagset,
    #[error("Failed signing")]
    FailedSigning,
    #[error("Error while signing")]
    ErrorSigning(#[from] Box<dyn std::error::Error + Send + Sync>),
    #[error("Error DER encoding: `{0}`")]
    DERError(der::Error),
    #[error("Failed building valifity not_before")]
    FailedBuildingNotBefore,
    #[error("Failed building valifity not_after")]
    FailedBuildingNotAfter,
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<der::Error> for Error {
    fn from(e: der::Error) -> Self {
        Error::DERError(e)
    }
}
