use std::{ops::Range, time::Duration};

use chrono::{DateTime, Utc};
use spki::der::asn1::UtcTime;

use crate::error::Error;

pub struct Validity {
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
}

fn chrono_as_time(ch: &DateTime<Utc>) -> Option<x509_cert::time::Time> {
    let offset = ch.timestamp_millis().try_into().ok()?;
    let duration = Duration::from_millis(offset);

    UtcTime::from_unix_duration(duration).ok().map(|v| v.into())
}

impl TryFrom<&Validity> for x509_cert::time::Validity {
    type Error = crate::error::Error;

    fn try_from(this: &Validity) -> Result<Self, Self::Error> {
        Ok(x509_cert::time::Validity {
            not_before: chrono_as_time(&this.not_before).ok_or(Error::FailedBuildingNotBefore)?,
            not_after: chrono_as_time(&this.not_after).ok_or(Error::FailedBuildingNotAfter)?,
        })
    }
}

impl From<Range<DateTime<Utc>>> for Validity {
    fn from(this: Range<DateTime<Utc>>) -> Self {
        Validity {
            not_before: this.start,
            not_after: this.end,
        }
    }
}
