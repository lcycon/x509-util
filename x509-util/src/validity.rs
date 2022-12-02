use std::{ops::Range, time::Duration};

use chrono::{DateTime, Datelike, Utc};
use der::asn1::GeneralizedTime;
use spki::der::asn1::UtcTime;

use crate::error::Error;

pub struct Validity {
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
}

fn chrono_as_time(ch: &DateTime<Utc>) -> Option<x509_cert::time::Time> {
    let offset = ch.timestamp_millis().try_into().ok()?;
    let duration = Duration::from_millis(offset);

    if ch.year() < 2050 {
        UtcTime::from_unix_duration(duration).ok().map(|v| v.into())
    } else {
        GeneralizedTime::from_unix_duration(duration)
            .ok()
            .map(|v| v.into())
    }
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

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use x509_cert::time::Time;

    use super::chrono_as_time;

    #[test]
    fn test_chrono_to_utctime() {
        let time = chrono::Utc.with_ymd_and_hms(2025, 1, 1, 0, 0, 0).unwrap();
        let time2 = chrono::Utc
            .with_ymd_and_hms(2049, 12, 31, 23, 59, 59)
            .unwrap();

        assert!(matches!(chrono_as_time(&time), Some(Time::UtcTime(_))));
        assert!(matches!(chrono_as_time(&time2), Some(Time::UtcTime(_))));
    }

    #[test]
    fn test_chrono_to_generalized() {
        let time = chrono::Utc.with_ymd_and_hms(2055, 1, 1, 0, 0, 0).unwrap();

        assert!(matches!(chrono_as_time(&time), Some(Time::GeneralTime(_))));
    }
}
