//! Duration strings for CRD fields.
//!
//! Kubernetes API convention is a duration *string* ("15m", "90d"), not a
//! bare integer, because a bare integer forces every reader to remember the
//! unit. We parse into `std::time::Duration` and validate against per-field
//! floors and ceilings at admission time rather than trusting the value at
//! use time — a `tokenValidity` below the cache's freshness floor would make
//! every entry permanently stale and turn each request into a Cognito call,
//! which is a quota problem, not just a correctness one.

use std::fmt;
use std::str::FromStr;
use std::time::Duration as StdDuration;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A duration written the way Kubernetes writes them: an integer followed by
/// a single unit suffix. Deliberately *not* a general parser — no compound
/// forms ("1h30m"), no fractions. One number, one unit, unambiguous in review.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct Duration(StdDuration);

/// Regex mirrored into the CRD's OpenAPI schema so the apiserver rejects
/// malformed values before the controller ever sees them.
pub const DURATION_PATTERN: &str = r"^[1-9][0-9]*(s|m|h|d)$";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum DurationError {
    #[error("duration is empty")]
    Empty,
    #[error("duration {0:?} must be a positive integer followed by one of s, m, h, d")]
    Malformed(String),
    #[error("duration {0:?} overflows")]
    Overflow(String),
}

impl Duration {
    pub const fn from_secs(secs: u64) -> Self {
        Duration(StdDuration::from_secs(secs))
    }

    pub const fn as_std(self) -> StdDuration {
        self.0
    }

    pub const fn as_secs(self) -> u64 {
        self.0.as_secs()
    }
}

impl FromStr for Duration {
    type Err = DurationError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(DurationError::Empty);
        }
        let (digits, unit) = s.split_at(s.len() - 1);
        let multiplier = match unit {
            "s" => 1u64,
            "m" => 60,
            "h" => 60 * 60,
            "d" => 24 * 60 * 60,
            _ => return Err(DurationError::Malformed(s.to_owned())),
        };
        // Reject leading zeros and "+"/"-" signs: `u64::from_str` would accept
        // "007" and we want exactly one spelling per value so that specHash is
        // stable across cosmetically different manifests.
        if digits.is_empty()
            || digits.starts_with('0')
            || !digits.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(DurationError::Malformed(s.to_owned()));
        }
        let value: u64 = digits
            .parse()
            .map_err(|_| DurationError::Overflow(s.to_owned()))?;
        let secs = value
            .checked_mul(multiplier)
            .ok_or_else(|| DurationError::Overflow(s.to_owned()))?;
        Ok(Duration(StdDuration::from_secs(secs)))
    }
}

impl fmt::Display for Duration {
    /// Renders back to the largest unit that divides evenly, so a round-trip
    /// through the API server is a fixed point.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let secs = self.0.as_secs();
        for (unit, size) in [("d", 86_400u64), ("h", 3_600), ("m", 60)] {
            if secs % size == 0 && secs / size > 0 {
                return write!(f, "{}{}", secs / size, unit);
            }
        }
        write!(f, "{secs}s")
    }
}

impl Serialize for Duration {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Duration {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        raw.parse().map_err(serde::de::Error::custom)
    }
}

impl schemars::JsonSchema for Duration {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "Duration".into()
    }

    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "pattern": DURATION_PATTERN,
            "description": "Positive integer with a single unit suffix: s, m, h, or d. Example: \"15m\".",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_each_unit() {
        assert_eq!("30s".parse::<Duration>().unwrap().as_secs(), 30);
        assert_eq!("15m".parse::<Duration>().unwrap().as_secs(), 900);
        assert_eq!("2h".parse::<Duration>().unwrap().as_secs(), 7_200);
        assert_eq!("90d".parse::<Duration>().unwrap().as_secs(), 7_776_000);
    }

    #[test]
    fn rejects_forms_that_would_destabilize_spec_hash() {
        // Each of these is a second spelling of a value that already has one.
        for bad in ["007m", "0m", "+5m", "-5m", "1h30m", "1.5h", "5", "m", ""] {
            assert!(
                bad.parse::<Duration>().is_err(),
                "{bad:?} should be rejected"
            );
        }
    }

    #[test]
    fn display_round_trips_through_the_largest_even_unit() {
        for original in ["30s", "15m", "2h", "90d"] {
            let parsed: Duration = original.parse().unwrap();
            assert_eq!(parsed.to_string(), original);
            assert_eq!(parsed.to_string().parse::<Duration>().unwrap(), parsed);
        }
        // 3600s and 60m are the same instant; both normalize to "1h" so two
        // manifests that differ only cosmetically hash identically.
        assert_eq!("3600s".parse::<Duration>().unwrap().to_string(), "1h");
        assert_eq!("60m".parse::<Duration>().unwrap().to_string(), "1h");
    }

    #[test]
    fn rejects_overflow_rather_than_wrapping() {
        let huge = format!("{}d", u64::MAX);
        assert!(matches!(
            huge.parse::<Duration>(),
            Err(DurationError::Overflow(_))
        ));
    }
}
