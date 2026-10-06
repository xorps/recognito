//! Controller configuration, from the environment, validated at startup.

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::time::Duration;

use crate::reconcile::Settings;
use crate::resync::DEFAULT_VERIFICATION_TTL_SECS;

#[derive(Debug)]
pub struct ControllerConfig {
    pub ops_listen: SocketAddr,
    pub settings: Settings,
    /// Read budget: `Describe`/`List*` calls per second, audit included.
    pub read_rps: f64,
    /// Write budget: create/update/delete/secret calls per second.
    pub write_rps: f64,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("{0}: {1:?} is not valid: {2}")]
    Invalid(&'static str, String, &'static str),
}

impl ControllerConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|k| std::env::var(k).ok().filter(|v| !v.is_empty()))
    }

    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let rps = |k: &'static str, default: f64| match get(k) {
            None => Ok(default),
            Some(raw) => raw
                .parse::<f64>()
                .ok()
                .filter(|r| *r > 0.0 && r.is_finite())
                .ok_or(ConfigError::Invalid(k, raw, "expected a positive number")),
        };
        let duration = |k: &'static str, default: Duration| match get(k) {
            None => Ok(default),
            Some(raw) => raw
                .parse::<recognito_api::Duration>()
                .map(|d| Duration::from_secs(d.as_secs()))
                .map_err(|_| ConfigError::Invalid(k, raw, "expected a duration like 10m")),
        };

        let ops_raw = get("RECOGNITO_OPS_LISTEN_ADDR").unwrap_or_else(|| "0.0.0.0:9090".into());
        let ops_listen = ops_raw.parse().map_err(|_| {
            ConfigError::Invalid("RECOGNITO_OPS_LISTEN_ADDR", ops_raw, "expected host:port")
        })?;

        let allowed_pools = get("RECOGNITO_ALLOWED_USER_POOLS").map(|raw| {
            raw.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect::<BTreeSet<_>>()
        });

        let rotation_grace = duration("RECOGNITO_ROTATION_GRACE", Duration::from_secs(600))?;
        if rotation_grace < Duration::from_secs(60) {
            return Err(ConfigError::Invalid(
                "RECOGNITO_ROTATION_GRACE",
                format!("{rotation_grace:?}"),
                "must be at least 1m: it has to outlast propagation to every broker",
            ));
        }
        let verification_ttl = duration(
            "RECOGNITO_VERIFICATION_TTL",
            Duration::from_secs(DEFAULT_VERIFICATION_TTL_SECS as u64),
        )?;

        Ok(ControllerConfig {
            ops_listen,
            settings: Settings {
                allowed_pools,
                rotation_grace,
                verification_ttl_secs: verification_ttl.as_secs() as i64,
            },
            read_rps: rps("RECOGNITO_AUDIT_RPS", 1.0)?,
            write_rps: rps("RECOGNITO_WRITE_RPS", 2.0)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_respect_the_quota_split() {
        let c = ControllerConfig::from_lookup(|_| None).unwrap();
        assert_eq!(c.read_rps, 1.0);
        assert_eq!(c.settings.rotation_grace, Duration::from_secs(600));
        assert!(c.settings.allowed_pools.is_none());
    }

    #[test]
    fn values_are_parsed_and_checked() {
        let c = ControllerConfig::from_lookup(|k| match k {
            "RECOGNITO_ALLOWED_USER_POOLS" => Some("us-east-1_a, eu-west-1_b".into()),
            "RECOGNITO_ROTATION_GRACE" => Some("15m".into()),
            _ => None,
        })
        .unwrap();
        assert_eq!(c.settings.allowed_pools.unwrap().len(), 2);
        assert_eq!(c.settings.rotation_grace, Duration::from_secs(900));

        for (k, v) in [
            ("RECOGNITO_ROTATION_GRACE", "10s"),
            ("RECOGNITO_AUDIT_RPS", "0"),
            ("RECOGNITO_OPS_LISTEN_ADDR", "nope"),
        ] {
            assert!(
                ControllerConfig::from_lookup(|key| (key == k).then(|| v.to_owned())).is_err(),
                "{k}={v}"
            );
        }
    }
}
