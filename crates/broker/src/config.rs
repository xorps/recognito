//! Broker configuration, from the environment. Everything is validated here,
//! at startup: a broker that starts with a config it cannot enforce is worse
//! than one that does not start.

use std::net::SocketAddr;
use std::path::PathBuf;

use std::time::Duration;

use crate::audience::{AudienceConfigError, CanonicalAudience};
use crate::cluster::{ClusterConfig, PeerTls};
use crate::cognito::{TokenEndpointError, token_endpoint};
use crate::sigv4::{SigV4ConfigError, StsEndpoint};

#[derive(Debug)]
pub struct BrokerConfig {
    pub audience: CanonicalAudience,
    /// Cluster-specific apiserver audiences, for attack classification only.
    pub apiserver_audiences: Vec<String>,
    pub user_pool_id: String,
    pub region: String,
    pub token_url: String,
    pub listen: SocketAddr,
    pub ops_listen: SocketAddr,
    pub tls: Option<(PathBuf, PathBuf)>,
    /// This replica's slice of the fleet's Describe budget.
    pub describe_rps: f64,
    pub sigv4: Option<SigV4Config>,
    /// Peer fabric (ADR-5). `None`: replicas run independently, as in v1.
    pub cluster: Option<ClusterConfig>,
}

#[derive(Debug)]
pub struct SigV4Config {
    pub endpoints: Vec<StsEndpoint>,
    pub trusted_accounts: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("{0} must be set")]
    Missing(&'static str),
    #[error("RECOGNITO_BROKER_AUDIENCE: {0}")]
    Audience(#[from] AudienceConfigError),
    #[error("RECOGNITO_USER_POOL_ID {0:?} is not a Cognito user pool ID (<region>_<id>)")]
    UserPoolId(String),
    #[error("RECOGNITO_COGNITO_DOMAIN: {0}")]
    Domain(#[from] TokenEndpointError),
    #[error("{0}: {1:?} is not a socket address")]
    Addr(&'static str, String),
    #[error("RECOGNITO_TLS_CERT_FILE and RECOGNITO_TLS_KEY_FILE must be set together")]
    HalfTls,
    #[error("RECOGNITO_DESCRIBE_RPS must be a positive number, got {0:?}")]
    Rps(String),
    #[error("SigV4: {0}")]
    SigV4(#[from] SigV4ConfigError),
    #[error("{0} must be a positive whole number of milliseconds, got {1:?}")]
    Millis(&'static str, String),
}

impl BrokerConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|k| std::env::var(k).ok().filter(|v| !v.is_empty()))
    }

    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let required = |k: &'static str| get(k).ok_or(ConfigError::Missing(k));
        let addr = |k: &'static str, default: &str| {
            let raw = get(k).unwrap_or_else(|| default.to_owned());
            raw.parse().map_err(|_| ConfigError::Addr(k, raw))
        };

        let audience = CanonicalAudience::parse(&required("RECOGNITO_BROKER_AUDIENCE")?)?;

        let user_pool_id = required("RECOGNITO_USER_POOL_ID")?;
        let region = user_pool_id
            .split_once('_')
            .filter(|(_, id)| !id.is_empty() && id.bytes().all(|b| b.is_ascii_alphanumeric()))
            .and_then(|(region, _)| StsEndpoint::regional(region).ok().map(|_| region))
            .ok_or_else(|| ConfigError::UserPoolId(user_pool_id.clone()))?
            .to_owned();

        let token_url = token_endpoint(&required("RECOGNITO_COGNITO_DOMAIN")?)?;

        let tls = match (
            get("RECOGNITO_TLS_CERT_FILE"),
            get("RECOGNITO_TLS_KEY_FILE"),
        ) {
            (Some(c), Some(k)) => Some((c.into(), k.into())),
            (None, None) => None,
            _ => return Err(ConfigError::HalfTls),
        };

        let describe_rps = match get("RECOGNITO_DESCRIBE_RPS") {
            None => 1.0,
            Some(raw) => raw
                .parse::<f64>()
                .ok()
                .filter(|r| *r > 0.0 && r.is_finite())
                .ok_or(ConfigError::Rps(raw))?,
        };

        // The SigV4 door is opt-in: closed unless regions are set. Once open,
        // trusted accounts are mandatory (SigV4Validator refuses an empty list).
        let sigv4 = match get("RECOGNITO_SIGV4_REGIONS") {
            None => None,
            Some(regions) => Some(SigV4Config {
                endpoints: split_list(&regions)
                    .map(StsEndpoint::regional)
                    .collect::<Result<_, _>>()?,
                trusted_accounts: split_list(
                    &get("RECOGNITO_SIGV4_TRUSTED_ACCOUNTS").unwrap_or_default(),
                )
                .map(str::to_owned)
                .collect(),
            }),
        };

        let millis = |k: &'static str, default: u64| match get(k) {
            None => Ok(Duration::from_millis(default)),
            Some(raw) => raw
                .parse::<u64>()
                .ok()
                .filter(|ms| *ms > 0)
                .map(Duration::from_millis)
                .ok_or(ConfigError::Millis(k, raw)),
        };
        // The fabric is on when a peer Service is named; everything else it
        // needs is then mandatory, so a half-configured mesh fails at startup.
        let cluster = match get("RECOGNITO_PEER_SERVICE") {
            None => None,
            Some(service) => Some(ClusterConfig {
                service,
                namespace: required("RECOGNITO_POD_NAMESPACE")?,
                pod_ip: {
                    let raw = required("RECOGNITO_POD_IP")?;
                    raw.parse()
                        .map_err(|_| ConfigError::Addr("RECOGNITO_POD_IP", raw))?
                },
                listen: addr("RECOGNITO_PEER_LISTEN_ADDR", "0.0.0.0:8444")?,
                tls: PeerTls {
                    cert: required("RECOGNITO_PEER_TLS_CERT_FILE")?.into(),
                    key: required("RECOGNITO_PEER_TLS_KEY_FILE")?.into(),
                    ca: required("RECOGNITO_PEER_TLS_CA_FILE")?.into(),
                    server_name: get("RECOGNITO_PEER_SERVER_NAME")
                        .unwrap_or_else(|| "recognito-broker-peer".into()),
                },
                forward_deadline: millis("RECOGNITO_FORWARD_DEADLINE_MS", 500)?,
                anti_entropy_interval: millis("RECOGNITO_ANTI_ENTROPY_INTERVAL_MS", 1000)?,
            }),
        };

        Ok(BrokerConfig {
            audience,
            apiserver_audiences: split_list(
                &get("RECOGNITO_APISERVER_AUDIENCES").unwrap_or_default(),
            )
            .map(str::to_owned)
            .collect(),
            user_pool_id,
            region,
            token_url,
            listen: addr("RECOGNITO_LISTEN_ADDR", "0.0.0.0:8443")?,
            ops_listen: addr("RECOGNITO_OPS_LISTEN_ADDR", "0.0.0.0:9090")?,
            tls,
            describe_rps,
            sigv4,
            cluster,
        })
    }
}

fn split_list(raw: &str) -> impl Iterator<Item = &str> {
    raw.split(',').map(str::trim).filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        move |k| map.get(k).cloned()
    }

    const BASE: &[(&str, &str)] = &[
        (
            "RECOGNITO_BROKER_AUDIENCE",
            "https://cognito-broker.example.com",
        ),
        ("RECOGNITO_USER_POOL_ID", "eu-west-2_aBc123"),
        ("RECOGNITO_COGNITO_DOMAIN", "https://auth.example.com"),
    ];

    #[test]
    fn a_minimal_config_has_safe_defaults() {
        let c = BrokerConfig::from_lookup(env(BASE)).unwrap();
        assert_eq!(c.region, "eu-west-2");
        assert_eq!(c.token_url, "https://auth.example.com/oauth2/token");
        assert_eq!(c.listen.port(), 8443);
        assert!(c.tls.is_none());
        assert!(c.sigv4.is_none(), "SigV4 is opt-in");
        assert_eq!(c.describe_rps, 1.0);
    }

    #[test]
    fn misconfigurations_refuse_to_start() {
        let with = |extra: &[(&'static str, &'static str)]| {
            let mut pairs = BASE.to_vec();
            pairs.retain(|(k, _)| !extra.iter().any(|(e, _)| e == k));
            pairs.extend_from_slice(extra);
            BrokerConfig::from_lookup(env(&pairs))
        };
        assert!(with(&[("RECOGNITO_BROKER_AUDIENCE", "http://broker")]).is_err());
        assert!(with(&[("RECOGNITO_USER_POOL_ID", "nope")]).is_err());
        assert!(with(&[("RECOGNITO_COGNITO_DOMAIN", "http://auth.example.com")]).is_err());
        assert!(with(&[("RECOGNITO_TLS_CERT_FILE", "/tls.crt")]).is_err());
        assert!(with(&[("RECOGNITO_DESCRIBE_RPS", "0")]).is_err());
        assert!(with(&[("RECOGNITO_SIGV4_REGIONS", "not a region")]).is_err());
        assert!(BrokerConfig::from_lookup(env(&BASE[1..])).is_err());
    }

    #[test]
    fn the_peer_fabric_is_opt_in_and_complete_or_absent() {
        assert!(
            BrokerConfig::from_lookup(env(BASE))
                .unwrap()
                .cluster
                .is_none()
        );

        let mut pairs = BASE.to_vec();
        pairs.push(("RECOGNITO_PEER_SERVICE", "cognito-broker-peers"));
        assert!(
            BrokerConfig::from_lookup(env(&pairs)).is_err(),
            "a named peer Service without pod identity and TLS must not start"
        );
        pairs.extend_from_slice(&[
            ("RECOGNITO_POD_NAMESPACE", "recognito-system"),
            ("RECOGNITO_POD_IP", "10.0.0.7"),
            ("RECOGNITO_PEER_TLS_CERT_FILE", "/peer/tls.crt"),
            ("RECOGNITO_PEER_TLS_KEY_FILE", "/peer/tls.key"),
            ("RECOGNITO_PEER_TLS_CA_FILE", "/peer/ca.crt"),
        ]);
        let c = BrokerConfig::from_lookup(env(&pairs))
            .unwrap()
            .cluster
            .unwrap();
        assert_eq!(c.listen.port(), 8444);
        assert_eq!(c.forward_deadline, Duration::from_millis(500));
        assert_eq!(c.tls.server_name, "recognito-broker-peer");
    }

    #[test]
    fn sigv4_is_configured_from_regions_and_accounts() {
        let mut pairs = BASE.to_vec();
        pairs.push(("RECOGNITO_SIGV4_REGIONS", "us-east-1, eu-west-2"));
        pairs.push(("RECOGNITO_SIGV4_TRUSTED_ACCOUNTS", "111122223333"));
        let c = BrokerConfig::from_lookup(env(&pairs)).unwrap();
        let s = c.sigv4.unwrap();
        assert_eq!(s.endpoints.len(), 2);
        assert_eq!(s.trusted_accounts, vec!["111122223333"]);
    }
}
