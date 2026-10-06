//! Broker library surface.
//!
//! The binary is a thin `main` over this crate so that the security-relevant
//! layers — audience binding above all, on both the JWT and SigV4 doors — are reachable from integration tests
//! in `crates/broker/tests/` without standing up a cluster.

pub mod audience;
pub mod aws;
pub mod cluster;
pub mod cognito;
pub mod config;
pub mod exchange;
pub mod http;
pub mod index;
pub mod jwt;
pub use recognito_api::metrics;
pub mod secrets;
pub mod server;
pub mod service;
pub mod sigv4;
pub mod sts;

pub use audience::{
    AudienceClaim, AudienceConfigError, AudienceRejection, AudienceValidator, CanonicalAudience,
    DEFAULT_APISERVER_AUDIENCES,
};
pub use exchange::{
    ErrorCode, ExchangeError, SubjectToken, TokenExchangeForm, TokenExchangeRequest,
    TokenExchangeResponse,
};
pub use sigv4::{
    PresignedCallerIdentity, SigV4ConfigError, SigV4Rejection, SigV4Validator, StsEndpoint,
    StsError, VerifiedAwsCaller,
};
