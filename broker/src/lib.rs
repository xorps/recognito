//! Broker library surface.
//!
//! The binary is a thin `main` over this crate so that the security-relevant
//! layers — audience binding above all — are reachable from integration tests
//! in `broker/tests/` without standing up a cluster.

pub mod audience;
pub mod exchange;

pub use audience::{
    AudienceClaim, AudienceConfigError, AudienceRejection, AudienceValidator, CanonicalAudience,
    DEFAULT_APISERVER_AUDIENCES,
};
pub use exchange::{
    ErrorCode, ExchangeError, TokenExchangeForm, TokenExchangeRequest, TokenExchangeResponse,
};
