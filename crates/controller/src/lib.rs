//! The controller: reconciles `CognitoClientMapping`s into Cognito app
//! clients, rotates their secrets, and audits them for drift.
//!
//! [`resync`] decides from CRD status alone (invariant 4), [`reconcile`] acts
//! through the [`cognito::CognitoAdmin`] seam, [`controller`] is the kube-rs
//! plumbing, and [`aws`] is the SDK-backed admin. The binary in `main.rs` only
//! wires them together.

pub mod aws;
pub mod cognito;
pub mod config;
pub mod controller;
pub mod reconcile;
pub mod resync;
