//! Direct-`reqwest` transport for REST connector tools.
//!
//! Bypasses OAGW (per design) and therefore re-implements the safeguards OAGW
//! would normally provide: host allowlist, private/loopback/metadata IP
//! blocking, no auto-redirects, per-request timeout, and a max-response-bytes
//! cap. See [`reqwest_rest_client`] for the adapter and pure helpers.

pub mod reqwest_rest_client;
