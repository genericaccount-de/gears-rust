//! Interactive per-user OAuth2 authorization-code enrollment (infra layer).
//!
//! Implements the [`OAuthEnrollmentService`](crate::domain::services::OAuthEnrollmentService)
//! domain port against credstore (state + token store) and an HTTP client
//! (discovery / dynamic client registration / token exchange).

pub(crate) mod enrollment;

pub(crate) use enrollment::OAuthEnrollmentServiceImpl;
