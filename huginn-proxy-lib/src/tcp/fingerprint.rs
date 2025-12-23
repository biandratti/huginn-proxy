#![forbid(unsafe_code)]

/// HTTP header names used to propagate fingerprints to backends.
pub const HDR_TCP_FP: &str = "X-Huginn-TCP-F";
pub const HDR_HTTP_FP: &str = "X-Huginn-HTTP-F";
pub const HDR_TLS_FP: &str = "X-Huginn-TLS-F";
