pub mod plain;
mod timeout_helper;
pub mod tls;

pub use plain::{PlainConnectionConfig, handle_plain_connection};
pub use tls::{TlsConnectionConfig, handle_tls_connection};
