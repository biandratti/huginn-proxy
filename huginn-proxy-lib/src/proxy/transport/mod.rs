pub mod plain;
pub mod tls;

pub use plain::{handle_plain_connection, PlainConnectionConfig};
pub use tls::{handle_tls_connection, TlsConnectionConfig};
