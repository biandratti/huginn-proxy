pub mod guards;
pub mod manager;
pub mod stream;

pub use guards::{ConnectionGuard, TlsConnectionGuard};
pub use manager::{ConnectionError, ConnectionManager};
pub use stream::PrefixedStream;
