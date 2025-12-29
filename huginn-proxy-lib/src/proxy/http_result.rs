use http::StatusCode;
use thiserror::Error;

/// HTTP result type, T is typically a hyper::Response
/// HttpError is used to generate a synthetic error response
pub(crate) type HttpResult<T> = std::result::Result<T, HttpError>;

/// Describes things that can go wrong in the forwarder
#[derive(Debug, Error, Clone)]
pub enum HttpError {
    #[error("Invalid host in request header")]
    InvalidHostInRequestHeader,

    #[error("No matching backend")]
    NoMatchingBackend,

    #[error("No upstream candidates")]
    NoUpstreamCandidates,

    #[error("Failed to generate upstream request for backend: {0}")]
    FailedToGenerateUpstreamRequest(String),

    #[error("Failed to get response from backend: {0}")]
    FailedToGetResponseFromBackend(String),

    #[error("Failed to generate downstream response: {0}")]
    FailedToGenerateDownstreamResponse(String),

    #[error("Invalid URI: {0}")]
    InvalidUri(String),

    #[error("Backend error: {0}")]
    BackendError(String),
}

impl From<HttpError> for StatusCode {
    fn from(e: HttpError) -> StatusCode {
        match e {
            HttpError::InvalidHostInRequestHeader => StatusCode::BAD_REQUEST,
            HttpError::NoMatchingBackend => StatusCode::SERVICE_UNAVAILABLE,
            HttpError::NoUpstreamCandidates => StatusCode::NOT_FOUND,
            HttpError::FailedToGenerateUpstreamRequest(_) => StatusCode::INTERNAL_SERVER_ERROR,
            HttpError::FailedToGetResponseFromBackend(_) => StatusCode::BAD_GATEWAY,
            HttpError::FailedToGenerateDownstreamResponse(_) => StatusCode::INTERNAL_SERVER_ERROR,
            HttpError::InvalidUri(_) => StatusCode::BAD_REQUEST,
            HttpError::BackendError(_) => StatusCode::BAD_GATEWAY,
        }
    }
}
