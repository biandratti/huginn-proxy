use huginn_proxy_lib::proxy::http_result::HttpError;

#[test]
fn test_error_type_mapping() {
    assert_eq!(
        HttpError::InvalidHostInRequestHeader.error_type(),
        "invalid_host"
    );
    assert_eq!(HttpError::NoMatchingBackend.error_type(), "no_matching_backend");
    assert_eq!(
        HttpError::NoUpstreamCandidates.error_type(),
        "no_upstream_candidates"
    );
    assert_eq!(
        HttpError::FailedToGenerateUpstreamRequest("test".to_string()).error_type(),
        "upstream_request_failed"
    );
    assert_eq!(
        HttpError::FailedToGetResponseFromBackend("test".to_string()).error_type(),
        "backend_error"
    );
    assert_eq!(
        HttpError::FailedToGenerateDownstreamResponse("test".to_string()).error_type(),
        "downstream_response_failed"
    );
    assert_eq!(HttpError::InvalidUri("test".to_string()).error_type(), "invalid_uri");
    assert_eq!(HttpError::BackendError("test".to_string()).error_type(), "backend_error");
}

#[test]
fn test_status_code_conversion() {
    use http::StatusCode;
    use std::convert::From;

    assert_eq!(
        StatusCode::from(HttpError::InvalidHostInRequestHeader),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        StatusCode::from(HttpError::NoMatchingBackend),
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        StatusCode::from(HttpError::NoUpstreamCandidates),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        StatusCode::from(HttpError::FailedToGetResponseFromBackend("test".to_string())),
        StatusCode::BAD_GATEWAY
    );
}

