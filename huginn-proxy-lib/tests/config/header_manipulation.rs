use huginn_proxy_lib::config::{load_from_path, HeaderManipulation, HeaderManipulationGroup};
use std::io::Write;
use tempfile::NamedTempFile;

#[test]
fn test_header_manipulation_defaults() {
    let group = HeaderManipulationGroup::default();
    assert!(group.add.is_empty(), "add should default to empty vector");
    assert!(group.remove.is_empty(), "remove should default to empty vector");

    let manipulation = HeaderManipulation::default();
    assert!(manipulation.request.add.is_empty());
    assert!(manipulation.request.remove.is_empty());
    assert!(manipulation.response.add.is_empty());
    assert!(manipulation.response.remove.is_empty());
}

#[tokio::test]
async fn test_header_manipulation_only_request_add(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut file = NamedTempFile::new()?;
    writeln!(
        file,
        r#"
listen = "127.0.0.1:0"
backends = [{{ address = "localhost:9000" }}]

[headers.request]
add = [
  {{ name = "X-Custom", value = "test" }}
]
"#
    )?;

    let config = load_from_path(file.path())?;

    if let Some(headers) = config.headers.as_ref() {
        assert_eq!(headers.request.add.len(), 1);
        assert_eq!(headers.request.add[0].name, "X-Custom");

        assert!(
            headers.request.remove.is_empty(),
            "remove should default to empty when only add is configured"
        );

        assert!(headers.response.add.is_empty());
        assert!(headers.response.remove.is_empty());

        Ok(())
    } else {
        Err("headers should be present".into())
    }
}

#[tokio::test]
async fn test_header_manipulation_only_request_remove(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut file = NamedTempFile::new()?;
    writeln!(
        file,
        r#"
listen = "127.0.0.1:0"
backends = [{{ address = "localhost:9000" }}]

[headers.request]
remove = ["Server", "X-Powered-By"]
"#
    )?;

    let config = load_from_path(file.path())?;

    if let Some(headers) = config.headers.as_ref() {
        assert_eq!(headers.request.remove.len(), 2);

        assert!(
            headers.request.add.is_empty(),
            "add should default to empty when only remove is configured"
        );

        assert!(headers.response.add.is_empty());
        assert!(headers.response.remove.is_empty());

        Ok(())
    } else {
        Err("headers should be present".into())
    }
}

#[tokio::test]
async fn test_header_manipulation_only_response_add(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut file = NamedTempFile::new()?;
    writeln!(
        file,
        r#"
listen = "127.0.0.1:0"
backends = [{{ address = "localhost:9000" }}]

[headers.response]
add = [
  {{ name = "X-Proxy", value = "huginn" }}
]
"#
    )?;

    let config = load_from_path(file.path())?;

    if let Some(headers) = config.headers.as_ref() {
        assert_eq!(headers.response.add.len(), 1);
        assert_eq!(headers.response.add[0].name, "X-Proxy");

        assert!(
            headers.response.remove.is_empty(),
            "remove should default to empty when only add is configured"
        );

        assert!(headers.request.add.is_empty());
        assert!(headers.request.remove.is_empty());

        Ok(())
    } else {
        Err("headers should be present".into())
    }
}

#[tokio::test]
async fn test_header_manipulation_only_response_remove(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut file = NamedTempFile::new()?;
    writeln!(
        file,
        r#"
listen = "127.0.0.1:0"
backends = [{{ address = "localhost:9000" }}]

[headers.response]
remove = ["Server"]
"#
    )?;

    let config = load_from_path(file.path())?;

    if let Some(headers) = config.headers.as_ref() {
        assert_eq!(headers.response.remove.len(), 1);

        assert!(
            headers.response.add.is_empty(),
            "add should default to empty when only remove is configured"
        );

        assert!(headers.request.add.is_empty());
        assert!(headers.request.remove.is_empty());

        Ok(())
    } else {
        Err("headers should be present".into())
    }
}

#[tokio::test]
async fn test_header_manipulation_mixed_request_response(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut file = NamedTempFile::new()?;
    writeln!(
        file,
        r#"
listen = "127.0.0.1:0"
backends = [{{ address = "localhost:9000" }}]

[headers.request]
add = [{{ name = "X-Request", value = "test" }}]

[headers.response]
remove = ["Server"]
"#
    )?;

    let config = load_from_path(file.path())?;

    if let Some(headers) = config.headers.as_ref() {
        assert_eq!(headers.request.add.len(), 1);
        assert!(headers.request.remove.is_empty());

        assert_eq!(headers.response.remove.len(), 1);
        assert!(headers.response.add.is_empty());

        Ok(())
    } else {
        Err("headers should be present".into())
    }
}

#[tokio::test]
async fn test_header_manipulation_per_route_defaults(
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut file = NamedTempFile::new()?;
    writeln!(
        file,
        r#"
listen = "127.0.0.1:0"
backends = [{{ address = "localhost:9000" }}]

[[routes]]
prefix = "/api"
backend = "localhost:9000"

[routes.headers.request]
add = [{{ name = "X-API", value = "v1" }}]
"#
    )?;

    let config = load_from_path(file.path())?;
    let route = &config.routes[0];

    if let Some(headers) = route.headers.as_ref() {
        assert_eq!(headers.request.add.len(), 1);
        assert!(
            headers.request.remove.is_empty(),
            "route request remove should default to empty"
        );

        assert!(headers.response.add.is_empty());
        assert!(headers.response.remove.is_empty());

        Ok(())
    } else {
        Err("route headers should be present".into())
    }
}

#[test]
fn test_empty_header_manipulation_group_serialization() {
    let group = HeaderManipulationGroup::default();

    if let Ok(toml) = toml::to_string(&group) {
        assert!(toml.contains("add = []") || !toml.contains("add"));
        assert!(toml.contains("remove = []") || !toml.contains("remove"));
    } else {
        panic!("Failed to serialize HeaderManipulationGroup");
    }
}
