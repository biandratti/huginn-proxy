use crate::config::HealthFormat;
use crate::telemetry::http::{json_response, text_response, RespBody};
use hyper::{Response, StatusCode};
use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotReadyReason {
    PinsNotReady,
    CaptureDraining,
    CaptureDetached,
}

impl Serialize for NotReadyReason {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl NotReadyReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PinsNotReady => "pins_not_ready",
            Self::CaptureDraining => "capture_draining",
            Self::CaptureDetached => "capture_detached",
        }
    }

    pub const fn text_token(self) -> &'static str {
        match self {
            Self::PinsNotReady => "PINS_MISSING",
            Self::CaptureDraining | Self::CaptureDetached => "NOCAPTURE",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Status {
    Healthy,
    Alive,
    Serving,
    NotReady,
    NotFound,
    Error,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct StatusBody {
    status: Status,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<NotReadyReason>,
}

impl StatusBody {
    pub(crate) fn new(status: Status) -> Self {
        Self { status, reason: None }
    }

    pub(crate) fn with_reason(status: Status, reason: NotReadyReason) -> Self {
        Self { status, reason: Some(reason) }
    }

    pub(crate) fn render(
        self,
        http_status: StatusCode,
        format: HealthFormat,
    ) -> Response<RespBody> {
        match format {
            HealthFormat::Json => json_response(http_status, self),
            HealthFormat::Text => text_response(http_status, self.agent_text_token()),
        }
    }

    /// Status tokens must stay in lockstep with `proxy_text_token` in
    /// `huginn-proxy-lib` (`HEALTHY` / `ALIVE` / `SERVING` / `NOT_FOUND` / `ERROR`).
    /// `NotReady` tokens differ per process (`PINS_MISSING` / `NOCAPTURE` vs
    /// `STARTING` / `DRAINING` / `NOCAPTURE`).
    pub(crate) fn agent_text_token(&self) -> &'static str {
        match self.status {
            Status::Healthy => "HEALTHY",
            Status::Alive => "ALIVE",
            Status::Serving => "SERVING",
            Status::NotReady => match self.reason {
                Some(reason) => reason.text_token(),
                None => "ERROR",
            },
            Status::NotFound => "NOT_FOUND",
            Status::Error => "ERROR",
        }
    }
}
