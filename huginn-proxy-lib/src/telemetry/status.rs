use crate::config::HealthFormat;
use crate::telemetry::readiness::NotReadyReason;
use crate::utils::http::{json_response, text_response, RespBody};
use hyper::{Response, StatusCode};
use serde::Serialize;

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
            HealthFormat::Text => text_response(http_status, self.proxy_text_token()),
        }
    }

    /// Status tokens must stay in lockstep with `agent_text_token` in
    /// `huginn-ebpf-agent` (`HEALTHY` / `ALIVE` / `SERVING` / `NOT_FOUND` / `ERROR`).
    /// `NotReady` tokens differ per process (`STARTING` / `DRAINING` vs `PINS_MISSING`).
    pub(crate) fn proxy_text_token(&self) -> &'static str {
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
