use serde::Serialize;

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum NotReadyReason {
    PinsNotReady,
}

impl NotReadyReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PinsNotReady => "pins_not_ready",
        }
    }

    pub const fn text_token(self) -> &'static str {
        match self {
            Self::PinsNotReady => "PINS_MISSING",
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
