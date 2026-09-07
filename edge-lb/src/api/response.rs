use anyhow::Result;
use serde_json::{Value, json};
use tiny_http::{Header, Response};

pub(super) struct Reply {
    pub(super) status: u16,
    pub(super) content_type: String,
    pub(super) body: Vec<u8>,
}

impl Reply {
    pub(super) fn json(status: u16, value: Value) -> Self {
        Self {
            status,
            content_type: "application/json".into(),
            body: value.to_string().into_bytes(),
        }
    }

    pub(super) fn json_bytes(status: u16, body: Vec<u8>) -> Self {
        Self {
            status,
            content_type: "application/json".into(),
            body,
        }
    }

    pub(super) fn error(status: u16, msg: impl Into<String>) -> Self {
        Self::json(status, json!({ "error": msg.into() }))
    }
}

pub(super) fn respond(request: tiny_http::Request, reply: Reply) -> Result<()> {
    let header = Header::from_bytes("Content-Type", reply.content_type)
        .map_err(|e| anyhow::anyhow!("building header: {e:?}"))?;
    request
        .respond(
            Response::from_data(reply.body)
                .with_status_code(reply.status)
                .with_header(header),
        )
        .map_err(|e| anyhow::anyhow!("responding: {e}"))?;
    Ok(())
}
