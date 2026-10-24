//! Deterministic OpenAI-compatible model server for the browser end-to-end
//! tests (`e2e/`). Loopback only, no model weights, no network.
//!
//!   cargo run -p cg-researcher --example mock_llm -- 127.0.0.1:11434
//!
//! * `GET  /v1/models`            -> one model, `qwen3:8b`
//! * `POST /v1/embeddings`        -> 16-dim vectors derived from input length
//! * `POST /v1/chat/completions`  -> "MOCK ANSWER: saw N chars; attachment=…"
//!   (JSON, or server-sent events when the request has `"stream": true`);
//!   a request containing `SLOW` waits 2 s first (busy-state tests)

use std::net::SocketAddr;

use axum::Router;
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde_json::{Value, json};

async fn models() -> Response {
    axum::Json(json!({"data":[{"id":"qwen3:8b"}]})).into_response()
}

async fn embeddings(axum::Json(req): axum::Json<Value>) -> Response {
    let inputs: Vec<String> = match &req["input"] {
        Value::Array(a) => a
            .iter()
            .map(|v| v.as_str().unwrap_or("").to_owned())
            .collect(),
        v => vec![v.as_str().unwrap_or("").to_owned()],
    };
    let data: Vec<Value> = inputs
        .iter()
        .enumerate()
        .map(|(i, t)| {
            let e: Vec<f32> = (0..16).map(|k| ((t.len() + k) % 7) as f32).collect();
            json!({"index": i, "embedding": e})
        })
        .collect();
    axum::Json(json!({ "data": data })).into_response()
}

async fn chat(axum::Json(req): axum::Json<Value>) -> Response {
    let dump = req.to_string();
    if dump.contains("SLOW") {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }
    let last = &req["messages"]
        .as_array()
        .and_then(|m| m.last())
        .cloned()
        .unwrap_or_default()["content"];
    let n = match last {
        Value::String(s) => s.chars().count(),
        other => other.to_string().chars().count(),
    };
    let answer = format!(
        "MOCK ANSWER: saw {n} chars; attachment={}.",
        if dump.contains("ATTACH-OK") {
            "True"
        } else {
            "False"
        }
    );
    if req["stream"] != json!(true) {
        return axum::Json(json!({"model":"qwen3:8b","choices":[{"message":{"role":"assistant","content":answer}}]}))
            .into_response();
    }
    let mut body = String::new();
    for w in answer.split_inclusive(' ') {
        let ev = json!({"model":"qwen3:8b","choices":[{"delta":{"content":w}}]});
        body.push_str(&format!("data: {ev}\n\n"));
    }
    body.push_str("data: [DONE]\n\n");
    ([(header::CONTENT_TYPE, "text/event-stream")], body).into_response()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let addr: SocketAddr = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:11434".into())
        .parse()?;
    anyhow::ensure!(addr.ip().is_loopback(), "mock_llm binds loopback only");
    let app = Router::new()
        .route("/v1/models", get(models))
        .route("/v1/embeddings", post(embeddings))
        .route("/v1/chat/completions", post(chat));
    let l = tokio::net::TcpListener::bind(addr).await?;
    eprintln!("mock_llm on http://{addr}/v1");
    axum::serve(l, app).await?;
    Ok(())
}
