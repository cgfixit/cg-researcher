//! Loopback HTTP API. Bearer key (constant-time compare), body cap, global
//! rate limit, no CORS headers (browsers on other origins cannot read
//! responses), no telemetry. HTTP turns cannot approve write tools.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{DefaultBodyLimit, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use cg_core::agent::{Agent, TurnRequest};
use cg_core::tools::{DenyAll, Origin};
use serde::Deserialize;
use serde_json::json;
use tokio::sync::Mutex;

pub struct AppState {
    pub agent: Arc<Agent>,
    pub api_key: String,
    pub limit_per_min: usize,
    pub recent: Mutex<VecDeque<Instant>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryBody {
    pub query: String,
    #[serde(default)]
    pub confirm_online: Option<bool>,
    #[serde(default)]
    pub attachments: Vec<AttachmentBody>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttachmentBody {
    pub name: String,
    pub data_base64: String,
}

pub fn router(state: Arc<AppState>, max_body: usize) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/query", post(query))
        .route("/tools", get(tools))
        .layer(DefaultBodyLimit::max(max_body))
        .with_state(state)
}

fn err(code: StatusCode, msg: &str) -> Response {
    (code, Json(json!({"error": msg}))).into_response()
}

fn authorized(h: &HeaderMap, key: &str) -> bool {
    use subtle::ConstantTimeEq;
    let Some(v) = h.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let Some(tok) = v.strip_prefix("Bearer ") else {
        return false;
    };
    tok.len() == key.len() && bool::from(tok.as_bytes().ct_eq(key.as_bytes()))
}

async fn gate(s: &AppState, h: &HeaderMap) -> Result<(), (StatusCode, &'static str)> {
    if !authorized(h, &s.api_key) {
        return Err((StatusCode::UNAUTHORIZED, "missing or invalid bearer token"));
    }
    let mut r = s.recent.lock().await;
    let now = Instant::now();
    while r
        .front()
        .is_some_and(|t| now.duration_since(*t) > Duration::from_secs(60))
    {
        r.pop_front();
    }
    if r.len() >= s.limit_per_min {
        return Err((StatusCode::TOO_MANY_REQUESTS, "rate limited"));
    }
    r.push_back(now);
    Ok(())
}

async fn health(State(s): State<Arc<AppState>>) -> Response {
    Json(json!({"ok": true, "local_model": s.agent.local_healthy().await})).into_response()
}

async fn tools(State(s): State<Arc<AppState>>, h: HeaderMap) -> Response {
    if let Err((code, msg)) = gate(&s, &h).await {
        return err(code, msg);
    }
    let t: Vec<_> = s
        .agent
        .tool_specs()
        .iter()
        .map(|t| json!({"name": t.name, "write": t.effect == cg_core::tools::Effect::Write, "untrusted": t.untrusted_output}))
        .collect();
    Json(json!({"tools": t, "graph": s.agent.graph_nodes()})).into_response()
}

async fn query(
    State(s): State<Arc<AppState>>,
    h: HeaderMap,
    body: Result<Json<QueryBody>, axum::extract::rejection::JsonRejection>,
) -> Response {
    if let Err((code, msg)) = gate(&s, &h).await {
        return err(code, msg);
    }
    let Ok(Json(b)) = body else {
        return err(StatusCode::BAD_REQUEST, "invalid JSON body");
    };
    let lim = &s.agent.config().attachments;
    if b.attachments.len() > lim.max_per_turn {
        return err(StatusCode::BAD_REQUEST, "too many attachments");
    }
    let mut atts = Vec::new();
    for a in &b.attachments {
        let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(a.data_base64.as_bytes())
        else {
            return err(StatusCode::BAD_REQUEST, "attachment is not base64");
        };
        match cg_core::attachments::parse(&a.name, &bytes, lim) {
            Ok(x) => atts.push(x),
            Err(e) => return err(StatusCode::UNPROCESSABLE_ENTITY, &e.to_string()),
        }
    }
    let r = s
        .agent
        .run(TurnRequest {
            query: b.query,
            origin: Origin::Http,
            sender: "http".into(),
            attachments: atts,
            confirm_online: b.confirm_online,
            confirmer: Arc::new(DenyAll),
        })
        .await;
    Json(json!({
        "answer": r.answer, "answer_model": r.answer_model, "needs_confirm": r.needs_confirm,
        "blocked": r.blocked, "tainted": r.tainted, "path": r.path, "sources": r.sources,
        "tools": r.tools.iter().map(|(t, d)| json!({"tool": t, "decision": d})).collect::<Vec<_>>()
    }))
    .into_response()
}

pub async fn serve(state: Arc<AppState>, addr: SocketAddr, max_body: usize) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("listening on http://{addr} (bearer auth required)");
    axum::serve(listener, router(state, max_body))
        .with_graceful_shutdown(shutdown())
        .await?;
    Ok(())
}

pub async fn shutdown() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! { _ = ctrl_c => {}, _ = term => {} }
}
