//! Loopback HTTP API and the local web UI.
//!
//! * Bearer auth (API key, or a short-lived UI session) with constant-time
//!   compare; global rate limit; body cap (413 when exceeded).
//! * Host-header allowlist (127.0.0.1 / localhost / [::1]) against DNS
//!   rebinding; foreign `Origin` headers are refused.
//! * Strict CSP, nosniff, no-referrer, no-store, frame-ancestors none. The UI
//!   ships as static files compiled into the binary; no inline script.
//! * No CORS headers, no telemetry. HTTP turns can never approve write tools
//!   (the confirmer is `DenyAll`); the UI cannot change bind address,
//!   loopback rules, write approval or connectors (settings whitelist).

// Handlers short-circuit with `Result<_, Response>` (idiomatic axum); the
// error path is cold, so boxing would only add noise.
#![allow(clippy::result_large_err)]

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use cg_core::agent::TurnRequest;
use cg_core::external::Provider;
use cg_core::tools::{DenyAll, Origin};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::Mutex;

use crate::runtime::{AgentSlot, Control, current};

const SESSION_TTL: Duration = Duration::from_secs(12 * 3600);
const PAIR_TTL: Duration = Duration::from_secs(120);
const MAX_SESSIONS: usize = 8;

pub const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; \
connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";

const INDEX_HTML: &str = include_str!("../ui/index.html");
const APP_JS: &str = include_str!("../ui/app.js");
const APP_CSS: &str = include_str!("../ui/app.css");

pub struct AppState {
    pub slot: Arc<AgentSlot>,
    pub control: Arc<Control>,
    pub api_key: String,
    pub limit_per_min: usize,
    pub recent: Mutex<VecDeque<Instant>>,
    /// UI session tokens (memory only; restart logs the UI out).
    pub sessions: Mutex<Vec<(String, Instant)>>,
    /// Single-use pairing tokens minted by `cg-researcher ui`.
    pub pairing: Mutex<Vec<(String, Instant)>>,
    /// Client nonce, server challenge and expiry for local CLI authentication.
    pub challenges: Mutex<Vec<(String, String, Instant)>>,
}

impl AppState {
    pub fn new(
        slot: Arc<AgentSlot>,
        control: Arc<Control>,
        api_key: String,
        limit_per_min: usize,
    ) -> Self {
        Self {
            slot,
            control,
            api_key,
            limit_per_min,
            recent: Mutex::default(),
            sessions: Mutex::default(),
            pairing: Mutex::default(),
            challenges: Mutex::default(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryBody {
    pub query: String,
    #[serde(default)]
    pub confirm_online: Option<bool>,
    /// Explicitly route this one message to the external model.
    #[serde(default)]
    pub prefer_external: bool,
    #[serde(default)]
    pub attachments: Vec<AttachmentBody>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttachmentBody {
    pub name: String,
    pub data_base64: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SettingsBody {
    set: serde_json::Map<String, Value>,
    #[serde(default)]
    ack_relax: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyBody {
    provider: String,
    #[serde(default)]
    key: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PairBody {
    pair: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChallengeBody {
    nonce: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalPairBody {
    nonce: String,
    challenge: String,
    proof: String,
}

/// Separate labels prevent a server proof from serving as client authentication.
pub fn pairing_proof(key: &str, side: &str, nonce: &str, challenge: &str) -> String {
    use hmac::{Hmac, KeyInit, Mac};
    let mut mac =
        Hmac::<sha2::Sha256>::new_from_slice(key.as_bytes()).expect("HMAC accepts any key length");
    mac.update(b"cg-researcher-ui-pair-v1:");
    mac.update(side.as_bytes());
    mac.update(nonce.as_bytes());
    mac.update(challenge.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

fn is_token(t: &str) -> bool {
    t.len() == 64 && t.bytes().all(|b| b.is_ascii_hexdigit())
}

pub fn router(state: Arc<AppState>, max_body: usize) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/app.js", get(app_js))
        .route("/app.css", get(app_css))
        // Browsers request this unprompted; answer quietly instead of 404 noise.
        .route("/favicon.ico", get(|| async { StatusCode::NO_CONTENT }))
        .route("/health", get(health))
        .route("/query", post(query))
        .route("/query/stream", post(query_stream))
        .route("/tools", get(tools))
        .route("/api/pair", post(pair))
        .route("/api/pair/challenge", post(pair_challenge))
        .route("/api/pair/local", post(pair_local))
        .route("/api/session", post(session))
        .route("/api/status", get(status))
        .route("/api/models", get(models))
        .route("/api/settings", post(settings))
        .route("/api/autotune", post(autotune))
        .route("/api/reindex", post(reindex))
        .route("/api/keys", post(set_key))
        .route("/api/keys/delete", post(delete_key))
        .route("/api/audit/verify", get(audit_verify))
        .layer(DefaultBodyLimit::max(max_body))
        .layer(middleware::from_fn(guard))
        .with_state(state)
}

fn err(code: StatusCode, msg: &str) -> Response {
    (code, Json(json!({"error": msg}))).into_response()
}

// ------------------------------------------------------------ middleware

pub fn host_allowed(h: &HeaderMap) -> bool {
    let Some(host) = h.get(header::HOST).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let name = if let Some(rest) = host.strip_prefix('[') {
        rest.split(']').next().map(|n| format!("[{n}]"))
    } else {
        host.split(':').next().map(str::to_string)
    };
    matches!(
        name.as_deref(),
        Some("127.0.0.1") | Some("localhost") | Some("[::1]")
    )
}

fn origin_allowed(h: &HeaderMap) -> bool {
    match h.get(header::ORIGIN).and_then(|v| v.to_str().ok()) {
        None => true,
        Some(o) => url::Url::parse(o)
            .ok()
            .is_some_and(|u| cg_core::egress::is_loopback_url(&u)),
    }
}

async fn guard(req: Request, next: Next) -> Response {
    let mut resp = if !host_allowed(req.headers()) {
        err(StatusCode::MISDIRECTED_REQUEST, "host not allowed")
    } else if !origin_allowed(req.headers()) {
        err(StatusCode::FORBIDDEN, "cross-origin request refused")
    } else {
        next.run(req).await
    };
    let h = resp.headers_mut();
    for (k, v) in [
        ("content-security-policy", CSP),
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "no-referrer"),
        ("cache-control", "no-store"),
        ("x-frame-options", "DENY"),
        ("cross-origin-opener-policy", "same-origin"),
        ("cross-origin-resource-policy", "same-origin"),
        (
            "permissions-policy",
            "camera=(), microphone=(), geolocation=(), interest-cohort=()",
        ),
    ] {
        h.insert(k, HeaderValue::from_static(v));
    }
    resp
}

// ------------------------------------------------------------ auth

fn bearer(h: &HeaderMap) -> Option<&str> {
    h.get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
}

fn ct_eq(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq;
    a.len() == b.len() && bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

async fn authorized(s: &AppState, h: &HeaderMap, allow_session: bool) -> bool {
    let Some(tok) = bearer(h) else {
        return false;
    };
    if ct_eq(tok, &s.api_key) {
        return true;
    }
    if !allow_session {
        return false;
    }
    let now = Instant::now();
    let mut sess = s.sessions.lock().await;
    sess.retain(|(_, exp)| *exp > now);
    // Compare against every live session so timing does not reveal which.
    sess.iter().fold(false, |hit, (t, _)| hit | ct_eq(tok, t))
}

async fn rate_ok(s: &AppState) -> bool {
    let mut r = s.recent.lock().await;
    let now = Instant::now();
    while r
        .front()
        .is_some_and(|t| now.duration_since(*t) > Duration::from_secs(60))
    {
        r.pop_front();
    }
    if r.len() >= s.limit_per_min {
        return false;
    }
    r.push_back(now);
    true
}

async fn gate(s: &AppState, h: &HeaderMap) -> Result<(), Response> {
    gate_with(s, h, true).await
}

async fn gate_with(s: &AppState, h: &HeaderMap, allow_session: bool) -> Result<(), Response> {
    if !authorized(s, h, allow_session).await {
        return Err(err(
            StatusCode::UNAUTHORIZED,
            "missing or invalid bearer token",
        ));
    }
    if !rate_ok(s).await {
        return Err(err(StatusCode::TOO_MANY_REQUESTS, "rate limited"));
    }
    Ok(())
}

fn random_token() -> Result<String, Response> {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).map_err(|_| err(StatusCode::INTERNAL_SERVER_ERROR, "no randomness"))?;
    Ok(hex::encode(b))
}

fn json_body<T>(
    body: Result<Json<T>, axum::extract::rejection::JsonRejection>,
) -> Result<T, Response> {
    match body {
        Ok(Json(b)) => Ok(b),
        // 413 for oversized bodies, 415 for wrong content type, 400/422 otherwise.
        Err(e) => Err(err(e.status(), "invalid request body")),
    }
}

// ------------------------------------------------------------ static UI

fn static_file(ct: &'static str, body: &'static str) -> Response {
    ([(header::CONTENT_TYPE, ct)], body).into_response()
}
async fn index() -> Response {
    static_file("text/html; charset=utf-8", INDEX_HTML)
}
async fn app_js() -> Response {
    static_file("text/javascript; charset=utf-8", APP_JS)
}
async fn app_css() -> Response {
    static_file("text/css; charset=utf-8", APP_CSS)
}

// ------------------------------------------------------------ pairing

/// API-key holders (scripts, curl) mint a single-use pairing token with the
/// bearer key. The `cg-researcher ui` command uses the key-less challenge /
/// proof pair below instead. Only the dead-on-use token ever appears in a URL.
async fn pair(State(s): State<Arc<AppState>>, h: HeaderMap) -> Response {
    if let Err(r) = gate_with(&s, &h, false).await {
        return r;
    }
    mint_pair(&s).await
}

async fn pair_challenge(
    State(s): State<Arc<AppState>>,
    body: Result<Json<ChallengeBody>, axum::extract::rejection::JsonRejection>,
) -> Response {
    if !rate_ok(&s).await {
        return err(StatusCode::TOO_MANY_REQUESTS, "rate limited");
    }
    let b = match json_body(body) {
        Ok(b) if is_token(&b.nonce) => b,
        _ => return err(StatusCode::BAD_REQUEST, "invalid nonce"),
    };
    let challenge = match random_token() {
        Ok(t) => t,
        Err(r) => return r,
    };
    let proof = pairing_proof(&s.api_key, "server", &b.nonce, &challenge);
    let now = Instant::now();
    let mut pending = s.challenges.lock().await;
    pending.retain(|(_, _, exp)| *exp > now);
    if pending.len() >= 4 {
        pending.remove(0);
    }
    pending.push((b.nonce, challenge.clone(), now + PAIR_TTL));
    Json(json!({"challenge": challenge, "proof": proof})).into_response()
}

async fn pair_local(
    State(s): State<Arc<AppState>>,
    body: Result<Json<LocalPairBody>, axum::extract::rejection::JsonRejection>,
) -> Response {
    if !rate_ok(&s).await {
        return err(StatusCode::TOO_MANY_REQUESTS, "rate limited");
    }
    let b = match json_body(body) {
        Ok(b) if is_token(&b.nonce) && is_token(&b.challenge) && is_token(&b.proof) => b,
        _ => return err(StatusCode::BAD_REQUEST, "invalid pairing proof"),
    };
    let expected = pairing_proof(&s.api_key, "client", &b.nonce, &b.challenge);
    if !ct_eq(&expected, &b.proof) {
        return err(StatusCode::UNAUTHORIZED, "invalid pairing proof");
    }
    let found = {
        let mut pending = s.challenges.lock().await;
        pending.retain(|(_, _, exp)| *exp > Instant::now());
        pending
            .iter()
            .position(|(n, c, _)| n == &b.nonce && c == &b.challenge)
            .map(|i| pending.remove(i))
            .is_some()
    };
    if !found {
        return err(StatusCode::UNAUTHORIZED, "challenge invalid or expired");
    }
    mint_pair(&s).await
}

async fn mint_pair(s: &AppState) -> Response {
    let tok = match random_token() {
        Ok(t) => t,
        Err(r) => return r,
    };
    let now = Instant::now();
    let mut p = s.pairing.lock().await;
    p.retain(|(_, exp)| *exp > now);
    if p.len() >= 4 {
        p.remove(0);
    }
    p.push((tok.clone(), now + PAIR_TTL));
    Json(json!({"pair": tok, "ttl_secs": PAIR_TTL.as_secs()})).into_response()
}

async fn session(
    State(s): State<Arc<AppState>>,
    body: Result<Json<PairBody>, axum::extract::rejection::JsonRejection>,
) -> Response {
    if !rate_ok(&s).await {
        return err(StatusCode::TOO_MANY_REQUESTS, "rate limited");
    }
    let b = match json_body(body) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let now = Instant::now();
    let found = {
        let mut p = s.pairing.lock().await;
        p.retain(|(_, exp)| *exp > now);
        let idx = p.iter().position(|(t, _)| ct_eq(t, &b.pair));
        idx.map(|i| p.remove(i)).is_some() // single use
    };
    if !found {
        return err(StatusCode::UNAUTHORIZED, "pairing code invalid or expired");
    }
    let tok = match random_token() {
        Ok(t) => t,
        Err(r) => return r,
    };
    let mut sess = s.sessions.lock().await;
    sess.retain(|(_, exp)| *exp > now);
    if sess.len() >= MAX_SESSIONS {
        sess.remove(0);
    }
    sess.push((tok.clone(), now + SESSION_TTL));
    s.control
        .event("ui_session", format!("sessions={}", sess.len()));
    Json(json!({"session": tok, "ttl_secs": SESSION_TTL.as_secs()})).into_response()
}

// ------------------------------------------------------------ API

async fn health(State(s): State<Arc<AppState>>) -> Response {
    let agent = current(&s.slot).await;
    Json(json!({"ok": true, "local_model": agent.local_healthy().await})).into_response()
}

async fn tools(State(s): State<Arc<AppState>>, h: HeaderMap) -> Response {
    if let Err(r) = gate(&s, &h).await {
        return r;
    }
    let agent = current(&s.slot).await;
    let t: Vec<_> = agent
        .tool_specs()
        .iter()
        .map(|t| json!({"name": t.name, "write": t.effect == cg_core::tools::Effect::Write, "untrusted": t.untrusted_output}))
        .collect();
    Json(json!({"tools": t, "graph": agent.graph_nodes()})).into_response()
}

async fn key_configured(s: &AppState, r: &str) -> bool {
    !r.is_empty() && s.control.secrets.resolve(r).await.is_ok()
}

async fn status(State(s): State<Arc<AppState>>, h: HeaderMap) -> Response {
    if let Err(r) = gate(&s, &h).await {
        return r;
    }
    let agent = current(&s.slot).await;
    let c = agent.config();
    let (lp, lt) = agent.local_tuning();
    let ext = agent.external_tuning().await;
    let used = cg_core::external::budget_use();
    Json(json!({
        "mode": if c.app.mode == cg_core::config::Mode::Hybrid { "hybrid" } else { "offline" },
        "local": {
            "provider": c.llm.provider, "base_url": c.llm.base_url, "model": c.llm.model,
            "vision_model": c.llm.vision_model, "healthy": agent.local_healthy().await,
            "profile": lp, "tuning": lt,
        },
        "external": {
            "enabled": c.external.enabled, "built": agent.has_external(),
            "provider": c.external.provider.name(), "model": c.external.effective_model(),
            "xai_region": c.external.xai_region,
            "label": agent.external_label(),
            "profile": ext.as_ref().map(|e| &e.0), "tuning": ext.as_ref().map(|e| &e.1),
            "rules": {
                "send_local_context": c.external.rules.send_local_context,
                "allow_telegram": c.external.rules.allow_telegram,
                "allow_images": c.external.rules.allow_images,
                "allow_attachment_text": c.external.rules.allow_attachment_text,
                "max_calls_per_hour": c.external.rules.max_calls_per_hour,
                "max_calls_per_day": c.external.rules.max_calls_per_day,
                "max_output_tokens": c.external.rules.max_output_tokens,
                "temperature": c.external.rules.temperature,
                "max_outbound_chars": c.external.rules.max_outbound_chars,
            },
            "budget_used": {"last_hour": used.last_hour, "last_day": used.last_day},
            // Only ever whether a key resolves; never the value or its prefix.
            "keys": {
                "anthropic": key_configured(&s, &c.external.anthropic_key_ref).await,
                "xai": key_configured(&s, &c.external.xai_key_ref).await,
            },
        },
        "tools": agent.tool_specs().iter().map(|t| json!({"name": t.name, "write": t.effect == cg_core::tools::Effect::Write})).collect::<Vec<_>>(),
        "graph": agent.graph_nodes(),
        "graph_edges": agent.graph_edges().into_iter().map(|(n, to)| json!({"node": n, "to": to})).collect::<Vec<_>>(),
        "indexed_chunks": agent.indexed_chunks(),
        "corpus_dir": agent.corpus_dir().display().to_string(),
        "attachments": json!({"max_bytes": c.attachments.max_bytes, "max_per_turn": c.attachments.max_per_turn}),
        "http_can_approve_writes": false,
    }))
    .into_response()
}

async fn models(State(s): State<Arc<AppState>>, h: HeaderMap) -> Response {
    if let Err(r) = gate(&s, &h).await {
        return r;
    }
    let agent = current(&s.slot).await;
    let (external, external_error) = match agent.external_models().await {
        Ok(v) => (v, None),
        Err(e) => (Vec::new(), Some(e.to_string())),
    };
    Json(json!({
        "local": agent.local_models().await,
        "external": external,
        "external_error": external_error,
        "external_defaults": {
            "anthropic": Provider::Anthropic.default_model(),
            "xai": Provider::Xai.default_model(),
        },
    }))
    .into_response()
}

fn to_toml(v: &Value) -> Option<toml::Value> {
    Some(match v {
        Value::Bool(b) => toml::Value::Boolean(*b),
        Value::String(s) => toml::Value::String(s.clone()),
        Value::Number(n) if n.is_i64() => toml::Value::Integer(n.as_i64()?),
        Value::Number(n) => toml::Value::Float(n.as_f64()?),
        _ => return None,
    })
}

/// Apply `changes` to the overlay, validate, require an ack for anything
/// that loosens policy, persist, rebuild and swap the agent.
async fn apply_settings(
    s: &AppState,
    changes: &serde_json::Map<String, Value>,
    ack_relax: bool,
) -> Result<Value, Response> {
    let _guard = s.control.lock.lock().await;
    let path = s.control.layout.settings();
    let mut overlay = cg_core::settings::read(&path)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    for (k, v) in changes {
        let tv =
            to_toml(v).ok_or_else(|| err(StatusCode::BAD_REQUEST, "unsupported value type"))?;
        cg_core::settings::set(&mut overlay, k, tv)
            .map_err(|e| err(StatusCode::BAD_REQUEST, &e.to_string()))?;
    }
    // Validate the merged result before anything is written.
    let tmp = path.with_extension("toml.check");
    cg_core::settings::write(&tmp, &overlay)
        .map_err(|e| err(StatusCode::BAD_REQUEST, &e.to_string()))?;
    let new_cfg = s.control.load_config(&tmp);
    let _ = std::fs::remove_file(&tmp);
    let new_cfg = new_cfg.map_err(|e| err(StatusCode::BAD_REQUEST, &e.to_string()))?;
    let old = current(&s.slot).await;
    let relax = cg_core::settings::relaxations(old.config(), &new_cfg);
    if !relax.is_empty() && !ack_relax {
        return Err((
            StatusCode::CONFLICT,
            Json(json!({"error": "this change loosens policy; resend with ack_relax", "relaxations": relax})),
        )
            .into_response());
    }
    // Build first; persist only if the new agent comes up.
    let agent = s.control.build(new_cfg).await.map_err(|e| {
        err(
            StatusCode::BAD_REQUEST,
            &cg_core::sanitizer::redact(&e.to_string()),
        )
    })?;
    // I8: a relaxation is recorded before it takes effect. If the audit
    // append fails, the change is not applied.
    if !relax.is_empty() {
        s.control
            .try_event("policy_relaxed", format!("{relax:?}"))
            .map_err(|e| {
                err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("audit append failed, change not applied: {e}"),
                )
            })?;
    }
    cg_core::settings::write(&path, &overlay)
        .map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))?;
    *s.slot.write().await = agent.clone();
    let keys: Vec<&String> = changes.keys().collect();
    s.control
        .event("settings_changed", format!("keys={keys:?}"));
    let (lp, lt) = agent.local_tuning();
    Ok(json!({
        "ok": true, "relaxations": relax,
        "local": {"profile": lp, "tuning": lt},
        "external": agent.external_tuning().await.map(|(p, t)| json!({"profile": p, "tuning": t})),
    }))
}

async fn settings(
    State(s): State<Arc<AppState>>,
    h: HeaderMap,
    body: Result<Json<SettingsBody>, axum::extract::rejection::JsonRejection>,
) -> Response {
    if let Err(r) = gate(&s, &h).await {
        return r;
    }
    let b = match json_body(body) {
        Ok(b) => b,
        Err(r) => return r,
    };
    if b.set.is_empty() || b.set.len() > 32 {
        return err(StatusCode::BAD_REQUEST, "set 1..=32 keys");
    }
    match apply_settings(&s, &b.set, b.ack_relax).await {
        Ok(v) => Json(v).into_response(),
        Err(r) => r,
    }
}

async fn autotune(State(s): State<Arc<AppState>>, h: HeaderMap) -> Response {
    if let Err(r) = gate(&s, &h).await {
        return r;
    }
    // Rebuild from the current config: re-probes local and external.
    let _guard = s.control.lock.lock().await;
    let cfg = current(&s.slot).await.config().clone();
    match s.control.build(cfg).await {
        Ok(agent) => {
            *s.slot.write().await = agent.clone();
            let (lp, lt) = agent.local_tuning();
            Json(json!({"ok": true, "local": {"profile": lp, "tuning": lt},
                "external": agent.external_tuning().await.map(|(p, t)| json!({"profile": p, "tuning": t}))}))
            .into_response()
        }
        Err(e) => err(
            StatusCode::BAD_GATEWAY,
            &cg_core::sanitizer::redact(&e.to_string()),
        ),
    }
}

/// Rebuild the RAG index from the corpus directory (same as `cg-researcher index`).
/// Serialized with settings changes; the running agent picks up the new index.
async fn reindex(State(s): State<Arc<AppState>>, h: HeaderMap) -> Response {
    if let Err(r) = gate(&s, &h).await {
        return r;
    }
    let _guard = s.control.lock.lock().await;
    let agent = current(&s.slot).await;
    match agent.reindex().await {
        Ok((files, chunks, embedded)) => Json(json!({
            "ok": true, "files": files, "chunks": chunks, "embedded": embedded,
        }))
        .into_response(),
        Err(e) => err(
            StatusCode::INTERNAL_SERVER_ERROR,
            &cg_core::sanitizer::redact(&e.to_string()),
        ),
    }
}

fn provider_of(name: &str) -> Result<(Provider, &'static str, &'static str), Response> {
    match Provider::parse(name) {
        Some(Provider::Anthropic) => Ok((
            Provider::Anthropic,
            "anthropic_api_key",
            "external.anthropic_key_ref",
        )),
        Some(Provider::Xai) => Ok((Provider::Xai, "xai_api_key", "external.xai_key_ref")),
        None => Err(err(
            StatusCode::BAD_REQUEST,
            "provider must be anthropic or xai",
        )),
    }
}

async fn set_key(
    State(s): State<Arc<AppState>>,
    h: HeaderMap,
    body: Result<Json<KeyBody>, axum::extract::rejection::JsonRejection>,
) -> Response {
    if let Err(r) = gate(&s, &h).await {
        return r;
    }
    let b = match json_body(body) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let (p, name, dotted) = match provider_of(&b.provider) {
        Ok(x) => x,
        Err(r) => return r,
    };
    let key = b.key.trim();
    if let Err(msg) = cg_core::external::validate_key(p, key) {
        return err(StatusCode::BAD_REQUEST, msg);
    }
    // Registers with the redactor before anything else can echo it.
    let reference = match s.control.secrets.store(name, key).await {
        Ok(r) => r,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()),
    };
    s.control.event(
        "secret_stored",
        format!(
            "provider={} backend={}",
            p.name(),
            reference.split(':').next().unwrap_or("")
        ),
    );
    let mut changes = serde_json::Map::new();
    changes.insert(dotted.into(), Value::String(reference.clone()));
    match apply_settings(&s, &changes, false).await {
        Ok(_) => Json(json!({"ok": true, "configured": true,
            "backend": reference.split(':').next().unwrap_or("")}))
        .into_response(),
        Err(r) => r,
    }
}

async fn delete_key(
    State(s): State<Arc<AppState>>,
    h: HeaderMap,
    body: Result<Json<KeyBody>, axum::extract::rejection::JsonRejection>,
) -> Response {
    if let Err(r) = gate(&s, &h).await {
        return r;
    }
    let b = match json_body(body) {
        Ok(b) => b,
        Err(r) => return r,
    };
    let (p, name, _) = match provider_of(&b.provider) {
        Ok(x) => x,
        Err(r) => return r,
    };
    if let Err(e) = s.control.secrets.delete(name).await {
        return err(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string());
    }
    s.control
        .event("secret_deleted", format!("provider={}", p.name()));
    // If this was the active provider, persistently disable external so the
    // next start does not fail on a missing key. Tightening needs no ack.
    let active = current(&s.slot).await.config().external.provider == p;
    if active {
        let mut changes = serde_json::Map::new();
        changes.insert("external.enabled".into(), Value::Bool(false));
        if let Err(r) = apply_settings(&s, &changes, false).await {
            return r;
        }
    }
    Json(json!({"ok": true, "configured": false, "external_disabled": active})).into_response()
}

async fn audit_verify(State(s): State<Arc<AppState>>, h: HeaderMap) -> Response {
    if let Err(r) = gate(&s, &h).await {
        return r;
    }
    match s.control.audit.verify_now() {
        Ok(n) => Json(json!({"ok": true, "records": n})).into_response(),
        Err(e) => Json(json!({"ok": false, "error": e.to_string()})).into_response(),
    }
}

/// Shared request preparation for `/query` and `/query/stream`.
async fn prepare_query(
    s: &AppState,
    h: &HeaderMap,
    body: Result<Json<QueryBody>, axum::extract::rejection::JsonRejection>,
) -> Result<(Arc<cg_core::agent::Agent>, TurnRequest), Response> {
    gate(s, h).await?;
    let b = json_body(body)?;
    let agent = current(&s.slot).await;
    let lim = &agent.config().attachments;
    if b.attachments.len() > lim.max_per_turn {
        return Err(err(StatusCode::BAD_REQUEST, "too many attachments"));
    }
    let mut atts = Vec::new();
    for a in &b.attachments {
        let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(a.data_base64.as_bytes())
        else {
            return Err(err(StatusCode::BAD_REQUEST, "attachment is not base64"));
        };
        match cg_core::attachments::parse(&a.name, &bytes, lim) {
            Ok(x) => atts.push(x),
            Err(e) => return Err(err(StatusCode::UNPROCESSABLE_ENTITY, &e.to_string())),
        }
    }
    let req = TurnRequest {
        query: b.query,
        origin: Origin::Http,
        sender: "http".into(),
        attachments: atts,
        confirm_online: b.confirm_online,
        prefer_external: b.prefer_external,
        confirmer: Arc::new(DenyAll),
    };
    Ok((agent, req))
}

fn turn_json(agent: &cg_core::agent::Agent, r: &cg_core::agent::TurnResult) -> Value {
    json!({
        "answer": r.answer, "answer_model": r.answer_model, "needs_confirm": r.needs_confirm,
        "external_label": agent.external_label(),
        "blocked": r.blocked, "tainted": r.tainted, "path": r.path, "sources": r.sources,
        "tools": r.tools.iter().map(|(t, d)| json!({"tool": t, "decision": d})).collect::<Vec<_>>()
    })
}

async fn query(
    State(s): State<Arc<AppState>>,
    h: HeaderMap,
    body: Result<Json<QueryBody>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let (agent, req) = match prepare_query(&s, &h, body).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    let r = agent.run(req).await;
    Json(turn_json(&agent, &r)).into_response()
}

/// Server-sent events: `delta` {text} (guarded provisional local-model
/// text), `reset` (discard provisional text; a tool round started), then
/// exactly one `final` (same JSON as `/query`, authoritative) or `error`.
/// The turn runs in its own task, so a client disconnect never skips the
/// audit record.
async fn query_stream(
    State(s): State<Arc<AppState>>,
    h: HeaderMap,
    body: Result<Json<QueryBody>, axum::extract::rejection::JsonRejection>,
) -> Response {
    use axum::response::sse::{Event, KeepAlive, Sse};
    use cg_core::stream::StreamEvent;

    let (agent, req) = match prepare_query(&s, &h, body).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<StreamEvent>();
    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<Value>();
    tokio::spawn(async move {
        let r = agent.run_streaming(req, tx).await;
        let _ = done_tx.send(turn_json(&agent, &r));
    });
    struct St {
        rx: Option<tokio::sync::mpsc::UnboundedReceiver<StreamEvent>>,
        done: Option<tokio::sync::oneshot::Receiver<Value>>,
    }
    let init = St {
        rx: Some(rx),
        done: Some(done_rx),
    };
    let events = futures_util::stream::unfold(init, |mut st| async move {
        if let Some(rx) = st.rx.as_mut() {
            match rx.recv().await {
                Some(StreamEvent::Delta(t)) => {
                    let ev = Event::default()
                        .event("delta")
                        .data(json!({"text": t}).to_string());
                    return Some((Ok::<_, std::convert::Infallible>(ev), st));
                }
                Some(StreamEvent::Reset) => {
                    let ev = Event::default().event("reset").data("{}");
                    return Some((Ok(ev), st));
                }
                None => st.rx = None, // turn finished; fall through to final
            }
        }
        let done = st.done.take()?;
        let ev = match done.await {
            Ok(v) => Event::default().event("final").data(v.to_string()),
            Err(_) => Event::default()
                .event("error")
                .data(json!({"error": "turn failed"}).to_string()),
        };
        Some((Ok(ev), st))
    });
    Sse::new(events)
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
        .into_response()
}

pub async fn serve(state: Arc<AppState>, addr: SocketAddr, max_body: usize) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("listening on http://{addr} (bearer auth required; UI: `cg-researcher ui`)");
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
