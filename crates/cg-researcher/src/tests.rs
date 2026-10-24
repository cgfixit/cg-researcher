use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use crate::serve::{AppState, router};

async fn state(limit: usize) -> (Arc<AppState>, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tmp");
    let layout = cg_core::paths::Layout::new(dir.path());
    layout.ensure().expect("layout");
    let home = dir.path().to_string_lossy().into_owned();
    std::fs::write(
        layout.config(),
        format!(
            "[app]\nhome = \"{home}\"\n[llm]\nbase_url = \"http://127.0.0.1:9/v1\"\ntimeout_secs = 2\n"
        ),
    )
    .expect("cfg");
    let cfg = cg_core::config::Config::load(&layout.config()).expect("load");
    let key = cg_audit::load_or_create_key(&layout.audit_key()).expect("key");
    let audit = Arc::new(cg_audit::AuditLog::open(layout.audit_log(), &key).expect("audit"));
    // Never touch the real login keychain from tests.
    let secrets = cg_core::secrets::SecretStore::new(layout.secrets()).without_keychain_writes();
    let agent = cg_core::agent::Agent::new(cfg, Default::default(), audit.clone(), &secrets)
        .await
        .expect("agent");
    let control = Arc::new(crate::runtime::Control {
        layout,
        secrets,
        audit,
        lock: tokio::sync::Mutex::new(()),
    });
    (
        Arc::new(AppState::new(
            Arc::new(tokio::sync::RwLock::new(Arc::new(agent))),
            control,
            "k".repeat(64),
            limit,
        )),
        dir,
    )
}

fn bearer() -> String {
    format!("Bearer {}", "k".repeat(64))
}

fn q(auth: Option<&str>, body: &str) -> Request<Body> {
    post("/query", auth, body)
}

fn post(path: &str, auth: Option<&str>, body: &str) -> Request<Body> {
    let mut b = Request::post(path)
        .header("host", "127.0.0.1:8797")
        .header("content-type", "application/json");
    if let Some(a) = auth {
        b = b.header("authorization", a);
    }
    b.body(Body::from(body.to_string())).expect("req")
}

fn get(path: &str, auth: Option<&str>) -> Request<Body> {
    let mut b = Request::get(path).header("host", "127.0.0.1:8797");
    if let Some(a) = auth {
        b = b.header("authorization", a);
    }
    b.body(Body::empty()).expect("req")
}

async fn body_json(r: axum::response::Response) -> serde_json::Value {
    use http_body_util::BodyExt;
    let bytes = r.into_body().collect().await.expect("body").to_bytes();
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

#[tokio::test]
async fn auth_is_required_and_constant_shape() {
    let (s, _d) = state(60).await;
    let app = router(s, 1024);
    for auth in [
        None,
        Some("Bearer wrong"),
        Some(&*format!("Basic {}", "k".repeat(64))),
        Some(&*format!("Bearer {}x", "k".repeat(64))),
    ] {
        let r = app
            .clone()
            .oneshot(q(auth, r#"{"query":"hi"}"#))
            .await
            .expect("resp");
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "{auth:?}");
    }
    let r = app
        .clone()
        .oneshot(get("/tools", None))
        .await
        .expect("resp");
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn body_limit_unknown_fields_and_rate_limit() {
    let (s, _d) = state(2).await;
    let app = router(s, 256);
    let good = format!("Bearer {}", "k".repeat(64));
    let big = format!(r#"{{"query":"{}"}}"#, "a".repeat(1000));
    let r = app
        .clone()
        .oneshot(q(Some(&good), &big))
        .await
        .expect("resp");
    assert_eq!(
        r.status(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "oversized body is a 413, not a generic 400"
    );
    let r = app
        .clone()
        .oneshot(q(Some(&good), r#"{"query":"x","approve_writes":true}"#))
        .await
        .expect("resp");
    assert!(
        r.status().is_client_error() && r.status() != StatusCode::UNAUTHORIZED,
        "unknown fields refused: {}",
        r.status()
    );
    let r = app
        .clone()
        .oneshot(q(Some(&good), r#"{"query":"x"}"#))
        .await
        .expect("resp");
    assert_eq!(
        r.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "third authenticated request in a minute"
    );
}

#[test]
fn core_never_depends_on_connectors() {
    // I6: the core must not be able to call connector APIs directly.
    let core = include_str!("../../cg-core/Cargo.toml");
    let graph = include_str!("../../cg-graph/Cargo.toml");
    let audit = include_str!("../../cg-audit/Cargo.toml");
    for (name, t) in [("cg-core", core), ("cg-graph", graph), ("cg-audit", audit)] {
        assert!(
            !t.contains("cg-connectors"),
            "{name} must not depend on cg-connectors"
        );
        assert!(
            !t.contains("cg-researcher ") && !t.contains("cg-researcher="),
            "{name} must not depend on the binary"
        );
    }
    assert!(!graph.contains("cg-core"), "cg-graph stays policy-free");
}

#[test]
fn shipped_config_is_safe_by_default() {
    let cfg = cg_core::config::Config::from_toml(crate::DEFAULT_CONFIG).expect("parses");
    cfg.validate().expect("validates");
    assert_eq!(cfg.app.mode, cg_core::config::Mode::Offline);
    assert!(
        !cfg.external.enabled
            && !cfg.tools.auto_approve_writes
            && cfg.tools.remote_origins_read_only
    );
    assert_eq!(cfg.server.host, "127.0.0.1");
    for (name, v) in &cfg.connectors {
        assert_eq!(
            v.get("enabled").and_then(|e| e.as_bool()),
            Some(false),
            "{name} must ship disabled"
        );
    }
}

#[tokio::test]
async fn host_and_origin_checks_block_dns_rebinding() {
    let (s, _d) = state(60).await;
    let app = router(s, 4096);
    for host in [
        "evil.example",
        "127.0.0.1.evil.example:8797",
        "192.168.1.5:8797",
    ] {
        let r = app
            .clone()
            .oneshot(
                Request::get("/")
                    .header("host", host)
                    .body(Body::empty())
                    .expect("req"),
            )
            .await
            .expect("resp");
        assert_eq!(r.status(), StatusCode::MISDIRECTED_REQUEST, "{host}");
    }
    let r = app
        .clone()
        .oneshot(Request::get("/").body(Body::empty()).expect("req"))
        .await
        .expect("resp");
    assert_eq!(r.status(), StatusCode::MISDIRECTED_REQUEST, "missing Host");
    for host in ["localhost:8797", "[::1]:8797", "127.0.0.1"] {
        let r = app
            .clone()
            .oneshot(
                Request::get("/")
                    .header("host", host)
                    .body(Body::empty())
                    .expect("req"),
            )
            .await
            .expect("resp");
        assert_eq!(r.status(), StatusCode::OK, "{host}");
    }
    let r = app
        .clone()
        .oneshot(
            Request::post("/api/session")
                .header("host", "127.0.0.1:8797")
                .header("origin", "https://evil.example")
                .header("content-type", "application/json")
                .body(Body::from(r#"{"pair":"x"}"#))
                .expect("req"),
        )
        .await
        .expect("resp");
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn every_response_carries_strict_security_headers() {
    let (s, _d) = state(60).await;
    let app = router(s, 4096);
    for req in [
        get("/", None),
        get("/app.js", None),
        get("/api/status", None),
    ] {
        let r = app.clone().oneshot(req).await.expect("resp");
        let h = r.headers();
        let csp = h["content-security-policy"].to_str().expect("csp");
        assert!(csp.contains("default-src 'none'") && csp.contains("script-src 'self'"));
        assert!(!csp.contains("unsafe-inline") && !csp.contains("unsafe-eval"));
        assert!(csp.contains("frame-ancestors 'none'"));
        assert_eq!(h["x-content-type-options"], "nosniff");
        assert_eq!(h["referrer-policy"], "no-referrer");
        assert_eq!(h["cache-control"], "no-store");
        assert!(h.get("access-control-allow-origin").is_none(), "no CORS");
    }
}

#[test]
fn ui_assets_have_no_inline_script_or_html_injection_sinks() {
    let html = include_str!("../ui/index.html");
    let js = include_str!("../ui/app.js");
    assert!(!html.contains("<script>"), "inline script");
    let lower = html.to_ascii_lowercase();
    let has_handler = lower.split(|c: char| c.is_whitespace()).any(|w| {
        w.starts_with("on")
            && w.find('=')
                .is_some_and(|i| i > 2 && w[2..i].chars().all(|c| c.is_ascii_alphabetic()))
    });
    assert!(!has_handler, "inline on*= event handler");
    assert!(
        !html.contains("http://") && !html.contains("https://"),
        "no remote assets"
    );
    for sink in [
        "innerHTML",
        "outerHTML",
        "insertAdjacentHTML",
        "document.write",
        "eval(",
        "new Function",
    ] {
        assert!(!js.contains(sink), "app.js uses {sink}");
    }
    assert!(
        js.contains("history.replaceState"),
        "pairing code is scrubbed from history"
    );
    assert!(
        !js.contains("localStorage"),
        "session token must not persist past the tab"
    );
}

#[tokio::test]
async fn pairing_is_single_use_and_yields_a_working_session() {
    let (s, _d) = state(60).await;
    let app = router(s, 4096);
    // Session tokens cannot mint pairing codes; only the API key can.
    let r = app
        .clone()
        .oneshot(post("/api/pair", None, "{}"))
        .await
        .expect("resp");
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    let r = app
        .clone()
        .oneshot(post("/api/pair", Some(&bearer()), "{}"))
        .await
        .expect("resp");
    assert_eq!(r.status(), StatusCode::OK);
    let code = body_json(r).await["pair"]
        .as_str()
        .expect("pair")
        .to_string();
    let body = format!(r#"{{"pair":"{code}"}}"#);
    let r = app
        .clone()
        .oneshot(post("/api/session", None, &body))
        .await
        .expect("resp");
    assert_eq!(r.status(), StatusCode::OK);
    let sess = body_json(r).await["session"]
        .as_str()
        .expect("s")
        .to_string();
    // Reuse of the pairing code fails.
    let r = app
        .clone()
        .oneshot(post("/api/session", None, &body))
        .await
        .expect("resp");
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    // The session works for the UI API but cannot mint new pairing codes.
    let auth = format!("Bearer {sess}");
    let r = app
        .clone()
        .oneshot(get("/api/status", Some(&auth)))
        .await
        .expect("resp");
    assert_eq!(r.status(), StatusCode::OK);
    let st = body_json(r).await;
    assert_eq!(st["http_can_approve_writes"], false);
    assert_eq!(st["external"]["keys"]["anthropic"], false);
    let r = app
        .clone()
        .oneshot(post("/api/pair", Some(&auth), "{}"))
        .await
        .expect("resp");
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn settings_require_auth_whitelist_and_ack_for_relaxations() {
    let (s, d) = state(60).await;
    let app = router(s.clone(), 8192);
    let r = app
        .clone()
        .oneshot(post("/api/settings", None, r#"{"set":{"llm.model":"x"}}"#))
        .await
        .expect("resp");
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    // Dangerous keys are refused outright.
    for bad in [
        r#"{"set":{"server.host":"0.0.0.0"}}"#,
        r#"{"set":{"tools.auto_approve_writes":true}}"#,
        r#"{"set":{"llm.allow_non_loopback":true}}"#,
        r#"{"set":{"external.anthropic_key_ref":"env:HOME"}}"#,
    ] {
        let r = app
            .clone()
            .oneshot(post("/api/settings", Some(&bearer()), bad))
            .await
            .expect("resp");
        assert_eq!(r.status(), StatusCode::BAD_REQUEST, "{bad}");
    }
    // A model switch rebuilds the agent and is applied.
    let r = app
        .clone()
        .oneshot(post(
            "/api/settings",
            Some(&bearer()),
            r#"{"set":{"llm.model":"llama3.2:3b"}}"#,
        ))
        .await
        .expect("resp");
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(
        crate::runtime::current(&s.slot).await.config().llm.model,
        "llama3.2:3b"
    );
    // Loosening a rule needs ack_relax, then is audited.
    let relax = r#"{"set":{"external.rules.send_local_context":true}}"#;
    let r = app
        .clone()
        .oneshot(post("/api/settings", Some(&bearer()), relax))
        .await
        .expect("resp");
    assert_eq!(r.status(), StatusCode::CONFLICT);
    let r = app
        .clone()
        .oneshot(post(
            "/api/settings",
            Some(&bearer()),
            r#"{"set":{"external.rules.send_local_context":true},"ack_relax":true}"#,
        ))
        .await
        .expect("resp");
    assert_eq!(r.status(), StatusCode::OK);
    let recs = cg_audit::read_all(&d.path().join("logs/audit.pb")).expect("audit");
    assert!(recs.iter().any(|r| r.event == "policy_relaxed"));
    assert!(recs.iter().any(|r| r.event == "settings_changed"));
    // Persisted to the owner-only overlay, which survives a reload.
    let overlay = d.path().join("ui-settings.toml");
    let text = std::fs::read_to_string(&overlay).expect("overlay");
    assert!(text.contains("llama3.2:3b") && text.contains("send_local_context = true"));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let m = std::fs::metadata(&overlay).expect("m").permissions().mode() & 0o777;
        assert_eq!(m, 0o600);
    }
}

#[tokio::test]
async fn keys_are_validated_stored_and_never_echoed() {
    let (s, d) = state(60).await;
    let app = router(s, 8192);
    let r = app
        .clone()
        .oneshot(post(
            "/api/keys",
            Some(&bearer()),
            r#"{"provider":"anthropic","key":"xai-wrong-slot-000000000000"}"#,
        ))
        .await
        .expect("resp");
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    let key = "sk-ant-api03-TESTKEY-0000000000000000";
    let r = app
        .clone()
        .oneshot(post(
            "/api/keys",
            Some(&bearer()),
            &format!(r#"{{"provider":"anthropic","key":"{key}"}}"#),
        ))
        .await
        .expect("resp");
    assert_eq!(r.status(), StatusCode::OK);
    let reply = body_json(r).await.to_string();
    assert!(!reply.contains("TESTKEY"), "key echoed: {reply}");
    let r = app
        .clone()
        .oneshot(get("/api/status", Some(&bearer())))
        .await
        .expect("resp");
    let st = body_json(r).await;
    assert_eq!(st["external"]["keys"]["anthropic"], true);
    assert!(!st.to_string().contains("TESTKEY"));
    // Stored owner-only (file fallback in tests); audit has no key material.
    let raw = std::fs::read(d.path().join("logs/audit.pb")).expect("audit");
    assert!(!String::from_utf8_lossy(&raw).contains("TESTKEY"));
    let r = app
        .clone()
        .oneshot(post(
            "/api/keys/delete",
            Some(&bearer()),
            r#"{"provider":"anthropic"}"#,
        ))
        .await
        .expect("resp");
    assert_eq!(r.status(), StatusCode::OK);
    assert!(!d.path().join("secrets/anthropic_api_key").exists());
}

#[tokio::test]
async fn http_prefer_external_without_external_stays_local() {
    let (s, _d) = state(60).await;
    let app = router(s, 4096);
    let r = app
        .clone()
        .oneshot(q(
            Some(&bearer()),
            r#"{"query":"hi","prefer_external":true}"#,
        ))
        .await
        .expect("resp");
    assert_eq!(r.status(), StatusCode::OK);
    let v = body_json(r).await;
    assert!(
        !v["path"]
            .as_array()
            .expect("path")
            .iter()
            .any(|p| p == "external_fallback")
    );
}

#[test]
fn app_bundle_detection_is_exact() {
    use std::path::Path;
    assert!(crate::is_bundle_exe(Path::new(
        "/Applications/cg-researcher.app/Contents/MacOS/cg-researcher"
    )));
    assert!(!crate::is_bundle_exe(Path::new(
        "/Users/x/.cg-researcher/bin/cg-researcher"
    )));
    assert!(!crate::is_bundle_exe(Path::new(
        "/tmp/app/Contents/MacOS/cg-researcher"
    )));
    assert!(!crate::is_bundle_exe(Path::new(
        "/x.app/MacOS/cg-researcher"
    )));
}

#[tokio::test]
async fn reindex_needs_auth_and_live_swaps_the_index() {
    let (s, d) = state(60).await;
    let corpus = d.path().join("corpus");
    std::fs::create_dir_all(&corpus).expect("corpus");
    std::fs::write(
        corpus.join("n.md"),
        "# Notes\nImmutable repositories resist ransomware.\n",
    )
    .expect("w");
    let r = router(s.clone(), 4096)
        .oneshot(post("/api/reindex", None, "{}"))
        .await
        .expect("r");
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    let r = router(s.clone(), 4096)
        .oneshot(post("/api/reindex", Some(&bearer()), "{}"))
        .await
        .expect("r");
    assert_eq!(r.status(), StatusCode::OK);
    let v = body_json(r).await;
    assert_eq!(v["files"], 1);
    assert!(v["chunks"].as_u64().expect("chunks") >= 1);
    let st = body_json(
        router(s.clone(), 4096)
            .oneshot(get("/api/status", Some(&bearer())))
            .await
            .expect("st"),
    )
    .await;
    assert_eq!(
        st["indexed_chunks"], v["chunks"],
        "running agent sees the new index"
    );
    assert!(st["corpus_dir"].as_str().expect("dir").ends_with("corpus"));
    let g = st["graph"].as_array().expect("graph");
    assert_eq!(g.first().and_then(|x| x.as_str()), Some("retrieve"));
    assert_eq!(g.last().and_then(|x| x.as_str()), Some("audit_logger"));
    assert_eq!(st["graph_edges"].as_array().expect("edges").len(), g.len());
}

#[tokio::test]
async fn settings_refuse_a_model_id_from_the_other_provider() {
    let (s, d) = state(60).await;
    let app = router(s.clone(), 8192);
    for bad in [
        r#"{"set":{"external.provider":"xai","external.model":"claude-sonnet-5-5"}}"#,
        r#"{"set":{"external.model":"grok-4.7"}}"#,
        r#"{"set":{"external.provider":"anthropic","external.model":"gpt-5"}}"#,
    ] {
        let r = app
            .clone()
            .oneshot(post("/api/settings", Some(&bearer()), bad))
            .await
            .expect("resp");
        assert_eq!(r.status(), StatusCode::BAD_REQUEST, "{bad}");
        let v = body_json(r).await;
        assert!(
            v["error"].as_str().unwrap_or("").contains("external.model"),
            "{v}"
        );
    }
    // Nothing was applied or persisted.
    let cfg = crate::runtime::current(&s.slot).await.config().clone();
    assert_eq!(
        cfg.external.provider,
        cg_core::external::Provider::Anthropic
    );
    assert!(cfg.external.model.is_empty());
    assert!(
        !d.path().join("ui-settings.toml").exists() || {
            let t = std::fs::read_to_string(d.path().join("ui-settings.toml")).expect("overlay");
            !t.contains("claude-sonnet") && !t.contains("grok") && !t.contains("gpt-5")
        }
    );
}

#[tokio::test]
async fn query_stream_is_gated_and_ends_with_one_final_event() {
    use http_body_util::BodyExt;
    let (s, _d) = state(60).await;
    let app = router(s, 4096);
    let r = app
        .clone()
        .oneshot(post("/query/stream", None, r#"{"query":"hi"}"#))
        .await
        .expect("resp");
    assert_eq!(r.status(), StatusCode::UNAUTHORIZED);
    // Validation errors are plain JSON responses, not a half-open stream.
    let r = app
        .clone()
        .oneshot(post(
            "/query/stream",
            Some(&bearer()),
            r#"{"query":"hi","nope":1}"#,
        ))
        .await
        .expect("resp");
    assert_eq!(r.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        r.headers()["content-type"]
            .to_str()
            .expect("ct")
            .starts_with("application/json")
    );
    let r = app
        .clone()
        .oneshot(post("/query/stream", Some(&bearer()), r#"{"query":"hi"}"#))
        .await
        .expect("resp");
    assert_eq!(r.status(), StatusCode::OK);
    let h = r.headers().clone();
    assert!(
        h["content-type"]
            .to_str()
            .expect("ct")
            .starts_with("text/event-stream"),
        "{h:?}"
    );
    assert!(
        h.contains_key("content-security-policy"),
        "security headers apply to SSE"
    );
    let bytes = tokio::time::timeout(std::time::Duration::from_secs(30), r.into_body().collect())
        .await
        .expect("stream ends")
        .expect("body")
        .to_bytes();
    let text = String::from_utf8_lossy(&bytes);
    assert_eq!(text.matches("event: final").count(), 1, "{text}");
    let data = text
        .split("event: final\n")
        .nth(1)
        .and_then(|t| t.lines().next())
        .and_then(|l| l.strip_prefix("data: "))
        .expect("final data");
    let v: serde_json::Value = serde_json::from_str(data).expect("final json");
    assert!(v["answer"].is_string() && v["path"].is_array(), "{v}");
    assert!(!text.contains("event: error"), "{text}");
}
