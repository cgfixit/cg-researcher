use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use crate::serve::{AppState, router};

async fn state(limit: usize) -> (Arc<AppState>, tempfile::TempDir) {
    let dir = tempfile::tempdir().expect("tmp");
    let mut cfg = cg_core::config::Config::default();
    cfg.app.home = dir.path().to_string_lossy().into_owned();
    cfg.llm.base_url = "http://127.0.0.1:9/v1".into();
    cfg.llm.timeout_secs = 2;
    let layout = cg_core::paths::Layout::new(dir.path());
    layout.ensure().expect("layout");
    let key = cg_audit::load_or_create_key(&layout.audit_key()).expect("key");
    let audit = Arc::new(cg_audit::AuditLog::open(layout.audit_log(), &key).expect("audit"));
    let secrets = cg_core::secrets::SecretStore::new(layout.secrets());
    let agent = cg_core::agent::Agent::new(cfg, Default::default(), audit, &secrets)
        .await
        .expect("agent");
    (
        Arc::new(AppState {
            agent: Arc::new(agent),
            api_key: "k".repeat(64),
            limit_per_min: limit,
            recent: Default::default(),
        }),
        dir,
    )
}

fn q(auth: Option<&str>, body: &str) -> Request<Body> {
    let mut b = Request::post("/query").header("content-type", "application/json");
    if let Some(a) = auth {
        b = b.header("authorization", a);
    }
    b.body(Body::from(body.to_string())).expect("req")
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
        .oneshot(Request::get("/tools").body(Body::empty()).expect("req"))
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
        StatusCode::BAD_REQUEST,
        "oversized body is rejected by the JSON extractor"
    );
    let r = app
        .clone()
        .oneshot(q(Some(&good), r#"{"query":"x","approve_writes":true}"#))
        .await
        .expect("resp");
    assert_eq!(
        r.status(),
        StatusCode::BAD_REQUEST,
        "unknown fields refused"
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
            !t.contains("cg-agent ") && !t.contains("cg-agent="),
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
