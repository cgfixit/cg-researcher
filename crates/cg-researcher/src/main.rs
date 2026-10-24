//! cg-researcher: local-first, telemetry-free agent. See README.md / SECURITY.md.
#![forbid(unsafe_code)]

mod chat;
mod runtime;
mod serve;

use std::path::PathBuf;
use std::sync::Arc;

use cg_core::sandbox::clean_command;
use clap::{Parser, Subcommand};
use runtime::{AgentHandler, AgentSlot, Control, Runtime};

const DEFAULT_CONFIG: &str = include_str!("../../../config/cg.toml");

#[derive(Parser)]
#[command(
    name = "cg-researcher",
    version,
    about = "Local-first RAG agent with gated connectors (no telemetry)"
)]
struct Cli {
    /// Data directory (default $CG_HOME or ~/.cg-researcher)
    #[arg(long, global = true)]
    home: Option<PathBuf>,
    /// Omitted only when launched as cg-researcher.app (then: `app`).
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create the data directory, default config, audit key, API key and SMS PIN.
    Init {
        #[arg(long)]
        force_config: bool,
    },
    /// Interactive chat (CLI origin; can confirm writes and online fallback).
    Chat,
    /// Loopback HTTP API, plus enabled Telegram/SMS gateways.
    Serve {
        #[arg(long)]
        no_gateways: bool,
    },
    /// Run only the inbound gateways (Telegram, SMS).
    Gateways,
    /// Rebuild the RAG index from the corpus directory.
    Index,
    /// Verify or show the HMAC-chained protobuf audit log.
    Audit {
        #[command(subcommand)]
        cmd: AuditCmd,
    },
    /// OAuth consent for the enabled Google connectors (loopback + PKCE).
    GoogleAuth,
    /// Offline checks: config, graph, connectors, egress pinning, local model.
    Selftest,
    /// Scheduled health check for launchd/cron: runs `selftest` (which
    /// includes audit-chain verification) and records the outcome in the
    /// audit log. Exits non-zero on failure. No network beyond loopback.
    Maintain,
    /// Open the local web UI (needs `cg-researcher serve` running). Mints a
    /// single-use pairing code; the API key never appears in a URL.
    Ui {
        /// Print the URL instead of opening the browser.
        #[arg(long)]
        print: bool,
    },
    /// What cg-researcher.app runs on double-click: `init` on first launch,
    /// start `serve` in the background unless one is already listening
    /// (e.g. the launchd agent), then open the paired web UI.
    App,
    /// Launch CyClaw-Net-Viewer (macOS) or print its CLI snapshot.
    Netviewer {
        #[arg(long)]
        cli: bool,
    },
}

#[derive(Subcommand)]
enum AuditCmd {
    Verify,
    Tail {
        #[arg(short, default_value_t = 20)]
        n: usize,
    },
}

fn init_logging() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_env("CG_LOG").unwrap_or_else(|_| EnvFilter::new("info"));
    // stderr only; no exporters, no files with secrets (the audit log is separate and HMAC-chained).
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .with_target(false)
        .init();
}

fn main() -> anyhow::Result<()> {
    // Telemetry kill-switch (I2): edition-2024 `set_var` is unsafe and this
    // crate forbids unsafe, so the kill-switch is applied to every child via
    // `sandbox::clean_command` (cleared env + TELEMETRY_KILL); the Rust binary
    // itself links no telemetry SDK (checked by `cargo deny` bans).
    init_logging();
    let cli = Cli::parse();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    rt.block_on(run(cli))
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    let home = runtime::home(cli.home);
    let cmd = match cli.cmd {
        Some(c) => c,
        None if in_app_bundle() => Cmd::App,
        None => {
            use clap::CommandFactory;
            Cli::command().print_help()?;
            return Ok(());
        }
    };
    match cmd {
        Cmd::Init { force_config } => init(home, force_config),
        Cmd::Chat => {
            let r = Runtime::load(home)?;
            let (agent, _, enabled) = r.agent().await?;
            r.event("session_start", format!("chat connectors={enabled:?}"));
            chat::run(agent).await
        }
        Cmd::Serve { no_gateways } => {
            let r = Runtime::load(home)?;
            let (agent, gateways, enabled) = r.agent().await?;
            let key = std::fs::read_to_string(r.layout.api_key())
                .map_err(|_| anyhow::anyhow!("no API key; run `cg-researcher init`"))?;
            let slot: Arc<AgentSlot> = Arc::new(tokio::sync::RwLock::new(agent));
            let state = Arc::new(serve::AppState::new(
                slot.clone(),
                Arc::new(Control::from_runtime(&r)),
                key.trim().to_string(),
                r.cfg.server.rate_limit_per_min.max(1) as usize,
            ));
            cg_core::secrets::redactor().register(key.trim());
            let ip: std::net::IpAddr = r.cfg.server.host.parse()?;
            r.event(
                "server_start",
                format!("port={} connectors={enabled:?}", r.cfg.server.port),
            );
            if !no_gateways {
                spawn_gateways(gateways, slot);
            }
            serve::serve(
                state,
                (ip, r.cfg.server.port).into(),
                r.cfg.server.max_body_bytes,
            )
            .await
        }
        Cmd::Gateways => {
            let r = Runtime::load(home)?;
            let (agent, gateways, _) = r.agent().await?;
            anyhow::ensure!(
                !gateways.is_empty(),
                "no gateway enabled (connectors.telegram / connectors.sms)"
            );
            r.event(
                "gateways_start",
                format!(
                    "{:?}",
                    gateways.iter().map(|g| g.name()).collect::<Vec<_>>()
                ),
            );
            spawn_gateways(gateways, Arc::new(tokio::sync::RwLock::new(agent)));
            serve::shutdown().await;
            Ok(())
        }
        Cmd::Index => {
            let r = Runtime::load(home)?;
            let (agent, _, _) = r.agent().await?;
            let (files, chunks, embedded) = agent.reindex().await?;
            println!(
                "indexed {files} files → {chunks} chunks ({embedded} embedded) from {}",
                r.cfg.corpus_dir().display()
            );
            Ok(())
        }
        Cmd::Audit { cmd } => {
            let r = Runtime::load(home)?;
            match cmd {
                AuditCmd::Verify => {
                    let n = r.audit.verify_now()?;
                    println!("audit chain OK: {n} records");
                }
                AuditCmd::Tail { n } => {
                    let all = cg_audit::read_all(&r.layout.audit_log())?;
                    for rec in all.iter().rev().take(n).rev() {
                        println!(
                            "{} #{} {} origin={} model={} path={} tools={} tainted={} blocked={} {}",
                            rec.ts_unix_ms,
                            rec.seq,
                            rec.event,
                            rec.origin,
                            rec.answer_model,
                            rec.node_path.join(">"),
                            rec.tools
                                .iter()
                                .map(|t| format!("{}:{}", t.tool, t.decision))
                                .collect::<Vec<_>>()
                                .join(","),
                            rec.tainted,
                            rec.guardrail_blocked,
                            rec.detail
                        );
                    }
                }
            }
            Ok(())
        }
        Cmd::GoogleAuth => {
            let r = Runtime::load(home)?;
            let scopes = cg_connectors::google_scopes(&r.cfg)?;
            let (id, secret) = cg_connectors::google_client(&r.cfg, &r.secrets).await?;
            let reference =
                cg_connectors::google::authorize(&id, &secret, &scopes, &r.secrets, |url| {
                    eprintln!(
                        "Open this URL to grant access (scopes: {}):\n\n{url}\n",
                        scopes.join(" ")
                    );
                    if cfg!(target_os = "macos") {
                        let _ = std::process::Command::new("/usr/bin/open")
                            .arg(url)
                            .status();
                    }
                })
                .await?;
            r.event("google_authorized", format!("scopes={}", scopes.len()));
            println!(
                "stored refresh token as {reference}; set refresh_token_ref = \"{reference}\" if it differs"
            );
            Ok(())
        }
        Cmd::Selftest => selftest(home).await,
        Cmd::Maintain => {
            let res = selftest(home.clone()).await;
            let r = Runtime::load(home)?;
            r.event(
                "maintenance",
                match &res {
                    Ok(()) => "ok".to_string(),
                    Err(e) => format!("fail: {e}"),
                },
            );
            res
        }
        Cmd::Ui { print } => ui(home, print).await,
        Cmd::App => app(home).await,
        Cmd::Netviewer { cli } => netviewer(&home, cli).await,
    }
}

fn spawn_gateways(gateways: Vec<Arc<dyn cg_core::tools::Gateway>>, slot: Arc<AgentSlot>) {
    let handler: Arc<dyn cg_core::tools::InboundHandler> = Arc::new(AgentHandler(slot));
    for g in gateways {
        let h = handler.clone();
        tokio::spawn(async move {
            let name = g.name();
            if let Err(e) = g.run(h).await {
                tracing::error!(
                    "gateway {name} stopped: {}",
                    cg_core::sanitizer::redact(&e.to_string())
                );
            }
        });
    }
}

fn random_hex(n: usize) -> anyhow::Result<String> {
    let mut b = vec![0u8; n];
    getrandom::fill(&mut b).map_err(|_| anyhow::anyhow!("OS RNG unavailable"))?;
    Ok(hex::encode(b))
}

fn init(home: PathBuf, force_config: bool) -> anyhow::Result<()> {
    let layout = cg_core::paths::Layout::new(&home);
    layout.ensure()?;
    if force_config || !layout.config().exists() {
        cg_core::fsutil::write_private(&layout.config(), DEFAULT_CONFIG.as_bytes())?;
        println!("wrote {}", layout.config().display());
    } else {
        println!("kept existing {}", layout.config().display());
    }
    cg_audit::load_or_create_key(&layout.audit_key())?;
    if !layout.api_key().exists() {
        cg_core::fsutil::write_private(&layout.api_key(), random_hex(32)?.as_bytes())?;
    }
    let pin = layout.secrets().join("sms_pin");
    if !pin.exists() {
        let mut b = [0u8; 8];
        getrandom::fill(&mut b).map_err(|_| anyhow::anyhow!("OS RNG unavailable"))?;
        let digits: String = b.iter().map(|x| char::from(b'0' + x % 10)).collect();
        cg_core::fsutil::write_private(&pin, digits.as_bytes())?;
    }
    println!("home: {} (owner-only)", layout.home.display());
    println!(
        "secrets: {} (api.key, audit.key, sms_pin)",
        layout.secrets().display()
    );
    println!(
        "next: put .md/.txt/.docx files in {} and run `cg-researcher index`",
        layout.home.join("corpus").display()
    );
    Ok(())
}

async fn selftest(home: PathBuf) -> anyhow::Result<()> {
    let r = Runtime::load(home)?;
    let mut fails = 0;
    let mut check = |name: &str, ok: bool, note: String| {
        println!(
            "[{}] {name}{}",
            if ok { " ok " } else { "FAIL" },
            if note.is_empty() {
                String::new()
            } else {
                format!(" — {note}")
            }
        );
        if !ok {
            fails += 1;
        }
    };
    check(
        "config validates (loopback model + bind)",
        true,
        format!("{} @ {}", r.cfg.llm.model, r.cfg.llm.base_url),
    );
    let (agent, gateways, enabled) = r.agent().await?;
    let nodes = agent.graph_nodes();
    check(
        "agent graph compiled",
        nodes.len() == 10,
        format!("{} nodes", nodes.len()),
    );
    check(
        "external model client",
        agent.has_external()
            == (r.cfg.app.mode == cg_core::config::Mode::Hybrid && r.cfg.external.enabled),
        if agent.has_external() {
            "constructed (hybrid + enabled; still asks per query)".into()
        } else {
            "not constructed".into()
        },
    );
    check(
        "connectors",
        true,
        format!("enabled={enabled:?} gateways={}", gateways.len()),
    );
    let eg = cg_core::egress::Egress::new(
        "selftest",
        &["serpapi.com"],
        false,
        std::time::Duration::from_secs(2),
    )?;
    let refused = [
        "http://serpapi.com/",
        "https://evil.example/",
        "https://1.1.1.1/",
        "https://u:p@serpapi.com/",
    ]
    .iter()
    .all(|u| eg.check(&url::Url::parse(u).expect("static url")).is_err());
    check(
        "egress pinning refuses http/unpinned/IP/userinfo",
        refused,
        String::new(),
    );
    let n = r.audit.verify_now();
    check(
        "audit chain verifies",
        n.is_ok(),
        n.map(|n| format!("{n} records"))
            .unwrap_or_else(|e| e.to_string()),
    );
    let healthy = agent.local_healthy().await;
    check(
        "local model reachable",
        healthy,
        if healthy {
            String::new()
        } else {
            "start Ollama / LM Studio (not fatal)".into()
        },
    );
    let fails = if healthy { fails } else { fails - 1 };
    anyhow::ensure!(fails == 0, "{fails} selftest check(s) failed");
    Ok(())
}

async fn netviewer(home: &std::path::Path, cli: bool) -> anyhow::Result<()> {
    anyhow::ensure!(cfg!(target_os = "macos"), "CyClaw-Net-Viewer is macOS-only");
    let nb = home.join("bin").join("netboard");
    if cli {
        anyhow::ensure!(
            nb.is_file(),
            "{} missing; run scripts/install.sh --with-netviewer",
            nb.display()
        );
        let st = clean_command(&nb, &[])
            .args(["--cli", "-n", "-a"])
            .stdin(std::process::Stdio::null())
            .status()
            .await?;
        anyhow::ensure!(st.success(), "netboard exited with {st}");
        return Ok(());
    }
    let user_apps = std::env::var("HOME")
        .map(|h| PathBuf::from(h).join("Applications/CyClaw-Net-Viewer.app"))
        .unwrap_or_default();
    let app = [
        PathBuf::from("/Applications/CyClaw-Net-Viewer.app"),
        user_apps,
        home.join("bin/CyClaw-Net-Viewer.app"),
    ]
    .into_iter()
    .find(|p| p.is_dir())
    .ok_or_else(|| {
        anyhow::anyhow!("CyClaw-Net-Viewer.app not found; run scripts/install.sh --with-netviewer")
    })?;
    let st = clean_command(std::path::Path::new("/usr/bin/open"), &[])
        .arg(&app)
        .status()
        .await?;
    anyhow::ensure!(st.success(), "open failed");
    Ok(())
}

#[cfg(test)]
mod docs_cli;
#[cfg(test)]
mod tests;

/// True when this binary is `<X>.app/Contents/MacOS/<exe>`.
fn in_app_bundle() -> bool {
    std::env::current_exe().is_ok_and(|p| is_bundle_exe(&p))
}

fn is_bundle_exe(p: &std::path::Path) -> bool {
    let mut it = p.ancestors().skip(1);
    matches!(
        (it.next(), it.next(), it.next()),
        (Some(m), Some(c), Some(app))
            if m.file_name().is_some_and(|n| n == "MacOS")
                && c.file_name().is_some_and(|n| n == "Contents")
                && app.extension().is_some_and(|e| e == "app")
    )
}

async fn app(home: PathBuf) -> anyhow::Result<()> {
    let layout = cg_core::paths::Layout::new(&home);
    if !layout.api_key().exists() {
        init(home.clone(), false)?;
    }
    let r = Runtime::load(home.clone())?;
    let addr = std::net::SocketAddr::new(r.cfg.server.host.parse()?, r.cfg.server.port);
    let up = || {
        std::net::TcpStream::connect_timeout(&addr, std::time::Duration::from_millis(300)).is_ok()
    };
    if !up() {
        layout.ensure()?;
        // Detached child (outlives the app's launcher process). Same env
        // hygiene as sandbox::clean_command: cleared env + telemetry kill.
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(layout.logs().join("app-serve.log"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            log.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        }
        let mut c = std::process::Command::new(std::env::current_exe()?);
        c.env_clear().env("PATH", cg_core::sandbox::SAFE_PATH);
        for k in ["HOME", "USER", "LANG", "TMPDIR"] {
            if let Ok(v) = std::env::var(k) {
                c.env(k, v);
            }
        }
        for (k, v) in cg_core::sandbox::TELEMETRY_KILL {
            c.env(k, v);
        }
        c.arg("--home")
            .arg(&home)
            .arg("serve")
            .stdin(std::process::Stdio::null())
            .stdout(log.try_clone()?)
            .stderr(log)
            .spawn()?;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        while !up() {
            anyhow::ensure!(
                std::time::Instant::now() < deadline,
                "serve did not start; see {}",
                layout.logs().join("app-serve.log").display()
            );
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }
    }
    ui(home, false).await
}

async fn ui(home: PathBuf, print: bool) -> anyhow::Result<()> {
    let r = Runtime::load(home)?;
    let key = std::fs::read_to_string(r.layout.api_key())
        .map_err(|_| anyhow::anyhow!("no API key; run `cg-researcher init`"))?;
    let addr = std::net::SocketAddr::new(r.cfg.server.host.parse()?, r.cfg.server.port);
    let base = format!("http://{addr}");
    let egress =
        cg_core::egress::Egress::new("ui-pair", &[], true, std::time::Duration::from_secs(5))?;
    // Authenticate the listener before opening its UI; never transmit the API key.
    let nonce = random_hex(32)?;
    let resp = egress
        .post(&format!("{base}/api/pair/challenge"))?
        .json(&serde_json::json!({"nonce": nonce}))
        .send()
        .await
        .map_err(|_| anyhow::anyhow!("cannot reach {base}; is `cg-researcher serve` running?"))?;
    anyhow::ensure!(
        resp.status().is_success(),
        "pairing challenge refused: {}",
        resp.status()
    );
    let v: serde_json::Value = resp.json().await?;
    let challenge = v["challenge"].as_str().unwrap_or_default();
    let proof = v["proof"].as_str().unwrap_or_default();
    let expected = serve::pairing_proof(key.trim(), "server", &nonce, challenge);
    use subtle::ConstantTimeEq;
    anyhow::ensure!(
        challenge.len() == 64
            && challenge.bytes().all(|b| b.is_ascii_hexdigit())
            && bool::from(expected.as_bytes().ct_eq(proof.as_bytes())),
        "local server identity check failed; refusing to pair"
    );
    let resp = egress
        .post(&format!("{base}/api/pair/local"))?
        .json(&serde_json::json!({"nonce": nonce, "challenge": challenge,
            "proof": serve::pairing_proof(key.trim(), "client", &nonce, challenge)}))
        .send()
        .await?;
    anyhow::ensure!(
        resp.status().is_success(),
        "pairing refused: {}",
        resp.status()
    );
    let v: serde_json::Value = resp.json().await?;
    let code = v["pair"].as_str().unwrap_or_default();
    anyhow::ensure!(
        code.len() == 64 && code.chars().all(|c| c.is_ascii_hexdigit()),
        "unexpected pairing reply"
    );
    // The fragment never reaches the server or logs; the page swaps it for a
    // session token, scrubs it from history, and it expires in 2 minutes.
    let url = format!("{base}/#p={code}");
    if print || !cfg!(target_os = "macos") {
        println!("{url}");
        eprintln!("single-use, expires in {}s", v["ttl_secs"]);
    } else {
        let st = std::process::Command::new("/usr/bin/open")
            .arg(&url)
            .status()?;
        anyhow::ensure!(st.success(), "open failed; rerun with --print");
        eprintln!("opened the UI (pairing code is single-use)");
    }
    Ok(())
}
