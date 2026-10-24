//! Shared startup: layout, config, secrets, audit, connectors, agent.

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use cg_audit::{AuditLog, AuditRecord};
use cg_core::agent::{Agent, TurnRequest, TurnResult};
use cg_core::config::Config;
use cg_core::paths::Layout;
use cg_core::secrets::SecretStore;
use cg_core::tools::{Confirmer, Gateway, Inbound, InboundHandler, Origin};

pub struct Runtime {
    pub layout: Layout,
    pub cfg: Config,
    pub secrets: SecretStore,
    pub audit: Arc<AuditLog>,
}

pub fn home(arg: Option<PathBuf>) -> PathBuf {
    arg.unwrap_or_else(cg_core::paths::default_home)
}

impl Runtime {
    pub fn load(home: PathBuf) -> anyhow::Result<Self> {
        let layout = Layout::new(home);
        anyhow::ensure!(
            layout.config().is_file(),
            "no config at {}; run `cg-agent init` first",
            layout.config().display()
        );
        let mut cfg = Config::load_with_overlay(&layout.config(), Some(&layout.settings()))?;
        if cfg.app.home.is_empty() {
            cfg.app.home = layout.home.to_string_lossy().into_owned();
        }
        cfg.validate()?;
        layout.ensure()?;
        let key = cg_audit::load_or_create_key(&layout.audit_key())?;
        let audit = Arc::new(AuditLog::open(layout.audit_log(), &key)?);
        let secrets = SecretStore::new(layout.secrets());
        Ok(Self {
            layout,
            cfg,
            secrets,
            audit,
        })
    }

    pub async fn agent(
        &self,
    ) -> anyhow::Result<(Arc<Agent>, Vec<Arc<dyn Gateway>>, Vec<&'static str>)> {
        let built = cg_connectors::build_all(&self.cfg, &self.secrets).await?;
        let agent = Agent::new(
            self.cfg.clone(),
            built.tools,
            self.audit.clone(),
            &self.secrets,
        )
        .await?;
        Ok((Arc::new(agent), built.gateways, built.enabled))
    }

    pub fn event(&self, event: &str, detail: String) {
        let _ = self.audit.append(AuditRecord {
            event: event.into(),
            origin: cg_audit::Origin::System as i32,
            detail,
            ..Default::default()
        });
    }
}

/// Run a turn; if the local answer was not confident and an external model
/// is configured, ask the confirmer (gate 3) and re-run with the decision.
/// SMS confirmers are DenyAll and the core also refuses SMS egress.
pub async fn run_turn(agent: &Agent, mut req: TurnRequest) -> TurnResult {
    let first = agent.run(clone_req(&req)).await;
    if !first.needs_confirm {
        return first;
    }
    let label = agent
        .external_label()
        .unwrap_or_else(|| "external model".into());
    let r = &agent.config().external.rules;
    let what = if r.send_local_context {
        "Sanitized local context WILL be sent with it (rule send_local_context)."
    } else {
        "Local corpus context is not sent."
    };
    let yes = req.origin != Origin::Sms
        && req
            .confirmer
            .confirm(&format!(
                "Local corpus is not confident. Send this query to {label}? {what}"
            ))
            .await;
    req.confirm_online = Some(yes);
    agent.run(req).await
}

fn clone_req(r: &TurnRequest) -> TurnRequest {
    TurnRequest {
        query: r.query.clone(),
        origin: r.origin,
        sender: r.sender.clone(),
        attachments: r.attachments.clone(),
        confirm_online: r.confirm_online,
        prefer_external: r.prefer_external,
        confirmer: r.confirmer.clone(),
    }
}

/// The live agent. A model/settings switch builds a fresh `Agent` through
/// `Agent::new` (so every gate and autotune runs again) and swaps it in.
pub type AgentSlot = tokio::sync::RwLock<Arc<Agent>>;

pub async fn current(slot: &AgentSlot) -> Arc<Agent> {
    slot.read().await.clone()
}

pub struct AgentHandler(pub Arc<AgentSlot>);

#[async_trait]
impl InboundHandler for AgentHandler {
    async fn handle(&self, msg: Inbound, confirmer: Arc<dyn Confirmer>) -> String {
        let agent = current(&self.0).await;
        let r = run_turn(
            &agent,
            TurnRequest {
                query: msg.text,
                origin: msg.origin,
                sender: msg.sender,
                attachments: msg.attachments,
                confirm_online: None,
                prefer_external: false,
                confirmer,
            },
        )
        .await;
        r.answer
    }
}

/// Everything a settings change needs to rebuild the agent.
pub struct Control {
    pub layout: Layout,
    pub secrets: SecretStore,
    pub audit: Arc<AuditLog>,
    /// Serializes settings writes and rebuilds.
    pub lock: tokio::sync::Mutex<()>,
}

impl Control {
    pub fn from_runtime(r: &Runtime) -> Self {
        Self {
            layout: Layout::new(r.layout.home.clone()),
            secrets: r.secrets.clone(),
            audit: r.audit.clone(),
            lock: tokio::sync::Mutex::new(()),
        }
    }

    /// Load base + overlay exactly as startup does.
    pub fn load_config(&self, overlay: &std::path::Path) -> anyhow::Result<Config> {
        let mut cfg = Config::load_with_overlay(&self.layout.config(), Some(overlay))?;
        if cfg.app.home.is_empty() {
            cfg.app.home = self.layout.home.to_string_lossy().into_owned();
        }
        cfg.validate()?;
        Ok(cfg)
    }

    /// Build a new agent from `cfg`. Connectors are rebuilt for their tool
    /// registry only; already-running gateways keep running and pick up the
    /// new agent through the shared slot.
    pub async fn build(&self, cfg: Config) -> anyhow::Result<Arc<Agent>> {
        let built = cg_connectors::build_all(&cfg, &self.secrets).await?;
        let agent = Agent::new(cfg, built.tools, self.audit.clone(), &self.secrets).await?;
        if agent.has_external() {
            // Autotune on every switch, external side included (metadata only).
            let _ = agent.autotune_external().await;
        }
        Ok(Arc::new(agent))
    }

    pub fn event(&self, event: &str, detail: String) {
        let _ = self.audit.append(AuditRecord {
            event: event.into(),
            origin: cg_audit::Origin::Http as i32,
            detail,
            ..Default::default()
        });
    }
}
