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
        let mut cfg = Config::load(&layout.config())?;
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
    let yes = req.origin != Origin::Sms
        && req.confirmer.confirm("Local corpus is not confident. Send this query to the external model (xAI)? Local context is not sent unless configured.").await;
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
        confirmer: r.confirmer.clone(),
    }
}

pub struct AgentHandler(pub Arc<Agent>);

#[async_trait]
impl InboundHandler for AgentHandler {
    async fn handle(&self, msg: Inbound, confirmer: Arc<dyn Confirmer>) -> String {
        let r = run_turn(
            &self.0,
            TurnRequest {
                query: msg.text,
                origin: msg.origin,
                sender: msg.sender,
                attachments: msg.attachments,
                confirm_online: None,
                confirmer,
            },
        )
        .await;
        r.answer
    }
}
