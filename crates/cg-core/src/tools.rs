//! The tool and gateway contracts. Connectors implement these traits in the
//! `cg-connectors` crate; the core only sees trait objects, so core code
//! can never call a connector API directly (I6 enforced by Cargo).

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use serde_json::Value;

/// What a tool can do to the world. Drives the tool gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Effect {
    /// Reads data. Allowed when the connector is enabled.
    Read,
    /// Sends, creates, modifies or deletes. Needs confirmation.
    Write,
}

#[derive(Debug, Clone)]
pub struct ToolSpec {
    pub name: &'static str,
    pub description: &'static str,
    /// JSON Schema for the arguments.
    pub parameters: Value,
    pub effect: Effect,
    /// Output carries third-party content (web pages, email bodies, SMS):
    /// it is wrapped, filtered and taints the turn.
    pub untrusted_output: bool,
    /// May be offered to Telegram/SMS turns (read tools only, and only when
    /// the connector allows it).
    pub remote_ok: bool,
}

impl ToolSpec {
    pub fn to_openai(&self) -> Value {
        serde_json::json!({
            "type": "function",
            "function": {"name": self.name, "description": self.description, "parameters": self.parameters}
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ToolError {
    #[error("bad arguments: {0}")]
    BadArgs(String),
    #[error("{0}")]
    Failed(String),
    #[error("not configured: {0}")]
    NotConfigured(String),
}

impl ToolError {
    pub fn failed(e: impl std::fmt::Display) -> Self {
        Self::Failed(crate::sanitizer::redact(&e.to_string()))
    }
}

#[async_trait]
pub trait Tool: Send + Sync {
    fn spec(&self) -> ToolSpec;
    async fn call(&self, args: Value) -> Result<String, ToolError>;
    /// One-line human description of a call, shown in confirmation prompts.
    fn describe(&self, args: &Value) -> String {
        format!(
            "{}({})",
            self.spec().name,
            crate::sanitizer::redact(&args.to_string())
        )
    }
}

#[derive(Default, Clone)]
pub struct ToolRegistry {
    tools: BTreeMap<&'static str, Arc<dyn Tool>>,
}

impl ToolRegistry {
    pub fn register(&mut self, t: Arc<dyn Tool>) -> anyhow::Result<()> {
        let name = t.spec().name;
        if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
            anyhow::bail!("tool name {name} must be [A-Za-z0-9_]");
        }
        if self.tools.insert(name, t).is_some() {
            anyhow::bail!("tool {name} registered twice");
        }
        Ok(())
    }
    pub fn get(&self, name: &str) -> Option<&Arc<dyn Tool>> {
        self.tools.get(name)
    }
    pub fn specs(&self) -> Vec<ToolSpec> {
        self.tools.values().map(|t| t.spec()).collect()
    }
    pub fn is_empty(&self) -> bool {
        self.tools.is_empty()
    }
}

/// Where a turn came from. Determines which tools are even offered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    Cli,
    Http,
    Telegram,
    Sms,
    System,
}

impl Origin {
    pub fn is_remote(self) -> bool {
        matches!(self, Origin::Telegram | Origin::Sms)
    }
    pub fn to_pb(self) -> cg_audit::Origin {
        match self {
            Origin::Cli => cg_audit::Origin::Cli,
            Origin::Http => cg_audit::Origin::Http,
            Origin::Telegram => cg_audit::Origin::Telegram,
            Origin::Sms => cg_audit::Origin::Sms,
            Origin::System => cg_audit::Origin::System,
        }
    }
}

/// A human decision on a write action or an external call.
#[async_trait]
pub trait Confirmer: Send + Sync {
    async fn confirm(&self, summary: &str) -> bool;
}

/// Refuses everything. Used for SMS and any origin that cannot authenticate
/// a second factor for confirmation.
pub struct DenyAll;
#[async_trait]
impl Confirmer for DenyAll {
    async fn confirm(&self, _summary: &str) -> bool {
        false
    }
}

/// A message arriving on an inbound channel (Telegram, SMS, ...).
#[derive(Debug, Clone)]
pub struct Inbound {
    pub origin: Origin,
    /// Channel-specific sender id (Telegram user id, E.164 number). Only ever
    /// stored as an HMAC fingerprint.
    pub sender: String,
    pub text: String,
    pub attachments: Vec<crate::attachments::Attachment>,
}

/// What the agent hands back to a gateway.
#[async_trait]
pub trait InboundHandler: Send + Sync {
    async fn handle(&self, msg: Inbound, confirmer: Arc<dyn Confirmer>) -> String;
}

/// A long-running inbound channel.
#[async_trait]
pub trait Gateway: Send + Sync {
    fn name(&self) -> &'static str;
    async fn run(self: Arc<Self>, handler: Arc<dyn InboundHandler>) -> anyhow::Result<()>;
}
