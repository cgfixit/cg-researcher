//! cg-connectors: every outbound integration and inbound gateway.
//!
//! Adding a connector = one module with `async fn build(&Ctx) -> Parts`
//! plus one line in [`REGISTRY`]. Rules every connector follows:
//! * ships `enabled = false`; strict `deny_unknown_fields` config;
//! * secrets only via `SecretStore` references, never inline;
//! * HTTP only through a host-pinned `Egress` (HTTPS, no redirects, no proxy);
//! * third-party text is flagged `untrusted_output` (taints the turn);
//! * anything that sends/creates is `Effect::Write` (needs a human yes);
//! * inbound gateways require a non-empty allowlist and fail loud otherwise.
#![forbid(unsafe_code)]

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use cg_core::config::Config;
use cg_core::secrets::SecretStore;
use cg_core::tools::{Gateway, Tool, ToolRegistry};

pub mod common;
pub mod fetch_page;
pub mod gcal;
pub mod gmail;
pub mod google;
pub mod netconnect;
pub mod onepassword;
pub mod sms;
pub mod telegram;
pub mod web_search;

pub struct Ctx<'a> {
    pub cfg: &'a Config,
    pub connectors: &'a toml::Table,
    pub secrets: &'a SecretStore,
}

#[derive(Default)]
pub struct Parts {
    pub tools: Vec<Arc<dyn Tool>>,
    pub gateways: Vec<Arc<dyn Gateway>>,
}

type BuildFut<'a> = Pin<Box<dyn Future<Output = anyhow::Result<Parts>> + Send + 'a>>;
type BuildFn = for<'a> fn(&'a Ctx<'a>) -> BuildFut<'a>;

macro_rules! entry {
    ($name:literal, $m:ident) => {
        ($name, (|ctx| Box::pin($m::build(ctx))) as BuildFn)
    };
}

/// The connector registry. Order is the tool-listing order.
pub const REGISTRY: &[(&str, BuildFn)] = &[
    entry!("web_search", web_search),
    entry!("fetch_page", fetch_page),
    entry!("netconnect", netconnect),
    entry!("telegram", telegram),
    entry!("gmail", gmail),
    entry!("gcal", gcal),
    entry!("onepassword", onepassword),
    entry!("sms", sms),
];

pub struct Built {
    pub tools: ToolRegistry,
    pub gateways: Vec<Arc<dyn Gateway>>,
    pub enabled: Vec<&'static str>,
}

/// Build every enabled connector. Any misconfigured enabled connector is a
/// hard error: we never start with a silently weakened policy.
pub async fn build_all(cfg: &Config, secrets: &SecretStore) -> anyhow::Result<Built> {
    for key in cfg.connectors.keys() {
        anyhow::ensure!(
            REGISTRY.iter().any(|(n, _)| n == key),
            "unknown connector section [connectors.{key}]"
        );
    }
    let ctx = Ctx {
        cfg,
        connectors: &cfg.connectors,
        secrets,
    };
    let mut tools = ToolRegistry::default();
    let mut gateways = Vec::new();
    let mut enabled = Vec::new();
    for (name, f) in REGISTRY {
        let parts = f(&ctx).await?;
        if !parts.tools.is_empty() || !parts.gateways.is_empty() {
            enabled.push(*name);
        }
        for t in parts.tools {
            tools.register(t)?;
        }
        gateways.extend(parts.gateways);
    }
    Ok(Built {
        tools,
        gateways,
        enabled,
    })
}

/// OAuth scopes needed by the enabled Google connectors (least privilege).
pub fn google_scopes(cfg: &Config) -> anyhow::Result<Vec<&'static str>> {
    let gm: google::GoogleCreds = common::section(&cfg.connectors, "gmail")?;
    let gc: google::GoogleCreds = common::section(&cfg.connectors, "gcal")?;
    let mut s = Vec::new();
    if gm.enabled {
        s.extend([
            google::SCOPE_GMAIL_READ,
            google::SCOPE_GMAIL_COMPOSE,
            google::SCOPE_GMAIL_SEND,
        ]);
    }
    if gc.enabled {
        s.push(google::SCOPE_CAL_EVENTS);
    }
    Ok(s)
}

/// Client credentials for the Google consent flow (from gmail or gcal).
pub async fn google_client(
    cfg: &Config,
    secrets: &SecretStore,
) -> anyhow::Result<(cg_core::secrets::Secret, cg_core::secrets::Secret)> {
    let gm: google::GoogleCreds = common::section(&cfg.connectors, "gmail")?;
    let gc: google::GoogleCreds = common::section(&cfg.connectors, "gcal")?;
    let c = if gm.enabled { gm } else { gc };
    Ok((
        secrets.resolve(&c.client_id_ref).await?,
        secrets.resolve(&c.client_secret_ref).await?,
    ))
}

#[cfg(test)]
pub(crate) fn test_secret(v: &str) -> cg_core::secrets::Secret {
    cg_core::secrets::Secret::minted(v.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn shipped_config_enables_nothing() {
        let text = include_str!("../../../config/cg.toml");
        let cfg = Config::from_toml(text).expect("shipped config parses");
        let built = build_all(&cfg, &SecretStore::new(std::env::temp_dir()))
            .await
            .expect("build");
        assert!(built.enabled.is_empty() && built.tools.is_empty() && built.gateways.is_empty());
        assert!(google_scopes(&cfg).expect("scopes").is_empty());
    }

    #[tokio::test]
    async fn unknown_section_and_unknown_key_rejected() {
        let mut cfg = Config::default();
        cfg.connectors
            .insert("slack".into(), toml::Value::Table(toml::Table::new()));
        assert!(
            build_all(&cfg, &SecretStore::new(std::env::temp_dir()))
                .await
                .is_err()
        );
        let mut cfg = Config::default();
        cfg.connectors.insert(
            "netconnect".into(),
            toml::Value::Table(toml::from_str("enabled = false\nallow_all = true").expect("t")),
        );
        assert!(
            build_all(&cfg, &SecretStore::new(std::env::temp_dir()))
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn every_writer_is_confirmed_and_local_only() {
        // Build tool specs without network by constructing Gmail/Gcal parts directly is
        // not possible without secrets; check the spec tables instead.
        let names = ["gmail_create_draft", "gmail_send", "gcal_create_event"];
        let src = [include_str!("gmail.rs"), include_str!("gcal.rs")].concat();
        for n in names {
            let i = src.find(&format!("name: \"{n}\"")).expect("spec present");
            let tail = &src[i..i + 600];
            assert!(
                tail.contains("Effect::Write") && tail.contains("remote_ok: false"),
                "{n}"
            );
        }
    }
}
