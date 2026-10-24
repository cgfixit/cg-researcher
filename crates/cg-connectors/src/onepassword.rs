//! 1Password: metadata search only. Runs `op item list --format json` and
//! returns title / vault / category / URLs. It never calls `op item get` or
//! `op read`, so the model cannot obtain a secret value through this tool.
//! The query is matched locally and is never passed to `op` (no argv injection).

use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use cg_core::sandbox::clean_command;
use cg_core::tools::{Effect, Tool, ToolError, ToolSpec};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::common::{arg_str, arg_usize, clip};
use crate::{Ctx, Parts};

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct OpConfig {
    pub enabled: bool,
    pub vaults: Vec<String>,
}

pub struct OpSearch {
    op: PathBuf,
    vaults: Vec<String>,
}

pub async fn build(ctx: &Ctx<'_>) -> anyhow::Result<Parts> {
    let c: OpConfig = crate::common::section(ctx.connectors, "onepassword")?;
    if !c.enabled {
        return Ok(Parts::default());
    }
    let op = cg_core::secrets::find_op()
        .ok_or_else(|| anyhow::anyhow!("onepassword: `op` CLI not found at fixed paths"))?;
    for v in &c.vaults {
        anyhow::ensure!(
            !v.is_empty() && !v.starts_with('-') && v.len() <= 100,
            "onepassword: invalid vault name"
        );
    }
    Ok(Parts {
        tools: vec![Arc::new(OpSearch {
            op,
            vaults: c.vaults,
        })],
        ..Default::default()
    })
}

#[derive(Debug, PartialEq)]
pub struct ItemMeta {
    pub title: String,
    pub vault: String,
    pub category: String,
    pub urls: Vec<String>,
}

/// Project `op item list` JSON down to the four allowed fields.
pub fn project(items: &Value, query: &str, max: usize) -> Vec<ItemMeta> {
    let q = query.to_lowercase();
    items
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|it| {
            let title = it["title"].as_str()?.to_string();
            let urls: Vec<String> = it["urls"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|u| u["href"].as_str().map(|s| clip(s, 200)))
                .take(5)
                .collect();
            let hay = format!("{} {}", title.to_lowercase(), urls.join(" ").to_lowercase());
            hay.contains(&q).then(|| ItemMeta {
                title: clip(&title, 200),
                vault: clip(it["vault"]["name"].as_str().unwrap_or(""), 100),
                category: clip(it["category"].as_str().unwrap_or(""), 40),
                urls,
            })
        })
        .take(max)
        .collect()
}

#[async_trait]
impl Tool for OpSearch {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "onepassword_search",
            description: "Find 1Password items by title or URL. Returns metadata only (title, vault, category, URLs) - never passwords or fields.",
            parameters: json!({"type":"object","properties":{"query":{"type":"string","minLength":1,"maxLength":100},"max":{"type":"integer","minimum":1,"maximum":25}},"required":["query"],"additionalProperties":false}),
            effect: Effect::Read,
            untrusted_output: true,
            remote_ok: false,
        }
    }
    async fn call(&self, args: Value) -> Result<String, ToolError> {
        let q = arg_str(&args, "query", 1, 100)?;
        let max = arg_usize(&args, "max", 10, 1, 25)?;
        let vaults: Vec<Option<&str>> = if self.vaults.is_empty() {
            vec![None]
        } else {
            self.vaults.iter().map(|v| Some(v.as_str())).collect()
        };
        let mut found = Vec::new();
        for v in vaults {
            let mut cmd = clean_command(&self.op, &["OP_SERVICE_ACCOUNT_TOKEN", "OP_ACCOUNT"]);
            cmd.args(["item", "list", "--format", "json"]);
            if let Some(v) = v {
                cmd.arg(format!("--vault={v}"));
            }
            let out = tokio::time::timeout(std::time::Duration::from_secs(30), cmd.output())
                .await
                .map_err(|_| ToolError::Failed("op timed out (is 1Password unlocked?)".into()))?
                .map_err(ToolError::failed)?;
            if !out.status.success() {
                return Err(ToolError::Failed(
                    "op item list failed (sign in / unlock 1Password)".into(),
                ));
            }
            let items: Value = serde_json::from_slice(&out.stdout)
                .map_err(|_| ToolError::Failed("op returned non-JSON".into()))?;
            found.extend(project(&items, q, max));
            if found.len() >= max {
                break;
            }
        }
        found.truncate(max);
        if found.is_empty() {
            return Ok("no matching items".into());
        }
        Ok(found
            .iter()
            .map(|m| {
                format!(
                    "- {} [{}] vault={} {}",
                    m.title,
                    m.category,
                    m.vault,
                    m.urls.join(" ")
                )
            })
            .collect::<Vec<_>>()
            .join("\n"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_metadata_survives() {
        let items = json!([
            {"id":"x","title":"GitHub","category":"LOGIN","vault":{"id":"v","name":"Private"},
             "urls":[{"href":"https://github.com"}],"fields":[{"value":"hunter2"}],"password":"hunter2"},
            {"title":"Bank","category":"LOGIN","vault":{"name":"Private"}}
        ]);
        let r = project(&items, "git", 10);
        assert_eq!(
            r,
            vec![ItemMeta {
                title: "GitHub".into(),
                vault: "Private".into(),
                category: "LOGIN".into(),
                urls: vec!["https://github.com".into()]
            }]
        );
        assert!(!format!("{r:?}").contains("hunter2"));
    }
}
