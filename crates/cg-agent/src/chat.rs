//! Interactive CLI chat with `/attach <path>` and a y/N stdin confirmer.

use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use cg_core::agent::{Agent, TurnRequest};
use cg_core::attachments::{self, Attachment};
use cg_core::config::AttachmentConfig;
use cg_core::tools::{Confirmer, Origin};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, Lines, Stdin};
use tokio::sync::Mutex;

type In = Arc<Mutex<Lines<BufReader<Stdin>>>>;

struct StdinConfirmer(In);

#[async_trait]
impl Confirmer for StdinConfirmer {
    async fn confirm(&self, summary: &str) -> bool {
        eprintln!("\n--- confirmation required ---\n{summary}\n-----------------------------");
        eprint!("approve? [y/N] ");
        let mut g = self.0.lock().await;
        matches!(g.next_line().await, Ok(Some(l)) if l.trim().eq_ignore_ascii_case("y") || l.trim().eq_ignore_ascii_case("yes"))
    }
}

pub fn load_attachment(path: &Path, lim: &AttachmentConfig) -> anyhow::Result<Attachment> {
    let meta = std::fs::symlink_metadata(path)?;
    anyhow::ensure!(meta.is_file(), "not a regular file (symlinks refused)");
    anyhow::ensure!(
        meta.len() as usize <= lim.max_bytes,
        "file exceeds attachments.max_bytes"
    );
    let bytes = std::fs::read(path)?;
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("file");
    Ok(attachments::parse(name, &bytes, lim)?)
}

pub async fn run(agent: Arc<Agent>) -> anyhow::Result<()> {
    let lines: In = Arc::new(Mutex::new(BufReader::new(tokio::io::stdin()).lines()));
    let confirmer: Arc<dyn Confirmer> = Arc::new(StdinConfirmer(lines.clone()));
    let lim = agent.config().attachments.clone();
    let mut pending: Vec<Attachment> = Vec::new();
    eprintln!(
        "cg-agent chat — model {} | external {} | tools {} | /attach <path>  /clear  /quit",
        agent.config().llm.model,
        if agent.has_external() {
            "configured (asks first)"
        } else {
            "off"
        },
        agent.tool_specs().len()
    );
    let mut out = tokio::io::stdout();
    loop {
        eprint!("\n> ");
        let line = { lines.lock().await.next_line().await? };
        let Some(line) = line else { break };
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }
        if line == "/quit" || line == "/exit" {
            break;
        }
        if line == "/clear" {
            pending.clear();
            eprintln!("attachments cleared");
            continue;
        }
        if let Some(p) = line.strip_prefix("/attach ") {
            let p = p.trim().trim_matches(['"', '\'']);
            let p = if let Some(rest) = p.strip_prefix("~/") {
                std::path::PathBuf::from(std::env::var("HOME").unwrap_or_default()).join(rest)
            } else {
                std::path::PathBuf::from(p)
            };
            match load_attachment(&p, &lim) {
                Ok(a) if pending.len() < lim.max_per_turn => {
                    eprintln!(
                        "attached {} ({}, {} bytes{})",
                        a.name,
                        a.kind.label(),
                        a.bytes,
                        if a.truncated { ", truncated" } else { "" }
                    );
                    pending.push(a);
                }
                Ok(_) => eprintln!("at most {} attachments per turn", lim.max_per_turn),
                Err(e) => eprintln!("attach failed: {e}"),
            }
            continue;
        }
        let req = TurnRequest {
            query: line,
            origin: Origin::Cli,
            sender: "cli".into(),
            attachments: std::mem::take(&mut pending),
            confirm_online: None,
            confirmer: confirmer.clone(),
        };
        let r = crate::runtime::run_turn(&agent, req).await;
        out.write_all(format!("{}\n", r.answer).as_bytes()).await?;
        out.flush().await?;
        eprintln!(
            "[{}{}{} | {}]",
            r.answer_model,
            if r.tainted { " | tainted" } else { "" },
            if r.sources.is_empty() {
                String::new()
            } else {
                format!(" | sources: {}", r.sources.join(", "))
            },
            r.path.join("→")
        );
    }
    Ok(())
}
