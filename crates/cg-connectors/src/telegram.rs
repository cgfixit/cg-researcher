//! Telegram gateway: long-polls getUpdates (no public webhook, no listening
//! port). Private chats only; sender must be in a numeric user-id allowlist.
//! An empty allowlist with `enabled = true` is a startup error.
//! Backlog queued while the agent was offline is discarded at startup, so
//! stale commands are never replayed.

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use cg_core::attachments::{self, Attachment};
use cg_core::config::AttachmentConfig;
use cg_core::egress::Egress;
use cg_core::secrets::Secret;
use cg_core::tools::{Confirmer, DenyAll, Gateway, Inbound, InboundHandler, Origin, ToolError};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::Mutex;

use crate::common::{clip, json_body, read_capped, send};
use crate::{Ctx, Parts};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct TelegramConfig {
    pub enabled: bool,
    pub bot_token_ref: String,
    pub allowed_user_ids: Vec<i64>,
    pub allow_confirm: bool,
    pub poll_secs: u64,
}
impl Default for TelegramConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bot_token_ref: "env:TELEGRAM_BOT_TOKEN".into(),
            allowed_user_ids: vec![],
            allow_confirm: false,
            poll_secs: 30,
        }
    }
}

const API: &str = "https://api.telegram.org";
const MAX_PER_MIN: usize = 20;
const CONFIRM_WINDOW: Duration = Duration::from_secs(120);

pub struct Telegram {
    egress: Egress,
    api: String,
    token: Secret,
    allowed: Vec<i64>,
    allow_confirm: bool,
    poll_secs: u64,
    limits: AttachmentConfig,
    offset: Mutex<Option<i64>>,
    recent: Mutex<VecDeque<Instant>>,
    /// Updates a confirmer fetched while waiting for its code but did not
    /// consume. `fetch` already moved the offset past them, so `poll_once`
    /// handles these before fetching again.
    pending: Mutex<VecDeque<Value>>,
}

/// Bound on `pending` (a flood during one confirmation drops the oldest).
const MAX_PENDING: usize = 100;

pub async fn build(ctx: &Ctx<'_>) -> anyhow::Result<Parts> {
    let c: TelegramConfig = crate::common::section(ctx.connectors, "telegram")?;
    if !c.enabled {
        return Ok(Parts::default());
    }
    anyhow::ensure!(
        !c.allowed_user_ids.is_empty(),
        "telegram is enabled but allowed_user_ids is empty (refusing to answer everyone)"
    );
    anyhow::ensure!(
        c.allowed_user_ids.iter().all(|&id| id > 0),
        "telegram allowed_user_ids must be positive user ids, not chat ids"
    );
    let token = ctx
        .secrets
        .resolve(&c.bot_token_ref)
        .await
        .map_err(|e| anyhow::anyhow!("telegram bot token: {e}"))?;
    let egress = Egress::new(
        "telegram",
        &["api.telegram.org"],
        false,
        Duration::from_secs(c.poll_secs.clamp(5, 50) + 15),
    )?;
    let tg = Telegram::new(egress, API.into(), token, c, ctx.cfg.attachments.clone());
    Ok(Parts {
        gateways: vec![Arc::new(tg)],
        ..Default::default()
    })
}

impl Telegram {
    pub(crate) fn new(
        egress: Egress,
        api: String,
        token: Secret,
        c: TelegramConfig,
        limits: AttachmentConfig,
    ) -> Self {
        Self {
            egress,
            api,
            token,
            allowed: c.allowed_user_ids,
            allow_confirm: c.allow_confirm,
            poll_secs: c.poll_secs.clamp(1, 50),
            limits,
            offset: Mutex::new(None),
            recent: Mutex::new(VecDeque::new()),
            pending: Mutex::new(VecDeque::new()),
        }
    }

    fn url(&self, method: &str) -> String {
        format!("{}/bot{}/{method}", self.api, self.token.expose())
    }

    async fn call(&self, method: &str, body: Value) -> Result<Value, ToolError> {
        let (s, b) = send(
            self.egress
                .post(&self.url(method))
                .map_err(ToolError::failed)?
                .json(&body),
        )
        .await?;
        let v = json_body(&b)?;
        if s != 200 || v["ok"] != true {
            return Err(ToolError::Failed(format!("telegram {method} HTTP {s}")));
        }
        Ok(v["result"].clone())
    }

    pub async fn send_text(&self, chat_id: i64, text: &str) -> Result<(), ToolError> {
        let chars: Vec<char> = text.chars().collect();
        for chunk in chars.chunks(3900).take(6) {
            self.call("sendMessage", json!({"chat_id": chat_id, "text": chunk.iter().collect::<String>(), "disable_web_page_preview": true}))
                .await?;
        }
        Ok(())
    }

    /// Skip anything queued while we were offline.
    async fn drop_backlog(&self) -> Result<(), ToolError> {
        let r = self
            .call("getUpdates", json!({"offset": -1, "timeout": 0}))
            .await?;
        let last = r
            .as_array()
            .and_then(|a| a.last())
            .and_then(|u| u["update_id"].as_i64());
        *self.offset.lock().await = Some(last.map_or(0, |l| l + 1));
        Ok(())
    }

    async fn fetch(&self, timeout: u64) -> Result<Vec<Value>, ToolError> {
        let off = *self.offset.lock().await;
        let r = self
            .call("getUpdates", json!({"offset": off.unwrap_or(0), "timeout": timeout, "allowed_updates": ["message"]}))
            .await?;
        let ups = r.as_array().cloned().unwrap_or_default();
        if let Some(max) = ups.iter().filter_map(|u| u["update_id"].as_i64()).max() {
            *self.offset.lock().await = Some(max + 1);
        }
        Ok(ups)
    }

    /// Returns (chat_id, user_id, message) only for allowlisted private DMs from humans.
    pub fn accept<'a>(&self, update: &'a Value) -> Option<(i64, i64, &'a Value)> {
        let m = update.get("message")?;
        if m["chat"]["type"].as_str() != Some("private")
            || m["from"]["is_bot"].as_bool() != Some(false)
        {
            return None;
        }
        let uid = m["from"]["id"].as_i64()?;
        let chat = m["chat"]["id"].as_i64()?;
        (self.allowed.contains(&uid) && chat == uid).then_some((chat, uid, m))
    }

    async fn rate_ok(&self) -> bool {
        let mut r = self.recent.lock().await;
        let now = Instant::now();
        while r
            .front()
            .is_some_and(|t| now.duration_since(*t) > Duration::from_secs(60))
        {
            r.pop_front();
        }
        if r.len() >= MAX_PER_MIN {
            return false;
        }
        r.push_back(now);
        true
    }

    async fn download(&self, file_id: &str, name: &str, size: u64) -> Result<Attachment, String> {
        if size as usize > self.limits.max_bytes {
            return Err(format!("{name}: too large"));
        }
        let f = self
            .call("getFile", json!({"file_id": file_id}))
            .await
            .map_err(|e| e.to_string())?;
        let path = f["file_path"].as_str().unwrap_or("");
        if path.is_empty()
            || path.contains("..")
            || !path
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_./-".contains(&b))
        {
            return Err("bad file path from Telegram".into());
        }
        let url = format!("{}/file/bot{}/{path}", self.api, self.token.expose());
        let resp = self
            .egress
            .get(&url)
            .map_err(|e| e.to_string())?
            .send()
            .await
            .map_err(|e| e.without_url().to_string())?;
        if !resp.status().is_success() {
            return Err("file download failed".into());
        }
        let bytes = read_capped(resp, self.limits.max_bytes)
            .await
            .map_err(|e| e.to_string())?;
        attachments::parse(name, &bytes, &self.limits).map_err(|e| e.to_string())
    }

    async fn collect_attachments(&self, m: &Value) -> (Vec<Attachment>, Vec<String>) {
        let mut out = Vec::new();
        let mut errs = Vec::new();
        if let Some(d) = m.get("document") {
            let name = d["file_name"].as_str().unwrap_or("file");
            match self
                .download(
                    d["file_id"].as_str().unwrap_or(""),
                    name,
                    d["file_size"].as_u64().unwrap_or(u64::MAX),
                )
                .await
            {
                Ok(a) => out.push(a),
                Err(e) => errs.push(e),
            }
        }
        // Telegram re-encodes photos as JPEG; only PNG sent "as file" is supported.
        if m.get("photo").is_some() {
            errs.push(
                "photos are re-encoded to JPEG by Telegram; send PNG as a file instead".into(),
            );
        }
        (out, errs)
    }

    /// One poll cycle. Public for tests; `run` loops it with backoff.
    pub async fn poll_once(
        self: &Arc<Self>,
        handler: &Arc<dyn InboundHandler>,
        timeout: u64,
    ) -> Result<usize, ToolError> {
        let mut handled = 0;
        let queued: Vec<Value> = self.pending.lock().await.drain(..).collect();
        let ups = if queued.is_empty() {
            self.fetch(timeout).await?
        } else {
            queued
        };
        for u in ups {
            let Some((chat, uid, m)) = self.accept(&u) else {
                tracing::debug!(
                    "telegram: dropped update from non-allowlisted or non-private chat"
                );
                continue;
            };
            if !self.rate_ok().await {
                let _ = self
                    .send_text(chat, "rate limited; try again in a minute")
                    .await;
                continue;
            }
            let text = m["text"]
                .as_str()
                .or(m["caption"].as_str())
                .unwrap_or("")
                .to_string();
            let (atts, errs) = self.collect_attachments(m).await;
            if text.trim().is_empty() && atts.is_empty() {
                if !errs.is_empty() {
                    let _ = self.send_text(chat, &errs.join("\n")).await;
                }
                continue;
            }
            let confirmer: Arc<dyn Confirmer> = if self.allow_confirm {
                Arc::new(TelegramConfirmer {
                    tg: self.clone(),
                    chat,
                    uid,
                })
            } else {
                Arc::new(DenyAll)
            };
            let reply = handler
                .handle(
                    Inbound {
                        origin: Origin::Telegram,
                        sender: uid.to_string(),
                        text: clip(&text, 8000),
                        attachments: atts,
                    },
                    confirmer,
                )
                .await;
            let reply = if errs.is_empty() {
                reply
            } else {
                format!("{reply}\n\n(attachment notes: {})", errs.join("; "))
            };
            // The offset already moved past this whole batch, so one failed
            // reply must not drop the messages after it.
            if let Err(e) = self.send_text(chat, &reply).await {
                tracing::warn!("telegram: reply failed: {e}");
            }
            handled += 1;
        }
        Ok(handled)
    }
}

/// Confirmation by one-time 6-digit code typed back in the same DM.
struct TelegramConfirmer {
    tg: Arc<Telegram>,
    chat: i64,
    uid: i64,
}

#[async_trait]
impl Confirmer for TelegramConfirmer {
    async fn confirm(&self, summary: &str) -> bool {
        let mut b = [0u8; 4];
        if getrandom::fill(&mut b).is_err() {
            return false;
        }
        let code = format!("{:06}", u32::from_le_bytes(b) % 1_000_000);
        let prompt = format!(
            "Approve?\n{}\n\nReply with code {code} within 2 minutes. Anything else = deny.",
            clip(summary, 1500)
        );
        if self.tg.send_text(self.chat, &prompt).await.is_err() {
            return false;
        }
        let deadline = Instant::now() + CONFIRM_WINDOW;
        while Instant::now() < deadline {
            let Ok(ups) = self.tg.fetch(10).await else {
                return false;
            };
            let mut answer = None;
            let mut rest = Vec::new();
            for u in ups {
                match self.tg.accept(&u) {
                    Some((_, uid, m)) if uid == self.uid && answer.is_none() => {
                        answer = Some(
                            m["text"]
                                .as_str()
                                .is_some_and(|t| crate::common::ct_eq(t.trim(), &code)),
                        );
                    }
                    _ => rest.push(u),
                }
            }
            if !rest.is_empty() {
                let mut q = self.tg.pending.lock().await;
                q.extend(rest);
                while q.len() > MAX_PENDING {
                    q.pop_front();
                }
            }
            if let Some(ok) = answer {
                let _ = self
                    .tg
                    .send_text(self.chat, if ok { "approved" } else { "denied" })
                    .await;
                return ok;
            }
        }
        false
    }
}

#[async_trait]
impl Gateway for Telegram {
    fn name(&self) -> &'static str {
        "telegram"
    }
    async fn run(self: Arc<Self>, handler: Arc<dyn InboundHandler>) -> anyhow::Result<()> {
        self.drop_backlog()
            .await
            .map_err(|e| anyhow::anyhow!("telegram startup: {e}"))?;
        tracing::info!(
            "telegram gateway polling ({} allowlisted user(s))",
            self.allowed.len()
        );
        let mut backoff = 1u64;
        loop {
            match self.poll_once(&handler, self.poll_secs).await {
                Ok(_) => backoff = 1,
                Err(e) => {
                    tracing::warn!(
                        "telegram poll: {}",
                        cg_core::sanitizer::redact(&e.to_string())
                    );
                    tokio::time::sleep(Duration::from_secs(backoff)).await;
                    backoff = (backoff * 2).min(300);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::mock;
    use std::sync::Mutex as StdMutex;

    struct Rec(StdMutex<Vec<Inbound>>);
    #[async_trait]
    impl InboundHandler for Rec {
        async fn handle(&self, msg: Inbound, c: Arc<dyn Confirmer>) -> String {
            assert!(!c.confirm("x").await, "allow_confirm=false must deny");
            self.0.lock().expect("lock").push(msg);
            "pong".into()
        }
    }

    fn upd(id: i64, uid: i64, chat: i64, kind: &str, text: &str) -> Value {
        json!({"update_id": id, "message": {"from": {"id": uid, "is_bot": false}, "chat": {"id": chat, "type": kind}, "text": text}})
    }

    #[tokio::test]
    async fn only_allowlisted_private_dms_reach_the_agent() {
        let ups = json!({"ok": true, "result": [
            upd(1, 42, 42, "private", "hello"),
            upd(2, 99, 99, "private", "intruder"),
            upd(3, 42, -100, "group", "group msg"),
            {"update_id": 4, "message": {"from": {"id": 42, "is_bot": true}, "chat": {"id": 42, "type": "private"}, "text": "bot"}}
        ]});
        let m = mock::serve(Arc::new(move |line, _| {
            if line.contains("getUpdates") {
                (200, ups.to_string())
            } else {
                (200, r#"{"ok":true,"result":{}}"#.into())
            }
        }))
        .await;
        let cfg = TelegramConfig {
            enabled: true,
            allowed_user_ids: vec![42],
            ..Default::default()
        };
        let tg = Arc::new(Telegram::new(
            mock::loopback_egress(),
            m.base.clone(),
            Secret::minted("123456:ABCDEFtesttoken".into()),
            cfg,
            AttachmentConfig::default(),
        ));
        let rec = Arc::new(Rec(StdMutex::new(vec![])));
        let h: Arc<dyn InboundHandler> = rec.clone();
        assert_eq!(tg.poll_once(&h, 0).await.expect("poll"), 1);
        {
            let got = rec.0.lock().expect("lock");
            assert_eq!(got.len(), 1);
            assert_eq!(
                (got[0].text.as_str(), got[0].origin),
                ("hello", Origin::Telegram)
            );
        }
        assert_eq!(*tg.offset.lock().await, Some(5));
        let seen = m.seen.lock().expect("lock");
        assert_eq!(
            seen.iter()
                .filter(|(l, _)| l.contains("sendMessage"))
                .count(),
            1,
            "no reply to non-allowlisted senders"
        );
    }

    struct Confirming(StdMutex<Vec<String>>);
    #[async_trait]
    impl InboundHandler for Confirming {
        async fn handle(&self, msg: Inbound, c: Arc<dyn Confirmer>) -> String {
            if msg.text == "do it" {
                let _ = c.confirm("send mail").await;
            }
            self.0.lock().expect("lock").push(msg.text);
            "ok".into()
        }
    }

    #[tokio::test]
    async fn messages_fetched_during_a_confirmation_are_not_lost() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let c2 = calls.clone();
        let m = mock::serve(Arc::new(move |line, _| {
            if !line.contains("getUpdates") {
                return (200, r#"{"ok":true,"result":{}}"#.into());
            }
            let r = match c2.fetch_add(1, std::sync::atomic::Ordering::SeqCst) {
                0 => json!([upd(1, 42, 42, "private", "do it")]),
                // While 42 is being asked for a code: 7 writes, 42 answers
                // (wrong code) and then asks a follow-up in the same batch.
                1 => json!([
                    upd(2, 7, 7, "private", "from seven"),
                    upd(3, 42, 42, "private", "000000"),
                    upd(4, 42, 42, "private", "follow-up"),
                ]),
                _ => json!([]),
            };
            (200, json!({"ok": true, "result": r}).to_string())
        }))
        .await;
        let cfg = TelegramConfig {
            enabled: true,
            allowed_user_ids: vec![42, 7],
            allow_confirm: true,
            ..Default::default()
        };
        let tg = Arc::new(Telegram::new(
            mock::loopback_egress(),
            m.base.clone(),
            Secret::minted("123456:ABCDEFtesttoken".into()),
            cfg,
            AttachmentConfig::default(),
        ));
        let rec = Arc::new(Confirming(StdMutex::new(vec![])));
        let h: Arc<dyn InboundHandler> = rec.clone();
        tg.poll_once(&h, 0).await.expect("poll 1");
        tg.poll_once(&h, 0).await.expect("poll 2");
        assert_eq!(
            *rec.0.lock().expect("lock"),
            ["do it", "from seven", "follow-up"]
        );
    }

    #[tokio::test]
    async fn empty_allowlist_fails_loud() {
        let mut t = toml::Table::new();
        t.insert(
            "telegram".into(),
            toml::Value::Table(
                toml::from_str("enabled = true\nallowed_user_ids = []").expect("toml"),
            ),
        );
        let cfg = cg_core::config::Config::default();
        let secrets = cg_core::secrets::SecretStore::new(std::env::temp_dir());
        let ctx = Ctx {
            cfg: &cfg,
            connectors: &t,
            secrets: &secrets,
        };
        let e = build(&ctx).await.err().expect("must fail");
        assert!(e.to_string().contains("allowed_user_ids is empty"));
    }
}
