//! SMS gateway (Twilio). Polls the Messages list API - no public webhook,
//! no inbound port. Sender must be an allowlisted E.164 number AND (by
//! default) prefix the message with a PIN, because caller ID is spoofable.
//! SMS turns can never confirm anything (DenyAll) and only see read tools.
//! Processed inbound messages are deleted from Twilio (best-effort) so the
//! PIN does not sit in the provider's message log.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use cg_core::egress::Egress;
use cg_core::secrets::Secret;
use cg_core::tools::{DenyAll, Gateway, Inbound, InboundHandler, Origin, ToolError};
use serde::Deserialize;
use serde_json::Value;
use tokio::sync::Mutex;

use crate::common::{clip, ct_eq, egress, is_e164, json_body, send};
use crate::{Ctx, Parts};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SmsConfig {
    pub enabled: bool,
    pub provider: String,
    pub account_sid_ref: String,
    pub auth_token_ref: String,
    pub from_number: String,
    pub allowed_numbers: Vec<String>,
    pub require_pin: bool,
    pub pin_ref: String,
    pub poll_secs: u64,
}
impl Default for SmsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            provider: "twilio".into(),
            account_sid_ref: "env:TWILIO_ACCOUNT_SID".into(),
            auth_token_ref: "env:TWILIO_AUTH_TOKEN".into(),
            from_number: String::new(),
            allowed_numbers: vec![],
            require_pin: true,
            pin_ref: "file:sms_pin".into(),
            poll_secs: 20,
        }
    }
}

const API: &str = "https://api.twilio.com";
const MAX_FAILS: u32 = 5;
const LOCKOUT: Duration = Duration::from_secs(3600);

pub struct Sms {
    egress: Egress,
    api: String,
    sid: Secret,
    token: Secret,
    from: String,
    allowed: Vec<String>,
    pin: Option<Secret>,
    poll_secs: u64,
    seen: Mutex<(HashSet<String>, VecDeque<String>, bool)>,
    fails: Mutex<HashMap<String, (u32, Instant)>>,
}

fn valid_sid(s: &str, prefix: &[&str]) -> bool {
    s.len() == 34
        && prefix.iter().any(|p| s.starts_with(p))
        && s[2..].bytes().all(|b| b.is_ascii_hexdigit())
}

pub async fn build(ctx: &Ctx<'_>) -> anyhow::Result<Parts> {
    let c: SmsConfig = crate::common::section(ctx.connectors, "sms")?;
    if !c.enabled {
        return Ok(Parts::default());
    }
    anyhow::ensure!(
        c.provider == "twilio",
        "sms: only provider = \"twilio\" is implemented"
    );
    anyhow::ensure!(
        is_e164(&c.from_number),
        "sms: from_number must be E.164 (+14045550123)"
    );
    anyhow::ensure!(
        !c.allowed_numbers.is_empty(),
        "sms is enabled but allowed_numbers is empty (refusing to answer everyone)"
    );
    for n in &c.allowed_numbers {
        anyhow::ensure!(is_e164(n), "sms: allowed number {n} is not E.164");
    }
    let sid = ctx
        .secrets
        .resolve(&c.account_sid_ref)
        .await
        .map_err(|e| anyhow::anyhow!("sms account sid: {e}"))?;
    anyhow::ensure!(
        valid_sid(sid.expose(), &["AC"]),
        "sms: account SID must look like AC + 32 hex"
    );
    let token = ctx
        .secrets
        .resolve(&c.auth_token_ref)
        .await
        .map_err(|e| anyhow::anyhow!("sms auth token: {e}"))?;
    let pin = if c.require_pin {
        let p = ctx.secrets.resolve(&c.pin_ref).await.map_err(|e| {
            anyhow::anyhow!("sms pin ({e}); run `cg-researcher init` or set pin_ref")
        })?;
        anyhow::ensure!(
            p.expose().len() >= 6 && !p.expose().contains(char::is_whitespace),
            "sms: PIN must be >= 6 non-space characters"
        );
        Some(p)
    } else {
        tracing::warn!("sms: require_pin = false; caller ID alone is spoofable");
        None
    };
    let s = Sms::new(
        egress("sms", &["api.twilio.com"])?,
        API.into(),
        sid,
        token,
        c,
        pin,
    );
    Ok(Parts {
        gateways: vec![Arc::new(s)],
        ..Default::default()
    })
}

pub enum Verdict {
    Accept(String),
    Ignore,
}

impl Sms {
    pub(crate) fn new(
        egress: Egress,
        api: String,
        sid: Secret,
        token: Secret,
        c: SmsConfig,
        pin: Option<Secret>,
    ) -> Self {
        Self {
            egress,
            api,
            sid,
            token,
            from: c.from_number,
            allowed: c.allowed_numbers,
            pin,
            poll_secs: c.poll_secs.clamp(5, 600),
            seen: Mutex::new((HashSet::new(), VecDeque::new(), false)),
            fails: Mutex::new(HashMap::new()),
        }
    }

    fn messages_url(&self) -> String {
        format!(
            "{}/2010-04-01/Accounts/{}/Messages.json",
            self.api,
            self.sid.expose()
        )
    }

    /// Allowlist + PIN + lockout. Never replies to unknown numbers (costs
    /// money and confirms the agent exists).
    pub async fn check(&self, from: &str, body: &str) -> Verdict {
        if !self.allowed.iter().any(|a| a == from) {
            return Verdict::Ignore;
        }
        let mut fails = self.fails.lock().await;
        if let Some((n, t)) = fails.get(from)
            && *n >= MAX_FAILS
            && t.elapsed() < LOCKOUT
        {
            return Verdict::Ignore;
        }
        let text = match &self.pin {
            None => body.trim().to_string(),
            Some(pin) => {
                let (head, rest) = body
                    .trim()
                    .split_once(char::is_whitespace)
                    .unwrap_or((body.trim(), ""));
                if !ct_eq(head, pin.expose()) {
                    let e = fails.entry(from.to_string()).or_insert((0, Instant::now()));
                    if e.1.elapsed() > LOCKOUT {
                        *e = (0, Instant::now());
                    }
                    e.0 += 1;
                    e.1 = Instant::now();
                    return Verdict::Ignore;
                }
                rest.trim().to_string()
            }
        };
        fails.remove(from);
        if text.is_empty() {
            Verdict::Ignore
        } else {
            Verdict::Accept(text)
        }
    }

    async fn reply(&self, to: &str, body: &str) -> Result<(), ToolError> {
        let req = self
            .egress
            .post(&self.messages_url())
            .map_err(ToolError::failed)?
            .basic_auth(self.sid.expose(), Some(self.token.expose()))
            .form(&[
                ("To", to),
                ("From", self.from.as_str()),
                ("Body", &clip(body, 1500)),
            ]);
        let (s, _) = send(req).await?;
        if !(200..300).contains(&s) {
            return Err(ToolError::Failed(format!("twilio send HTTP {s}")));
        }
        Ok(())
    }

    async fn delete(&self, msid: &str) {
        let url = format!(
            "{}/2010-04-01/Accounts/{}/Messages/{msid}.json",
            self.api,
            self.sid.expose()
        );
        if let Ok(r) = self.egress.request(reqwest::Method::DELETE, &url) {
            let _ = send(r.basic_auth(self.sid.expose(), Some(self.token.expose()))).await;
        }
    }

    pub async fn poll_once(&self, handler: &Arc<dyn InboundHandler>) -> Result<usize, ToolError> {
        let req = self
            .egress
            .get(&self.messages_url())
            .map_err(ToolError::failed)?
            .basic_auth(self.sid.expose(), Some(self.token.expose()))
            .query(&[("To", self.from.as_str()), ("PageSize", "50")]);
        let (s, b) = send(req).await?;
        if s != 200 {
            return Err(ToolError::Failed(format!("twilio list HTTP {s}")));
        }
        let v: Value = json_body(&b)?;
        let msgs = v["messages"].as_array().cloned().unwrap_or_default();
        let mut fresh = Vec::new();
        {
            let mut g = self.seen.lock().await;
            let (set, order, primed) = &mut *g;
            for m in &msgs {
                let Some(id) = m["sid"].as_str().filter(|id| valid_sid(id, &["SM", "MM"])) else {
                    continue;
                };
                if set.insert(id.to_string()) {
                    order.push_back(id.to_string());
                    if *primed {
                        fresh.push(m.clone());
                    }
                }
            }
            while order.len() > 5000 {
                if let Some(old) = order.pop_front() {
                    set.remove(&old);
                }
            }
            // First poll only records what already exists: no replay of history.
            *primed = true;
        }
        let mut handled = 0;
        for m in fresh.iter().rev() {
            if m["direction"].as_str() != Some("inbound") {
                continue;
            }
            let from = m["from"].as_str().unwrap_or("");
            let body = m["body"].as_str().unwrap_or("");
            let msid = m["sid"].as_str().unwrap_or("");
            match self.check(from, body).await {
                Verdict::Ignore => tracing::debug!("sms: ignored inbound message"),
                Verdict::Accept(text) => {
                    self.delete(msid).await;
                    let reply = handler
                        .handle(
                            Inbound {
                                origin: Origin::Sms,
                                sender: from.to_string(),
                                text: clip(&text, 1500),
                                attachments: vec![],
                            },
                            Arc::new(DenyAll),
                        )
                        .await;
                    self.reply(from, &reply).await?;
                    handled += 1;
                }
            }
        }
        Ok(handled)
    }
}

#[async_trait]
impl Gateway for Sms {
    fn name(&self) -> &'static str {
        "sms"
    }
    async fn run(self: Arc<Self>, handler: Arc<dyn InboundHandler>) -> anyhow::Result<()> {
        tracing::info!(
            "sms gateway polling every {}s ({} allowlisted number(s))",
            self.poll_secs,
            self.allowed.len()
        );
        let mut backoff = 1u64;
        loop {
            match self.poll_once(&handler).await {
                Ok(_) => {
                    backoff = 1;
                    tokio::time::sleep(Duration::from_secs(self.poll_secs)).await;
                }
                Err(e) => {
                    tracing::warn!("sms poll: {}", cg_core::sanitizer::redact(&e.to_string()));
                    tokio::time::sleep(Duration::from_secs(backoff.max(self.poll_secs))).await;
                    backoff = (backoff * 2).min(600);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::mock;
    use cg_core::tools::Confirmer;
    use std::sync::Mutex as StdMutex;

    const SID: &str = "AC0123456789abcdef0123456789abcdef";

    fn sms(api: String) -> Sms {
        let c = SmsConfig {
            enabled: true,
            from_number: "+14045550100".into(),
            allowed_numbers: vec!["+14045550123".into()],
            ..Default::default()
        };
        Sms::new(
            mock::loopback_egress(),
            api,
            Secret::minted(SID.into()),
            Secret::minted("twilio-token-xyz".into()),
            c,
            Some(Secret::minted("481516".into())),
        )
    }

    #[tokio::test]
    async fn empty_allowlist_fails_loud() {
        // I7: an enabled SMS gateway with no allowlist must refuse to build,
        // not answer every number.
        let mut t = toml::Table::new();
        t.insert(
            "sms".into(),
            toml::Value::Table(
                toml::from_str(
                    "enabled = true\nfrom_number = \"+14045550100\"\nallowed_numbers = []",
                )
                .expect("toml"),
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
        assert!(e.to_string().contains("allowed_numbers is empty"));
    }

    #[tokio::test]
    async fn pin_allowlist_and_lockout() {
        let s = sms(String::new());
        assert!(
            matches!(s.check("+14045550123", "481516 what's on my calendar").await, Verdict::Accept(t) if t == "what's on my calendar")
        );
        assert!(matches!(
            s.check("+19995550000", "481516 hi").await,
            Verdict::Ignore
        ));
        assert!(matches!(
            s.check("+14045550123", "hi").await,
            Verdict::Ignore
        ));
        assert!(matches!(
            s.check("+14045550123", "48151 hi").await,
            Verdict::Ignore
        ));
        for _ in 0..MAX_FAILS {
            let _ = s.check("+14045550123", "000000 x").await;
        }
        assert!(
            matches!(s.check("+14045550123", "481516 x").await, Verdict::Ignore),
            "locked out even with right PIN"
        );
    }

    struct Rec(StdMutex<Vec<String>>);
    #[async_trait]
    impl InboundHandler for Rec {
        async fn handle(&self, msg: Inbound, c: Arc<dyn Confirmer>) -> String {
            assert_eq!(msg.origin, Origin::Sms);
            assert!(!c.confirm("go online?").await, "SMS can never confirm");
            self.0.lock().expect("lock").push(msg.text);
            "ok".into()
        }
    }

    #[tokio::test]
    async fn first_poll_primes_without_replay() {
        let page = StdMutex::new(0usize);
        let m = mock::serve(Arc::new(move |line, _| {
            if line.starts_with("GET") {
                let mut p = page.lock().expect("lock");
                *p += 1;
                let mut msgs = vec![serde_json::json!({"sid":"SM00000000000000000000000000000001","direction":"inbound","from":"+14045550123","body":"481516 old"})];
                if *p > 1 {
                    msgs.insert(0, serde_json::json!({"sid":"SM00000000000000000000000000000002","direction":"inbound","from":"+14045550123","body":"481516 new"}));
                    msgs.insert(0, serde_json::json!({"sid":"SM00000000000000000000000000000003","direction":"inbound","from":"+15555550199","body":"481516 spoof"}));
                }
                (200, serde_json::json!({"messages": msgs}).to_string())
            } else {
                (201, "{}".into())
            }
        }))
        .await;
        let s = sms(m.base.clone());
        let rec = Arc::new(Rec(StdMutex::new(vec![])));
        let h: Arc<dyn InboundHandler> = rec.clone();
        assert_eq!(s.poll_once(&h).await.expect("p1"), 0);
        assert_eq!(s.poll_once(&h).await.expect("p2"), 1);
        assert_eq!(*rec.0.lock().expect("lock"), vec!["new".to_string()]);
        let seen = m.seen.lock().expect("lock");
        assert!(
            seen.iter().any(|(l, _)| l.starts_with("DELETE")
                && l.contains("SM00000000000000000000000000000002"))
        );
        let post = seen
            .iter()
            .find(|(l, _)| l.starts_with("POST"))
            .expect("reply");
        assert!(post.1.contains("To=%2B14045550123"));
        assert!(!post.1.contains("481516"), "PIN never echoed");
    }
}
