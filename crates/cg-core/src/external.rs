//! External fallback providers: Anthropic (Messages API) and xAI (stateless
//! chat completions). Both are text-in/text-out with **no tools**, pinned to
//! one HTTPS host each, and constructible only from `agent::Agent::new`
//! behind gates 1+2 (I3). Gate 3 (per-query consent) lives in the graph.
//!
//! Wire formats were checked against the vendor docs in October 2026:
//! * Anthropic: `POST /v1/messages`, headers `x-api-key` and
//!   `anthropic-version: 2023-06-01`, top-level `system`, reply
//!   `content[].type == "text"`; `GET /v1/models/{id}` exposes
//!   `max_input_tokens`, `max_tokens` and `capabilities`.
//! * xAI: `POST /v1/chat/completions` (OpenAI shape). We avoid the Responses
//!   API because it stores prompts server-side unless `store: false`.
//!   `GET /v1/language-models/{id}` exposes `input_modalities`.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::{Value, json};

use crate::egress::{Egress, is_loopback_url};
use crate::llm::LlmError;
use crate::secrets::Secret;
use crate::tune::{ModelProfile, ProfileSource};

pub const ANTHROPIC_VERSION: &str = "2023-06-01";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Provider {
    #[default]
    Anthropic,
    Xai,
}

impl Provider {
    pub fn name(self) -> &'static str {
        match self {
            Self::Anthropic => "anthropic",
            Self::Xai => "xai",
        }
    }
    pub fn display(self) -> &'static str {
        match self {
            Self::Anthropic => "Anthropic Claude",
            Self::Xai => "xAI Grok",
        }
    }
    pub fn default_model(self) -> &'static str {
        match self {
            Self::Anthropic => "claude-sonnet-5-5",
            Self::Xai => "grok-4.7",
        }
    }
    /// Model-id prefix of this provider's native API (`claude-*`, `grok-*`).
    pub fn model_prefix(self) -> &'static str {
        match self {
            Self::Anthropic => "claude-",
            Self::Xai => "grok-",
        }
    }
    /// Reject a model id that does not belong to this provider. Empty means
    /// "use the provider default" and is accepted. Without this, a provider
    /// switch that leaves the other vendor's id behind (xai + `claude-*`)
    /// only fails later, at call time, after the operator already consented.
    pub fn check_model(self, model: &str) -> Result<(), String> {
        if model.is_empty() || model.starts_with(self.model_prefix()) {
            return Ok(());
        }
        let owner = [Self::Anthropic, Self::Xai]
            .into_iter()
            .find(|p| model.starts_with(p.model_prefix()));
        Err(match owner {
            Some(o) => format!(
                "external.model {model:?} belongs to {o} but external.provider is {me}; \
                 use a {pre}* id or leave it empty for {def}",
                o = o.display(),
                me = self.name(),
                pre = self.model_prefix(),
                def = self.default_model()
            ),
            None => format!(
                "external.model {model:?} is not a {me} model id (expected {pre}*); \
                 leave it empty for {def}",
                me = self.name(),
                pre = self.model_prefix(),
                def = self.default_model()
            ),
        })
    }
    /// Expected key prefix; used to catch keys pasted into the wrong slot.
    pub fn key_prefix(self) -> &'static str {
        match self {
            Self::Anthropic => "sk-ant-",
            Self::Xai => "xai-",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "anthropic" => Some(Self::Anthropic),
            "xai" => Some(Self::Xai),
            _ => None,
        }
    }
}

/// Basic shape check for a pasted API key. Never logs the value.
pub fn validate_key(p: Provider, key: &str) -> Result<(), &'static str> {
    if key.len() < 20 || key.len() > 512 {
        return Err("key length is implausible");
    }
    if key.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err("key contains whitespace or control characters");
    }
    if !key.starts_with(p.key_prefix()) {
        return Err(match p {
            Provider::Anthropic => "Anthropic keys start with sk-ant-",
            Provider::Xai => "xAI keys start with xai-",
        });
    }
    Ok(())
}

/// The full cause chain of a send error. reqwest's `Display` stops at "error sending
/// request", which hides a refused certificate; say why, and how to opt out.
fn describe_send_error(e: &reqwest::Error) -> String {
    let mut s = e.to_string();
    let mut src = std::error::Error::source(e);
    while let Some(x) = src {
        s.push_str(": ");
        s.push_str(&x.to_string());
        src = x.source();
    }
    if let Some(h) = tls_hint(&s) {
        s.push_str(" (");
        s.push_str(h);
        s.push(')');
    }
    s
}

fn tls_hint(chain: &str) -> Option<&'static str> {
    chain.contains("UnknownIssuer").then_some(
        "certificate is not from a Mozilla-program root; a TLS-inspecting proxy or a \
         locally installed CA would cause this. Your key was not sent. Only if that \
         interception is expected, set external.tls_roots = \"system\" in cg.toml",
    )
}

pub struct ExternalReply {
    pub text: String,
    pub model: String,
    pub stop_reason: String,
}

pub struct ExternalClient {
    provider: Provider,
    base: String,
    egress: Egress,
    key: Secret,
}

impl ExternalClient {
    /// Construct ONLY inside the gated branch of `agent::Agent::new`.
    /// `test_base` exists for loopback mocks and is refused for anything else.
    pub(crate) fn external_provider(
        provider: Provider,
        xai_us_region: bool,
        timeout: Duration,
        tls_roots: crate::egress::TlsRoots,
        key: Secret,
        test_base: Option<&str>,
    ) -> anyhow::Result<Self> {
        if let Some(b) = test_base {
            let u = url::Url::parse(b)?;
            anyhow::ensure!(is_loopback_url(&u), "test base must be loopback");
            return Ok(Self {
                provider,
                base: b.trim_end_matches('/').into(),
                egress: Egress::new("llm-external", &[], true, timeout)?,
                key,
            });
        }
        let host = match provider {
            Provider::Anthropic => "api.anthropic.com",
            Provider::Xai if xai_us_region => "us.api.x.ai",
            Provider::Xai => "api.x.ai",
        };
        Ok(Self {
            provider,
            base: format!("https://{host}/v1"),
            egress: Egress::new_tls13("llm-external", &[host], timeout, tls_roots)?,
            key,
        })
    }

    pub fn provider(&self) -> Provider {
        self.provider
    }
    pub fn host(&self) -> String {
        url::Url::parse(&self.base)
            .ok()
            .and_then(|u| u.host_str().map(str::to_string))
            .unwrap_or_default()
    }

    fn authed(&self, rb: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match self.provider {
            Provider::Anthropic => rb
                .header("x-api-key", self.key.expose())
                .header("anthropic-version", ANTHROPIC_VERSION),
            Provider::Xai => rb.bearer_auth(self.key.expose()),
        }
    }

    async fn send(&self, rb: reqwest::RequestBuilder) -> Result<Value, LlmError> {
        let resp = self
            .authed(rb)
            .send()
            .await
            .map_err(|e| LlmError::Http(crate::sanitizer::redact(&describe_send_error(&e))))?;
        let status = resp.status();
        let v: Value = resp.json().await.map_err(|_| LlmError::Shape)?;
        if !status.is_success() {
            return Err(LlmError::Http(format!(
                "{status}: {}",
                crate::sanitizer::redact(error_message(&v))
            )));
        }
        Ok(v)
    }

    /// One stateless text completion. `images` are base64 PNGs and are only
    /// passed when the caller's rules allow it.
    pub async fn complete(
        &self,
        model: &str,
        system: &str,
        user: &str,
        images: &[String],
        max_tokens: u32,
        temperature: f32,
    ) -> Result<ExternalReply, LlmError> {
        let (path, body) = match self.provider {
            Provider::Anthropic => (
                "messages",
                anthropic_body(model, system, user, images, max_tokens, temperature),
            ),
            Provider::Xai => (
                "chat/completions",
                xai_body(model, system, user, images, max_tokens, temperature),
            ),
        };
        let v = self
            .send(
                self.egress
                    .post(&format!("{}/{path}", self.base))?
                    .json(&body),
            )
            .await?;
        match self.provider {
            Provider::Anthropic => parse_anthropic(&v),
            Provider::Xai => {
                let r = crate::llm::parse_chat(&v)?;
                Ok(ExternalReply {
                    text: r.content,
                    model: r.model,
                    stop_reason: v["choices"][0]["finish_reason"]
                        .as_str()
                        .unwrap_or("")
                        .into(),
                })
            }
        }
    }

    /// Model ids the key can use (for the UI picker).
    pub async fn list_models(&self) -> Result<Vec<String>, LlmError> {
        let path = match self.provider {
            Provider::Anthropic => "models?limit=100",
            Provider::Xai => "language-models",
        };
        let v = self
            .send(self.egress.get(&format!("{}/{path}", self.base))?)
            .await?;
        Ok(parse_model_list(self.provider, &v))
    }

    /// Metadata for autotune. A failure falls back to the builtin table.
    pub async fn profile(&self, model: &str) -> ModelProfile {
        let path = match self.provider {
            Provider::Anthropic => format!("models/{}", urlencoding(model)),
            Provider::Xai => format!("language-models/{}", urlencoding(model)),
        };
        let fetched = match self.egress.get(&format!("{}/{path}", self.base)) {
            Ok(rb) => self.send(rb).await.ok(),
            Err(_) => None,
        };
        match fetched {
            Some(v) => profile_from_metadata(self.provider, model, &v),
            None => crate::tune::builtin(self.provider.name(), model),
        }
    }
}

fn urlencoding(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_' | ':'))
        .collect()
}

fn error_message(v: &Value) -> &str {
    v["error"]["message"]
        .as_str()
        .or(v["error"].as_str())
        .unwrap_or("request failed")
}

pub fn anthropic_body(
    model: &str,
    system: &str,
    user: &str,
    images: &[String],
    max_tokens: u32,
    temperature: f32,
) -> Value {
    let mut content = Vec::new();
    for b in images {
        content.push(
            json!({"type":"image","source":{"type":"base64","media_type":"image/png","data":b}}),
        );
    }
    content.push(json!({"type":"text","text":user}));
    json!({
        "model": model,
        "max_tokens": max_tokens,
        "temperature": temperature.clamp(0.0, 1.0),
        "system": system,
        "messages": [{"role":"user","content":content}],
    })
}

pub fn xai_body(
    model: &str,
    system: &str,
    user: &str,
    images: &[String],
    max_tokens: u32,
    temperature: f32,
) -> Value {
    let content = if images.is_empty() {
        Value::String(user.into())
    } else {
        let mut parts = vec![json!({"type":"text","text":user})];
        for b in images {
            parts.push(json!({"type":"image_url","image_url":{"url":format!("data:image/png;base64,{b}")}}));
        }
        Value::Array(parts)
    };
    json!({
        "model": model,
        "max_tokens": max_tokens,
        "temperature": temperature.clamp(0.0, 2.0),
        "stream": false,
        "messages": [
            {"role":"system","content":system},
            {"role":"user","content":content}
        ],
    })
}

pub fn parse_anthropic(v: &Value) -> Result<ExternalReply, LlmError> {
    if v["type"] == "error" {
        return Err(LlmError::Http(crate::sanitizer::redact(error_message(v))));
    }
    let blocks = v["content"].as_array().ok_or(LlmError::Shape)?;
    let text: Vec<&str> = blocks
        .iter()
        .filter(|b| b["type"] == "text")
        .filter_map(|b| b["text"].as_str())
        .collect();
    Ok(ExternalReply {
        text: crate::llm::strip_thinking(&text.join("\n")),
        model: v["model"].as_str().unwrap_or("").into(),
        stop_reason: v["stop_reason"].as_str().unwrap_or("").into(),
    })
}

pub fn parse_model_list(p: Provider, v: &Value) -> Vec<String> {
    let arr = match p {
        Provider::Anthropic => v["data"].as_array(),
        Provider::Xai => v["models"].as_array().or(v["data"].as_array()),
    };
    let mut ids: Vec<String> = arr
        .into_iter()
        .flatten()
        .filter_map(|m| m["id"].as_str().map(str::to_string))
        .collect();
    ids.sort();
    ids.dedup();
    ids
}

fn as_u32(v: &Value) -> Option<u32> {
    v.as_u64().and_then(|n| u32::try_from(n).ok())
}

/// Parse vendor metadata defensively; unknown fields fall back to the table.
pub fn profile_from_metadata(p: Provider, model: &str, v: &Value) -> ModelProfile {
    let mut prof = crate::tune::builtin(p.name(), model);
    prof.source = ProfileSource::Provider;
    match p {
        Provider::Anthropic => {
            if let Some(n) = as_u32(&v["max_input_tokens"]) {
                prof.context_tokens = n;
            }
            if let Some(n) = as_u32(&v["max_tokens"]) {
                prof.max_output_tokens = n;
            }
            let img = &v["capabilities"]["image_input"];
            if let Some(b) = img.as_bool().or(img["supported"].as_bool()) {
                prof.vision = b;
            }
            prof.temp_max = 1.0;
        }
        Provider::Xai => {
            if let Some(m) = v["input_modalities"].as_array() {
                prof.vision = m.iter().any(|x| x == "image");
            }
            for k in ["context_length", "max_context_length", "context_window"] {
                if let Some(n) = as_u32(&v[k]) {
                    prof.context_tokens = n;
                }
            }
            prof.temp_max = 2.0;
        }
    }
    prof.tools = false; // external models never get tools, whatever they support
    prof
}

// ------------------------------------------------------------- call budget

/// Process-wide budget for external calls. Global (not per-Agent) so that a
/// model switch, which rebuilds the Agent, cannot reset it. It does reset on
/// process restart; that is documented.
static CALLS: Mutex<VecDeque<Instant>> = Mutex::new(VecDeque::new());

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BudgetUse {
    pub last_hour: u32,
    pub last_day: u32,
}

fn prune(q: &mut VecDeque<Instant>, now: Instant) {
    while q
        .front()
        .is_some_and(|t| now.duration_since(*t) > Duration::from_secs(86_400))
    {
        q.pop_front();
    }
}

fn count(q: &VecDeque<Instant>, now: Instant) -> BudgetUse {
    let hour = q
        .iter()
        .filter(|t| now.duration_since(**t) <= Duration::from_secs(3600))
        .count();
    BudgetUse {
        last_hour: u32::try_from(hour).unwrap_or(u32::MAX),
        last_day: u32::try_from(q.len()).unwrap_or(u32::MAX),
    }
}

pub fn budget_use() -> BudgetUse {
    let mut q = CALLS.lock().unwrap_or_else(|p| p.into_inner());
    let now = Instant::now();
    prune(&mut q, now);
    count(&q, now)
}

/// Reserve one call if under both limits. Returns the use *before* reserving.
pub fn budget_take(per_hour: u32, per_day: u32) -> Result<BudgetUse, BudgetUse> {
    take_in(
        &mut CALLS.lock().unwrap_or_else(|p| p.into_inner()),
        Instant::now(),
        per_hour,
        per_day,
    )
}

fn take_in(
    q: &mut VecDeque<Instant>,
    now: Instant,
    per_hour: u32,
    per_day: u32,
) -> Result<BudgetUse, BudgetUse> {
    prune(q, now);
    let u = count(q, now);
    if u.last_hour >= per_hour || u.last_day >= per_day {
        return Err(u);
    }
    q.push_back(now);
    Ok(u)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn model_ids_must_match_the_provider() {
        use Provider::{Anthropic, Xai};
        for (p, m) in [
            (Anthropic, ""),
            (Anthropic, "claude-sonnet-5-5"),
            (Xai, ""),
            (Xai, "grok-4.7"),
        ] {
            assert!(p.check_model(m).is_ok(), "{p:?} {m}");
        }
        let e = Xai
            .check_model("claude-sonnet-5-5")
            .expect_err("cross-vendor");
        assert!(
            e.contains("belongs to Anthropic Claude") && e.contains("grok-*"),
            "{e}"
        );
        let e = Anthropic.check_model("grok-4.7").expect_err("cross-vendor");
        assert!(
            e.contains("belongs to xAI Grok") && e.contains("claude-*"),
            "{e}"
        );
        for m in [
            "gpt-5",
            "Claude-sonnet",
            "claude",
            "llama3:8b",
            "xai/grok-4",
        ] {
            assert!(
                Anthropic.check_model(m).is_err() && Xai.check_model(m).is_err(),
                "{m}"
            );
        }
    }

    #[test]
    fn anthropic_body_has_top_level_system_and_clamped_temperature() {
        let b = anthropic_body("claude-x", "sys", "hello", &["AAAA".into()], 512, 1.7);
        assert_eq!(b["system"], "sys");
        assert_eq!(b["max_tokens"], 512);
        assert_eq!(b["temperature"], 1.0);
        assert_eq!(b["messages"][0]["role"], "user");
        let c = b["messages"][0]["content"].as_array().expect("arr");
        assert_eq!(c[0]["type"], "image");
        assert_eq!(c[0]["source"]["media_type"], "image/png");
        assert_eq!(c[1]["text"], "hello");
        assert!(b.get("tools").is_none(), "external calls never carry tools");
    }

    #[test]
    fn xai_body_is_stateless_chat_completions_without_tools() {
        let b = xai_body("grok", "sys", "hi", &[], 100, 0.5);
        assert_eq!(b["messages"][0]["role"], "system");
        assert_eq!(b["messages"][1]["content"], "hi");
        assert!(b.get("tools").is_none() && b.get("store").is_none());
    }

    #[test]
    fn parses_anthropic_text_blocks_and_errors() {
        let v = json!({"model":"claude-x","stop_reason":"end_turn","content":[
            {"type":"thinking","thinking":"secret plan"},
            {"type":"text","text":"Hello"},{"type":"text","text":"world"}]});
        let r = parse_anthropic(&v).expect("ok");
        assert_eq!(r.text, "Hello\nworld");
        assert_eq!(r.stop_reason, "end_turn");
        let e = json!({"type":"error","error":{"type":"overloaded_error","message":"busy"}});
        assert!(parse_anthropic(&e).is_err());
        assert!(parse_anthropic(&json!({})).is_err());
    }

    #[test]
    fn metadata_parsing_is_defensive_and_never_enables_tools() {
        let v = json!({"id":"claude-x","max_input_tokens":200000,"max_tokens":64000,
            "capabilities":{"image_input":{"supported":true}}});
        let p = profile_from_metadata(Provider::Anthropic, "claude-x", &v);
        assert_eq!(
            (p.context_tokens, p.max_output_tokens, p.vision, p.tools),
            (200_000, 64_000, true, false)
        );
        let x = profile_from_metadata(
            Provider::Xai,
            "grok-x",
            &json!({"input_modalities":["text","image"]}),
        );
        assert!(x.vision && !x.tools);
        // Garbage keeps the builtin defaults.
        let g = profile_from_metadata(
            Provider::Anthropic,
            "claude-x",
            &json!({"max_input_tokens":"lots"}),
        );
        assert!(g.context_tokens > 0);
        assert_eq!(
            parse_model_list(Provider::Xai, &json!({"models":[{"id":"b"},{"id":"a"}]})),
            vec!["a", "b"]
        );
    }

    #[test]
    fn key_validation_catches_wrong_slot_and_whitespace() {
        assert!(validate_key(Provider::Anthropic, "sk-ant-api03-0123456789abcdef").is_ok());
        assert!(validate_key(Provider::Anthropic, "xai-0123456789abcdef01234").is_err());
        assert!(validate_key(Provider::Xai, "xai-0123456789abcdef 1234").is_err());
        assert!(validate_key(Provider::Xai, "xai-short").is_err());
    }

    #[test]
    fn budget_enforces_hour_and_day_limits() {
        let mut q = VecDeque::new();
        let t0 = Instant::now();
        assert!(take_in(&mut q, t0, 2, 3).is_ok());
        assert!(take_in(&mut q, t0, 2, 3).is_ok());
        assert_eq!(
            take_in(&mut q, t0, 2, 3),
            Err(BudgetUse {
                last_hour: 2,
                last_day: 2
            })
        );
        let later = t0 + Duration::from_secs(3601);
        assert!(take_in(&mut q, later, 2, 3).is_ok(), "hour window rolled");
        assert!(take_in(&mut q, later, 2, 3).is_err(), "day cap of 3 hit");
    }

    #[test]
    fn unknown_issuer_names_the_cause_and_the_opt_out() {
        let h = tls_hint("error sending request: client error (Connect): invalid peer certificate: UnknownIssuer")
            .expect("hint");
        assert!(h.contains("external.tls_roots") && h.contains("not sent"));
        assert!(tls_hint("error sending request: connection refused").is_none());
    }

    #[test]
    fn test_base_must_be_loopback() {
        let k = Secret::minted("sk-ant-test-000000000000".into());
        assert!(
            ExternalClient::external_provider(
                Provider::Anthropic,
                false,
                Duration::from_secs(1),
                crate::egress::TlsRoots::Mozilla,
                k.clone(),
                Some("https://evil.example/v1")
            )
            .is_err()
        );
        let c = ExternalClient::external_provider(
            Provider::Xai,
            true,
            Duration::from_secs(1),
            crate::egress::TlsRoots::System,
            k,
            None,
        )
        .expect("ok");
        assert_eq!(c.host(), "us.api.x.ai");
    }
}
