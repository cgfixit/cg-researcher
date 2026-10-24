//! Autotune: probe what a model can do, then derive safe generation settings.
//! Runs when an Agent is built, which is also what every model switch does.
//!
//! Probes (all optional, all fall back to a conservative builtin table):
//! * Ollama: `POST {root}/api/show` → `model_info.*.context_length`, `capabilities`
//! * LM Studio: `GET {root}/api/v0/models/{id}` → `max_context_length`, `type`
//! * Anthropic / xAI: model metadata endpoints (see `external.rs`)
//!
//! `derive` is pure so the policy is unit-testable without any server.

use serde::Serialize;
use serde_json::{Value, json};

use crate::egress::Egress;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ProfileSource {
    Builtin,
    Probe,
    Provider,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ModelProfile {
    pub provider: String,
    pub model: String,
    pub context_tokens: u32,
    pub max_output_tokens: u32,
    pub tools: bool,
    pub vision: bool,
    pub temp_max: f32,
    pub source: ProfileSource,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Tuning {
    pub max_tokens: u32,
    pub temperature: f32,
    pub top_k: usize,
    /// Characters of retrieved/attached context that fit next to the reply.
    pub context_chars: usize,
    pub tools: bool,
    pub vision: bool,
}

/// Conservative defaults when nothing could be probed.
pub fn builtin(provider: &str, model: &str) -> ModelProfile {
    let m = model.to_ascii_lowercase();
    let (ctx, out, vision, tools) = match provider {
        "anthropic" => (200_000, 8_192, true, false),
        "xai" => (
            if m.starts_with("grok-4") {
                256_000
            } else {
                131_072
            },
            8_192,
            m.contains("vision") || m.starts_with("grok-4"),
            false,
        ),
        _ => (
            8_192,
            2_048,
            m.contains("vl") || m.contains("vision") || m.contains("llava"),
            true,
        ),
    };
    ModelProfile {
        provider: provider.into(),
        model: model.into(),
        context_tokens: ctx,
        max_output_tokens: out,
        tools,
        vision,
        temp_max: if provider == "anthropic" { 1.0 } else { 2.0 },
        source: ProfileSource::Builtin,
    }
}

/// Tokens reserved for the system prompt, tool schemas and the question.
const RESERVE_TOKENS: u32 = 1_500;
/// Deliberately pessimistic chars-per-token so budgets do not overflow.
const CHARS_PER_TOKEN: usize = 3;

pub fn derive(
    p: &ModelProfile,
    want_max_tokens: u32,
    want_temperature: f32,
    want_top_k: usize,
    chunk_chars: usize,
) -> Tuning {
    let ctx = p.context_tokens.max(1_024);
    let max_tokens = want_max_tokens
        .min(p.max_output_tokens.max(256))
        .min(ctx / 4)
        .max(256);
    let input_tokens = ctx
        .saturating_sub(max_tokens)
        .saturating_sub(RESERVE_TOKENS);
    let context_chars = (input_tokens as usize).saturating_mul(CHARS_PER_TOKEN);
    let per_hit = chunk_chars.max(1) + 200;
    let top_k = want_top_k.min(context_chars / per_hit).max(1);
    Tuning {
        max_tokens,
        temperature: if want_temperature.is_finite() {
            want_temperature.clamp(0.0, p.temp_max)
        } else {
            0.2
        },
        top_k,
        context_chars,
        tools: p.tools,
        vision: p.vision,
    }
}

fn root_of(base_url: &str) -> String {
    let b = base_url.trim_end_matches('/');
    b.strip_suffix("/v1").unwrap_or(b).to_string()
}

pub fn parse_ollama_show(model: &str, v: &Value) -> Option<ModelProfile> {
    let info = v["model_info"].as_object()?;
    let ctx = info
        .iter()
        .find(|(k, _)| k.ends_with(".context_length"))
        .and_then(|(_, n)| n.as_u64())
        .and_then(|n| u32::try_from(n).ok())?;
    let caps: Vec<&str> = v["capabilities"]
        .as_array()
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let mut p = builtin("ollama", model);
    p.context_tokens = ctx;
    p.max_output_tokens = ctx / 2;
    if !caps.is_empty() {
        p.tools = caps.contains(&"tools");
        p.vision = caps.contains(&"vision");
    }
    p.source = ProfileSource::Probe;
    Some(p)
}

pub fn parse_lmstudio(model: &str, v: &Value) -> Option<ModelProfile> {
    let ctx = v["loaded_context_length"]
        .as_u64()
        .or(v["max_context_length"].as_u64())
        .and_then(|n| u32::try_from(n).ok())?;
    let mut p = builtin("lmstudio", model);
    p.context_tokens = ctx;
    p.max_output_tokens = ctx / 2;
    if let Some(t) = v["type"].as_str() {
        p.vision = t == "vlm";
    }
    p.source = ProfileSource::Probe;
    Some(p)
}

/// Probe a local server. Never errors: an unknown server gets `builtin`.
pub async fn probe_local(
    egress: &Egress,
    provider: &str,
    base_url: &str,
    model: &str,
) -> ModelProfile {
    let root = root_of(base_url);
    if (provider == "ollama" || base_url.contains(":11434"))
        && let Ok(rb) = egress.post(&format!("{root}/api/show"))
        && let Ok(r) = rb.json(&json!({"model": model})).send().await
        && let Ok(v) = r.json::<Value>().await
        && let Some(p) = parse_ollama_show(model, &v)
    {
        return p;
    }
    if (provider == "lmstudio" || base_url.contains(":1234"))
        && let Ok(rb) = egress.get(&format!("{root}/api/v0/models/{model}"))
        && let Ok(r) = rb.send().await
        && let Ok(v) = r.json::<Value>().await
        && let Some(p) = parse_lmstudio(model, &v)
    {
        return p;
    }
    builtin(provider, model)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_clamps_to_model_limits() {
        let mut p = builtin("ollama", "qwen3:8b");
        p.context_tokens = 4_096;
        p.max_output_tokens = 4_096;
        let t = derive(&p, 8_000, 0.2, 8, 900);
        assert_eq!(t.max_tokens, 1_024, "≤ ctx/4");
        assert!(t.top_k >= 1 && t.top_k < 8, "small ctx cuts top_k: {t:?}");
        assert!(t.context_chars < 4_096 * 3);
        let a = builtin("anthropic", "claude-x");
        let t = derive(&a, 2_048, 1.6, 5, 900);
        assert_eq!(t.temperature, 1.0, "Anthropic temperature is 0..1");
        assert_eq!(t.top_k, 5);
        assert!(!t.tools, "external never gets tools");
        let t = derive(&p, 2_048, f32::NAN, 5, 900);
        assert_eq!(t.temperature, 0.2);
    }

    #[test]
    fn derive_survives_degenerate_profiles() {
        let mut p = builtin("x", "m");
        p.context_tokens = 0;
        p.max_output_tokens = 0;
        let t = derive(&p, 0, -3.0, 0, 0);
        assert!(t.max_tokens >= 256 && t.top_k == 1 && t.temperature == 0.0);
    }

    #[test]
    fn parses_ollama_and_lmstudio_probes() {
        let v = json!({"model_info":{"qwen3.context_length":40960,"general.architecture":"qwen3"},
            "capabilities":["completion","tools"]});
        let p = parse_ollama_show("qwen3:8b", &v).expect("p");
        assert_eq!((p.context_tokens, p.tools, p.vision), (40_960, true, false));
        assert_eq!(p.source, ProfileSource::Probe);
        let v = json!({"id":"qwen2.5-vl","type":"vlm","max_context_length":32768});
        let p = parse_lmstudio("qwen2.5-vl", &v).expect("p");
        assert!(p.vision && p.context_tokens == 32_768);
        assert!(parse_ollama_show("m", &json!({})).is_none());
    }

    #[test]
    fn root_strips_v1() {
        assert_eq!(
            root_of("http://127.0.0.1:11434/v1/"),
            "http://127.0.0.1:11434"
        );
    }
}
