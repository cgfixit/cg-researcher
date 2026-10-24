//! Typed configuration (TOML). Unknown keys are refused so a typo cannot
//! silently leave a control at its default. TOML booleans are already strict:
//! a quoted `"true"` is a type error, which matches CyClaw's "literal bool"
//! rule without extra code.

use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Local model only. No external LLM client is ever constructed.
    #[default]
    Offline,
    /// External fallback may be constructed if also enabled; each call still
    /// needs per-query confirmation (triple gate).
    Hybrid,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AppConfig {
    pub mode: Mode,
    /// Data directory; empty means `~/.cg-researcher`.
    pub home: String,
}
impl Default for AppConfig {
    fn default() -> Self {
        Self {
            mode: Mode::Offline,
            home: String::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LlmConfig {
    /// Label only: ollama | lmstudio | llamacpp | mlx | vllm | openai-compatible.
    pub provider: String,
    /// OpenAI-compatible base URL (`.../v1`).
    pub base_url: String,
    pub model: String,
    /// Model used when a turn carries an image. Empty disables image input.
    pub vision_model: String,
    pub embed_model: String,
    /// Optional secret reference for servers that want a bearer key.
    pub api_key_ref: String,
    pub timeout_secs: u64,
    pub max_tokens: u32,
    pub temperature: f32,
    /// The local backend must be loopback unless this is literally true.
    pub allow_non_loopback: bool,
}
impl Default for LlmConfig {
    fn default() -> Self {
        Self {
            provider: "ollama".into(),
            base_url: "http://127.0.0.1:11434/v1".into(),
            model: "qwen3.8:27b-mlx-cg".into(),
            vision_model: "gemma4-26b-a4b:ud-q4_k_xl-cg".into(),
            embed_model: "all-minilm".into(),
            api_key_ref: String::new(),
            timeout_secs: 720,
            max_tokens: 2048,
            temperature: 0.2,
            allow_non_loopback: false,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct RagConfig {
    pub corpus_dir: String,
    /// RRF scale (k=60), not cosine. Scaled by the number of ranked lists.
    pub min_score: f64,
    pub min_semantic_score: f64,
    pub top_k: usize,
    pub chunk_chars: usize,
    pub chunk_overlap: usize,
}
impl Default for RagConfig {
    fn default() -> Self {
        Self {
            corpus_dir: String::new(),
            min_score: 0.028,
            min_semantic_score: 0.30,
            top_k: 5,
            chunk_chars: 900,
            chunk_overlap: 120,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AgentConfig {
    pub max_steps: usize,
    pub max_tool_iterations: usize,
    /// Optional read-only persona file prepended to the system prompt.
    pub soul_file: String,
    pub max_input_chars: usize,
}
impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            max_steps: 48,
            max_tool_iterations: 8,
            soul_file: String::new(),
            max_input_chars: 4000,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ToolPolicyConfig {
    /// Write tools (send mail, create event, send message) run without a
    /// confirmation only if this is true AND the turn is untainted AND the
    /// origin is local. Ships false.
    pub auto_approve_writes: bool,
    /// Telegram/SMS turns see read tools only. Ships true.
    pub remote_origins_read_only: bool,
    pub max_tool_output_chars: usize,
}
impl Default for ToolPolicyConfig {
    fn default() -> Self {
        Self {
            auto_approve_writes: false,
            remote_origins_read_only: true,
            max_tool_output_chars: 12_000,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ExternalConfig {
    /// Gate 2 of 3 (gate 1 is `app.mode = "hybrid"`, gate 3 is per-query).
    pub enabled: bool,
    /// `anthropic` | `xai`.
    pub provider: crate::external::Provider,
    /// Empty means the provider's default model.
    pub model: String,
    pub anthropic_key_ref: String,
    pub xai_key_ref: String,
    /// `global` (api.x.ai) or `us` (us.api.x.ai).
    pub xai_region: String,
    pub timeout_secs: u64,
    pub rules: ExternalRules,
}
impl Default for ExternalConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            provider: crate::external::Provider::Anthropic,
            model: String::new(),
            anthropic_key_ref: "keychain:cg-researcher/anthropic_api_key".into(),
            xai_key_ref: "keychain:cg-researcher/xai_api_key".into(),
            xai_region: "global".into(),
            timeout_secs: 120,
            rules: ExternalRules::default(),
        }
    }
}
impl ExternalConfig {
    pub fn effective_model(&self) -> String {
        if self.model.is_empty() {
            self.provider.default_model().into()
        } else {
            self.model.clone()
        }
    }
    pub fn key_ref(&self) -> &str {
        match self.provider {
            crate::external::Provider::Anthropic => &self.anthropic_key_ref,
            crate::external::Provider::Xai => &self.xai_key_ref,
        }
    }
}

/// Rules enforced in the graph for every external call. All ship closed.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ExternalRules {
    /// Send sanitized top retrieval hits (wrapped as untrusted) with the query.
    pub send_local_context: bool,
    /// Let Telegram turns consent to egress. SMS can never consent.
    pub allow_telegram: bool,
    /// Forward PNG attachments (only if the model reports vision).
    pub allow_images: bool,
    /// Forward extracted Markdown/DOCX attachment text.
    pub allow_attachment_text: bool,
    pub max_calls_per_hour: u32,
    pub max_calls_per_day: u32,
    pub max_output_tokens: u32,
    pub temperature: f32,
    /// Hard cap on characters sent per call (query + context).
    pub max_outbound_chars: usize,
}
impl Default for ExternalRules {
    fn default() -> Self {
        Self {
            send_local_context: false,
            allow_telegram: false,
            allow_images: false,
            allow_attachment_text: false,
            max_calls_per_hour: 20,
            max_calls_per_day: 100,
            max_output_tokens: 2_048,
            temperature: 0.3,
            max_outbound_chars: 24_000,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub max_body_bytes: usize,
    pub rate_limit_per_min: u32,
}
impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "127.0.0.1".into(),
            port: 8797,
            max_body_bytes: 16 * 1024 * 1024,
            rate_limit_per_min: 60,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct AttachmentConfig {
    pub max_bytes: usize,
    pub max_text_chars: usize,
    pub max_image_side: u32,
    pub max_per_turn: usize,
}
impl Default for AttachmentConfig {
    fn default() -> Self {
        Self {
            max_bytes: 10 * 1024 * 1024,
            max_text_chars: 60_000,
            max_image_side: 8192,
            max_per_turn: 4,
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    pub app: AppConfig,
    pub llm: LlmConfig,
    pub rag: RagConfig,
    pub agent: AgentConfig,
    pub tools: ToolPolicyConfig,
    pub external: ExternalConfig,
    pub server: ServerConfig,
    pub attachments: AttachmentConfig,
    /// Connector sections are opaque to the core; each connector parses its
    /// own table. This keeps core free of connector types (I6).
    pub connectors: toml::Table,
}

impl Config {
    pub fn from_toml(text: &str) -> anyhow::Result<Self> {
        let cfg: Self = toml::from_str(text)?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("cannot read config {}: {e}", path.display()))?;
        Self::from_toml(&text)
    }

    /// Base config with the UI settings overlay deep-merged on top. The
    /// overlay may only touch whitelisted keys; the merged result goes
    /// through the same strict deserializer and `validate`.
    pub fn load_with_overlay(path: &Path, overlay: Option<&Path>) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("cannot read config {}: {e}", path.display()))?;
        let mut base: toml::Table = toml::from_str(&text)?;
        if let Some(o) = overlay.filter(|o| o.is_file()) {
            let ov: toml::Table = toml::from_str(&std::fs::read_to_string(o)?)?;
            crate::settings::check_overlay(&ov)?;
            crate::settings::merge(&mut base, &ov);
        }
        let cfg: Self = toml::Value::Table(base).try_into()?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        let url = url::Url::parse(&self.llm.base_url)?;
        if !self.llm.allow_non_loopback && !crate::egress::is_loopback_url(&url) {
            anyhow::bail!(
                "llm.base_url must be loopback (set llm.allow_non_loopback = true to override)"
            );
        }
        let host: std::net::IpAddr = self
            .server
            .host
            .parse()
            .map_err(|_| anyhow::anyhow!("server.host must be an IP literal"))?;
        if !host.is_loopback() && std::env::var("CG_ALLOW_NON_LOOPBACK_BIND").as_deref() != Ok("1")
        {
            anyhow::bail!("server.host must be loopback (CG_ALLOW_NON_LOOPBACK_BIND=1 overrides)");
        }
        anyhow::ensure!(
            matches!(self.external.xai_region.as_str(), "global" | "us"),
            "external.xai_region must be \"global\" or \"us\""
        );
        let r = &self.external.rules;
        anyhow::ensure!(
            r.max_calls_per_hour <= 1_000 && r.max_calls_per_day <= 10_000,
            "external.rules call budgets are implausibly high"
        );
        anyhow::ensure!(
            (1..=64_000).contains(&r.max_output_tokens),
            "external.rules.max_output_tokens must be 1..=64000"
        );
        anyhow::ensure!(
            r.temperature.is_finite() && (0.0..=2.0).contains(&r.temperature),
            "external.rules.temperature must be 0..=2"
        );
        anyhow::ensure!(
            (256..=400_000).contains(&r.max_outbound_chars),
            "external.rules.max_outbound_chars must be 256..=400000"
        );
        anyhow::ensure!(
            self.llm.temperature.is_finite() && (0.0..=2.0).contains(&self.llm.temperature),
            "llm.temperature must be 0..=2"
        );
        for (k, v) in [
            ("external.model", &self.external.model),
            ("llm.model", &self.llm.model),
            ("llm.vision_model", &self.llm.vision_model),
        ] {
            anyhow::ensure!(
                v.len() <= 128
                    && v.chars()
                        .all(|c| c.is_ascii_alphanumeric() || "-._:/@".contains(c)),
                "{k} has unexpected characters"
            );
        }
        // After the charset check, so the id is safe to echo in the error.
        self.external
            .provider
            .check_model(&self.external.model)
            .map_err(|e| anyhow::anyhow!(e))?;
        if self.rag.chunk_overlap >= self.rag.chunk_chars {
            anyhow::bail!("rag.chunk_overlap must be smaller than rag.chunk_chars");
        }
        Ok(())
    }

    pub fn home(&self) -> PathBuf {
        if !self.app.home.is_empty() {
            return PathBuf::from(&self.app.home);
        }
        crate::paths::default_home()
    }

    pub fn corpus_dir(&self) -> PathBuf {
        if self.rag.corpus_dir.is_empty() {
            self.home().join("corpus")
        } else {
            PathBuf::from(&self.rag.corpus_dir)
        }
    }

    /// A connector's own table, or an empty one.
    pub fn connector(&self, name: &str) -> toml::Table {
        self.connectors
            .get(name)
            .and_then(|v| v.as_table())
            .cloned()
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_local_models() {
        let c = Config::from_toml("").expect("empty config");
        assert_eq!(c.llm.model, "qwen3.8:27b-mlx-cg");
        assert_eq!(c.llm.vision_model, "gemma4-26b-a4b:ud-q4_k_xl-cg");
        assert_eq!(c.llm.base_url, "http://127.0.0.1:11434/v1");
        assert!(!c.llm.allow_non_loopback);
        let shipped = Config::from_toml(include_str!("../../../config/cg.toml")).expect("shipped");
        assert_eq!(shipped.llm.model, c.llm.model);
        assert_eq!(shipped.llm.vision_model, c.llm.vision_model);
    }

    #[test]
    fn defaults_are_offline_and_loopback() {
        let c = Config::from_toml("").expect("empty config");
        assert_eq!(c.app.mode, Mode::Offline);
        assert!(!c.external.enabled);
        assert!(!c.tools.auto_approve_writes);
        assert!(c.tools.remote_origins_read_only);
        let r = &c.external.rules;
        assert!(!r.send_local_context && !r.allow_telegram && !r.allow_images);
        assert!(!r.allow_attachment_text);
    }

    #[test]
    fn external_model_must_match_provider() {
        assert!(Config::from_toml("[external]\nprovider = \"xai\"\nmodel = \"grok-4.7\"").is_ok());
        assert!(
            Config::from_toml("[external]\nprovider = \"xai\"").is_ok(),
            "empty = default"
        );
        let e = Config::from_toml("[external]\nprovider = \"xai\"\nmodel = \"claude-sonnet-5-5\"")
            .expect_err("mismatch");
        assert!(e.to_string().contains("belongs to Anthropic Claude"), "{e}");
        assert!(
            Config::from_toml("[external]\nmodel = \"grok-4.7\"").is_err(),
            "default provider is anthropic"
        );
    }

    #[test]
    fn quoted_bool_and_unknown_keys_are_refused() {
        assert!(Config::from_toml("[external]\nenabled = \"true\"").is_err());
        assert!(Config::from_toml("[external]\nenabeld = true").is_err());
    }

    #[test]
    fn non_loopback_llm_is_refused_by_default() {
        assert!(Config::from_toml("[llm]\nbase_url = \"http://10.0.0.5:11434/v1\"").is_err());
        assert!(
            Config::from_toml(
                "[llm]\nbase_url = \"http://10.0.0.5:11434/v1\"\nallow_non_loopback = true"
            )
            .is_ok()
        );
    }

    #[test]
    fn shipped_config_parses_and_keeps_safe_defaults() {
        let text = include_str!("../../../config/cg.toml");
        let c = Config::from_toml(text).expect("shipped config");
        assert_eq!(c.app.mode, Mode::Offline);
        assert!(!c.external.enabled);
        assert!(!c.tools.auto_approve_writes);
        for (name, table) in &c.connectors {
            assert_eq!(
                table.get("enabled").and_then(|v| v.as_bool()),
                Some(false),
                "connector {name} must ship disabled"
            );
        }
    }
}
