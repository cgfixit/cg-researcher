//! Web search. Port of CG-agent-harness `src/server/web_google.rs`:
//! SerpAPI when a key is configured; public google.com only when no key is
//! configured AND `allow_public_google = true`. A rejected key or exhausted
//! quota never silently falls back to public Google (that would change the
//! privacy/ToS posture behind the operator's back).

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use cg_core::egress::Egress;
use cg_core::secrets::{Secret, SecretError};
use cg_core::tools::{Effect, Tool, ToolError, ToolSpec};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::sync::Mutex;

use crate::common::{arg_str, arg_usize, clip, egress, json_body, send};
use crate::{Ctx, Parts};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct WebSearchConfig {
    pub enabled: bool,
    pub serpapi_key_ref: String,
    pub allow_public_google: bool,
    pub max_results: usize,
}
impl Default for WebSearchConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            serpapi_key_ref: "env:SERPAPI_API_KEY".into(),
            allow_public_google: false,
            max_results: 5,
        }
    }
}

const SERP_ENDPOINT: &str = "https://serpapi.com/search.json";
const GOOGLE_ENDPOINT: &str = "https://www.google.com/search";
/// Minimum spacing between public Google requests.
const PUBLIC_PACE: Duration = Duration::from_secs(3);
/// Pause after a challenge page or HTTP 429.
const COOLDOWN: Duration = Duration::from_secs(30 * 60);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    pub title: String,
    pub url: String,
    pub snippet: String,
}

enum Backend {
    Serp {
        egress: Egress,
        endpoint: String,
        key: Secret,
    },
    Public {
        egress: Egress,
        endpoint: String,
    },
}

pub struct WebSearch {
    backend: Backend,
    max_results: usize,
    last: Mutex<Option<Instant>>,
    paused_until: Mutex<Option<Instant>>,
}

pub async fn build(ctx: &Ctx<'_>) -> anyhow::Result<Parts> {
    let c: WebSearchConfig = crate::common::section(ctx.connectors, "web_search")?;
    if !c.enabled {
        return Ok(Parts::default());
    }
    let key = if c.serpapi_key_ref.trim().is_empty() {
        None
    } else {
        match ctx.secrets.resolve(&c.serpapi_key_ref).await {
            Ok(k) => Some(k),
            Err(SecretError::Missing(_)) => None,
            Err(e) => anyhow::bail!("web_search: SerpAPI key reference failed: {e}"),
        }
    };
    let backend = match (key, c.allow_public_google) {
        (Some(key), _) => Backend::Serp {
            egress: egress("web_search", &["serpapi.com"])?,
            endpoint: SERP_ENDPOINT.into(),
            key,
        },
        (None, true) => {
            tracing::warn!(
                "web_search: no SerpAPI key; using public google.com (fragile, rate-limited, ToS-grey)"
            );
            Backend::Public {
                egress: egress("web_search", &["www.google.com"])?,
                endpoint: GOOGLE_ENDPOINT.into(),
            }
        }
        (None, false) => anyhow::bail!(
            "web_search is enabled but no SerpAPI key resolved from `{}` and allow_public_google = false",
            c.serpapi_key_ref
        ),
    };
    let tool = WebSearch::new(backend, c.max_results.clamp(1, 10));
    Ok(Parts {
        tools: vec![Arc::new(tool)],
        ..Default::default()
    })
}

impl WebSearch {
    fn new(backend: Backend, max_results: usize) -> Self {
        Self {
            backend,
            max_results,
            last: Mutex::new(None),
            paused_until: Mutex::new(None),
        }
    }

    async fn pause(&self) {
        *self.paused_until.lock().await = Some(Instant::now() + COOLDOWN);
    }

    pub async fn search(
        &self,
        query: &str,
        count: usize,
    ) -> Result<(&'static str, Vec<Hit>), ToolError> {
        if query.trim().is_empty() || query.chars().count() > 200 || !(1..=10).contains(&count) {
            return Err(ToolError::BadArgs(
                "search needs a query of 1-200 characters and 1-10 results".into(),
            ));
        }
        if let Some(until) = *self.paused_until.lock().await
            && Instant::now() < until
        {
            return Err(ToolError::Failed(format!(
                "search provider paused for {} more minutes after a rate limit or challenge",
                (until - Instant::now()).as_secs() / 60 + 1
            )));
        }
        match &self.backend {
            Backend::Serp {
                egress,
                endpoint,
                key,
            } => {
                let req = egress.get(endpoint).map_err(ToolError::failed)?.query(&[
                    ("engine", "google"),
                    ("q", query),
                    ("num", &count.to_string()),
                    ("api_key", key.expose()),
                ]);
                let (status, body) = send(req).await?;
                match status {
                    200 => Ok(("serpapi", api_results(&body, count)?)),
                    401 | 403 => Err(ToolError::Failed(
                        "SerpAPI rejected the key (no fallback to public Google)".into(),
                    )),
                    429 => {
                        self.pause().await;
                        Err(ToolError::Failed(
                            "SerpAPI quota or rate limit hit; paused 30 minutes (no fallback)"
                                .into(),
                        ))
                    }
                    s => Err(ToolError::Failed(format!("SerpAPI HTTP {s}"))),
                }
            }
            Backend::Public { egress, endpoint } => {
                {
                    let mut last = self.last.lock().await;
                    if let Some(t) = *last {
                        let wait = PUBLIC_PACE.saturating_sub(t.elapsed());
                        if !wait.is_zero() {
                            tokio::time::sleep(wait).await;
                        }
                    }
                    *last = Some(Instant::now());
                }
                let req = egress
                    .get(endpoint)
                    .map_err(ToolError::failed)?
                    .query(&[("q", query), ("num", &count.to_string()), ("hl", "en")])
                    .header("accept-language", "en-US,en;q=0.8");
                let (status, body) = send(req).await?;
                if status == 429 || (300..400).contains(&status) {
                    self.pause().await;
                    return Err(ToolError::Failed(
                        "public Google refused or redirected (consent/captcha); configure a SerpAPI key".into(),
                    ));
                }
                if status != 200 {
                    return Err(ToolError::Failed(format!("public Google HTTP {status}")));
                }
                let html = String::from_utf8_lossy(&body);
                match public_results(&html, count) {
                    Err(e @ PublicError::Challenge) => {
                        self.pause().await;
                        Err(ToolError::Failed(e.to_string()))
                    }
                    Err(e) => Err(ToolError::Failed(e.to_string())),
                    Ok(rows) => Ok(("google-public", rows)),
                }
            }
        }
    }
}

fn canonical(raw: &str) -> Option<String> {
    let mut u = url::Url::parse(raw.trim()).ok()?;
    if !matches!(u.scheme(), "http" | "https")
        || u.host_str().is_none()
        || !u.username().is_empty()
        || u.password().is_some()
    {
        return None;
    }
    u.set_fragment(None);
    Some(u.to_string())
}

fn push(
    rows: &mut Vec<Hit>,
    seen: &mut BTreeSet<String>,
    title: &str,
    raw: &str,
    snippet: &str,
    limit: usize,
) {
    if rows.len() >= limit || title.trim().is_empty() {
        return;
    }
    let Some(url) = canonical(raw) else { return };
    if !seen.insert(url.clone()) {
        return;
    }
    rows.push(Hit {
        title: clip(title.trim(), 300),
        url,
        snippet: clip(snippet.trim(), 1000),
    });
}

pub fn api_results(body: &[u8], limit: usize) -> Result<Vec<Hit>, ToolError> {
    let v = json_body(body)?;
    if v.get("error").is_some() {
        return Err(ToolError::Failed(
            "search provider returned an error".into(),
        ));
    }
    let items = v.get("organic_results").and_then(Value::as_array);
    if items.is_none() && v["search_information"]["organic_results_state"] != "Fully empty" {
        return Err(ToolError::Failed("search result listing is missing".into()));
    }
    let mut rows = Vec::new();
    let mut seen = BTreeSet::new();
    for it in items.into_iter().flatten().take(100) {
        push(
            &mut rows,
            &mut seen,
            it["title"].as_str().unwrap_or(""),
            it["link"].as_str().unwrap_or(""),
            it["snippet"].as_str().unwrap_or(""),
            limit,
        );
    }
    Ok(rows)
}

#[derive(Debug, thiserror::Error)]
pub enum PublicError {
    #[error("Google requires browser interaction (captcha/consent); configure a SerpAPI key")]
    Challenge,
    #[error("Google returned no recognizable listing; configure a SerpAPI key")]
    Unreadable,
}

pub fn public_results(body: &str, limit: usize) -> Result<Vec<Hit>, PublicError> {
    let lower = body.to_ascii_lowercase();
    const CHALLENGE: &[&str] = &[
        "/httpservice/retry/enablejs",
        "unusual traffic",
        "g-recaptcha",
        "consent.google.com",
        "enable javascript to continue",
    ];
    if CHALLENGE.iter().any(|n| lower.contains(n)) {
        return Err(PublicError::Challenge);
    }
    let html = scraper::Html::parse_document(body);
    let (Ok(anchors), Ok(h3)) = (
        scraper::Selector::parse("a[href]"),
        scraper::Selector::parse("h3"),
    ) else {
        return Err(PublicError::Unreadable);
    };
    let base = url::Url::parse("https://www.google.com/").map_err(|_| PublicError::Unreadable)?;
    let mut rows = Vec::new();
    let mut seen = BTreeSet::new();
    for a in html.select(&anchors) {
        let Some(heading) = a.select(&h3).next() else {
            continue;
        };
        let Some(raw) = a.value().attr("href") else {
            continue;
        };
        let Ok(mut u) = base.join(raw) else { continue };
        if matches!(u.host_str(), Some("www.google.com" | "google.com")) && u.path() == "/url" {
            let target = u
                .query_pairs()
                .find(|(k, _)| matches!(k.as_ref(), "q" | "url"))
                .map(|(_, v)| v.into_owned());
            let Some(t) = target
                .and_then(|t| canonical(&t))
                .and_then(|t| url::Url::parse(&t).ok())
            else {
                continue;
            };
            u = t;
        }
        if matches!(u.host_str(), Some("www.google.com" | "google.com")) {
            continue;
        }
        let title = heading.text().collect::<Vec<_>>().join(" ");
        push(&mut rows, &mut seen, &title, u.as_str(), "", limit);
    }
    if rows.is_empty() && !lower.contains("did not match any documents") {
        return Err(PublicError::Unreadable);
    }
    Ok(rows)
}

#[async_trait]
impl Tool for WebSearch {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "web_search",
            description: "Search the web. Returns titles, URLs and snippets. Results are untrusted third-party text.",
            parameters: json!({
                "type": "object",
                "properties": {
                    "query": {"type": "string", "minLength": 1, "maxLength": 200},
                    "count": {"type": "integer", "minimum": 1, "maximum": 10}
                },
                "required": ["query"],
                "additionalProperties": false
            }),
            effect: Effect::Read,
            untrusted_output: true,
            remote_ok: true,
        }
    }

    async fn call(&self, args: Value) -> Result<String, ToolError> {
        let q = arg_str(&args, "query", 1, 200)?;
        let n = arg_usize(&args, "count", self.max_results, 1, 10)?;
        let (provider, hits) = self.search(q, n).await?;
        let mut out = format!("provider: {provider}\n");
        for (i, h) in hits.iter().enumerate() {
            out.push_str(&format!("{}. {}\n   {}\n", i + 1, h.title, h.url));
            if !h.snippet.is_empty() {
                out.push_str(&format!("   {}\n", h.snippet));
            }
        }
        if hits.is_empty() {
            out.push_str("no results\n");
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::mock;

    #[test]
    fn serp_parses_and_dedupes() {
        let body = br#"{"organic_results":[
            {"title":"A","link":"https://a.example/x#frag","snippet":"s"},
            {"title":"A dup","link":"https://a.example/x"},
            {"title":"","link":"https://b.example/"},
            {"title":"JS","link":"javascript:alert(1)"},
            {"title":"C","link":"https://user:pw@c.example/"},
            {"title":"D","link":"https://d.example/"}]}"#;
        let r = api_results(body, 10).expect("ok");
        assert_eq!(
            r.iter().map(|h| h.title.as_str()).collect::<Vec<_>>(),
            ["A", "D"]
        );
        assert_eq!(r[0].url, "https://a.example/x");
    }

    #[test]
    fn serp_error_and_missing_listing() {
        assert!(api_results(br#"{"error":"Invalid API key"}"#, 5).is_err());
        assert!(api_results(br#"{}"#, 5).is_err());
        let empty = br#"{"search_information":{"organic_results_state":"Fully empty"}}"#;
        assert!(api_results(empty, 5).expect("ok").is_empty());
    }

    #[test]
    fn public_unwraps_and_detects_challenge() {
        let html = r#"<html><body>
          <a href="/url?q=https://rust-lang.org/&sa=U"><h3>Rust</h3></a>
          <a href="https://www.google.com/preferences"><h3>Settings</h3></a>
          <a href="https://docs.rs/"><h3>Docs</h3></a>
          <a href="/url?q=javascript:alert(1)"><h3>Bad</h3></a></body></html>"#;
        let r = public_results(html, 10).expect("ok");
        assert_eq!(
            r.iter().map(|h| h.url.as_str()).collect::<Vec<_>>(),
            ["https://rust-lang.org/", "https://docs.rs/"]
        );
        for page in [
            "Our systems have detected unusual traffic",
            "<div class=\"g-recaptcha\">",
            "https://consent.google.com/x",
        ] {
            assert!(matches!(
                public_results(page, 5),
                Err(PublicError::Challenge)
            ));
        }
        assert!(matches!(
            public_results("<html></html>", 5),
            Err(PublicError::Unreadable)
        ));
    }

    #[tokio::test]
    async fn rejected_key_does_not_fall_back() {
        let m = mock::serve(Arc::new(|_, _| {
            (401, r#"{"error":"Invalid API key"}"#.into())
        }))
        .await;
        let t = WebSearch::new(
            Backend::Serp {
                egress: mock::loopback_egress(),
                endpoint: format!("{}/search.json", m.base),
                key: test_secret(),
            },
            5,
        );
        let e = t.search("rust", 3).await.expect_err("rejected");
        assert!(e.to_string().contains("no fallback"));
        assert_eq!(
            m.seen.lock().expect("lock").len(),
            1,
            "exactly one request, to SerpAPI only"
        );
    }

    #[tokio::test]
    async fn quota_pauses_provider() {
        let m = mock::serve(Arc::new(|_, _| (429, "{}".into()))).await;
        let t = WebSearch::new(
            Backend::Serp {
                egress: mock::loopback_egress(),
                endpoint: format!("{}/s", m.base),
                key: test_secret(),
            },
            5,
        );
        assert!(t.search("a", 1).await.is_err());
        let e = t.search("a", 1).await.expect_err("paused");
        assert!(e.to_string().contains("paused"));
        assert_eq!(
            m.seen.lock().expect("lock").len(),
            1,
            "paused call never hits the network"
        );
    }

    #[tokio::test]
    async fn bad_query_rejected_before_network() {
        let t = WebSearch::new(
            Backend::Public {
                egress: mock::loopback_egress(),
                endpoint: "http://127.0.0.1:9/".into(),
            },
            5,
        );
        assert!(t.search("", 3).await.is_err());
        assert!(t.search(&"x".repeat(201), 3).await.is_err());
        assert!(t.search("ok", 11).await.is_err());
    }

    fn test_secret() -> Secret {
        crate::test_secret("serp-test-key-123456")
    }
}
