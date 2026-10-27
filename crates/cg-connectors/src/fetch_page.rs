//! Read one web page as plain text, from operator-pinned hosts only.
//!
//! `web_search` returns snippets; this lets a turn read the page behind a
//! result when its host is on `hosts` in cg.toml. The host list is fixed at
//! startup and is not reachable from the UI overlay, so the connector keeps
//! the usual `Egress` guarantees: exact hosts, HTTPS only, no redirects (a
//! 3xx is an error, never followed), no proxy, no IP literals, a capped body.
//! Output is third-party text: `untrusted_output` (sanitized, wrapped, taints
//! the turn) and not offered to remote origins.

use std::sync::Arc;

use async_trait::async_trait;
use cg_core::egress::Egress;
use cg_core::tools::{Effect, Tool, ToolError, ToolSpec};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::common::{HTTP_TIMEOUT, arg_str, clip, read_capped};
use crate::{Ctx, Parts};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct FetchPageConfig {
    pub enabled: bool,
    /// Exact DNS names, e.g. ["docs.rs", "en.wikipedia.org"]. No wildcards.
    pub hosts: Vec<String>,
    pub max_chars: usize,
}
impl Default for FetchPageConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            hosts: Vec::new(),
            max_chars: 8000,
        }
    }
}

/// Pages larger than this are refused rather than truncated mid-markup.
const MAX_PAGE_BYTES: usize = 2 * 1024 * 1024;

pub async fn build(ctx: &Ctx<'_>) -> anyhow::Result<Parts> {
    let c: FetchPageConfig = crate::common::section(ctx.connectors, "fetch_page")?;
    if !c.enabled {
        return Ok(Parts::default());
    }
    let hosts = valid_hosts(&c.hosts)?;
    let refs: Vec<&str> = hosts.iter().map(String::as_str).collect();
    let egress = Egress::new("fetch_page", &refs, false, HTTP_TIMEOUT)?;
    Ok(Parts {
        tools: vec![Arc::new(FetchPage {
            egress,
            max_chars: c.max_chars.clamp(500, 12_000),
        })],
        ..Default::default()
    })
}

/// An enabled connector with no hosts is a startup error, never "any host".
pub fn valid_hosts(hosts: &[String]) -> anyhow::Result<Vec<String>> {
    anyhow::ensure!(
        !hosts.is_empty(),
        "fetch_page is enabled but `hosts` is empty; list the exact hosts it may read"
    );
    hosts
        .iter()
        .map(|h| {
            let h = h.trim().to_ascii_lowercase();
            let label_ok = |l: &str| {
                !l.is_empty()
                    && l.len() <= 63
                    && !l.starts_with('-')
                    && !l.ends_with('-')
                    && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            };
            let ok = h.len() <= 253
                && h.contains('.')
                && h.split('.').all(label_ok)
                && !h.split('.').all(|l| l.bytes().all(|b| b.is_ascii_digit()));
            anyhow::ensure!(
                ok,
                "fetch_page: `{h}` is not a plain host name (no scheme, port, path, wildcard or IP)"
            );
            Ok(h)
        })
        .collect()
}

pub struct FetchPage {
    egress: Egress,
    max_chars: usize,
}

fn allowed_type(content_type: &str) -> Option<bool> {
    let t = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    match t.as_str() {
        "text/html" | "application/xhtml+xml" => Some(true),
        "text/plain" | "text/markdown" => Some(false),
        _ => None,
    }
}

/// Visible text of an HTML document: title plus body text, with script,
/// style and other non-content elements dropped and whitespace collapsed.
pub fn html_text(html: &str) -> (String, String) {
    const SKIP: &[&str] = &[
        "script", "style", "noscript", "template", "svg", "head", "iframe", "object",
    ];
    let doc = scraper::Html::parse_document(html);
    let title = scraper::Selector::parse("title")
        .ok()
        .and_then(|s| doc.select(&s).next())
        .map(|t| t.text().collect::<Vec<_>>().join(" "))
        .unwrap_or_default();
    let mut words: Vec<&str> = Vec::new();
    for node in doc.root_element().descendants() {
        let Some(text) = node.value().as_text() else {
            continue;
        };
        let hidden = node.ancestors().any(|a| {
            a.value()
                .as_element()
                .is_some_and(|e| SKIP.contains(&e.name()))
        });
        if !hidden {
            words.extend(text.split_whitespace());
        }
    }
    (
        title.split_whitespace().collect::<Vec<_>>().join(" "),
        words.join(" "),
    )
}

#[async_trait]
impl Tool for FetchPage {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "fetch_page",
            description: "Read one web page as plain text. Only operator-allowed hosts work; others are refused. Page text is untrusted third-party content.",
            parameters: json!({
                "type": "object",
                "properties": {
                    "url": {"type": "string", "minLength": 8, "maxLength": 2000}
                },
                "required": ["url"],
                "additionalProperties": false
            }),
            effect: Effect::Read,
            untrusted_output: true,
            remote_ok: false,
        }
    }

    async fn call(&self, args: Value) -> Result<String, ToolError> {
        let url = arg_str(&args, "url", 8, 2000)?;
        let req = self
            .egress
            .get(url)
            .map_err(|e| ToolError::Failed(e.to_string()))?
            .header("accept", "text/html, text/plain;q=0.9");
        let resp = req
            .send()
            .await
            .map_err(|e| ToolError::failed(e.without_url()))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(ToolError::Failed(format!(
                "HTTP {} (redirects are not followed)",
                status.as_u16()
            )));
        }
        let ctype = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let Some(is_html) = allowed_type(&ctype) else {
            return Err(ToolError::Failed(format!(
                "unsupported content type `{ctype}` (HTML or plain text only)"
            )));
        };
        let body = read_capped(resp, MAX_PAGE_BYTES).await?;
        let text = String::from_utf8_lossy(&body);
        let (title, text) = if is_html {
            html_text(&text)
        } else {
            (
                String::new(),
                text.split_whitespace().collect::<Vec<_>>().join(" "),
            )
        };
        Ok(format!(
            "url: {url}\ntitle: {title}\n\n{}",
            clip(&text, self.max_chars)
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts_must_be_exact_names() {
        assert!(valid_hosts(&[]).is_err(), "enabled with no hosts must fail");
        assert_eq!(
            valid_hosts(&[" Docs.RS ".into()]).expect("ok"),
            vec!["docs.rs".to_string()]
        );
        for bad in [
            "*.example.com",
            "https://docs.rs",
            "docs.rs:443",
            "docs.rs/x",
            "localhost",
            "10.0.0.1",
            "-a.example",
            "a..b",
        ] {
            assert!(valid_hosts(&[bad.into()]).is_err(), "{bad}");
        }
    }

    #[test]
    fn html_text_drops_scripts_and_collapses_whitespace() {
        let (title, text) = html_text(
            "<html><head><title> Page  T </title><style>p{}</style></head>\
             <body><script>steal()</script><h1>Hi</h1>\n<p>one\n two</p>\
             <noscript>x</noscript><svg><text>s</text></svg></body></html>",
        );
        assert_eq!(title, "Page T");
        assert_eq!(text, "Hi one two");
    }

    #[test]
    fn only_text_types_are_read() {
        assert_eq!(allowed_type("text/html; charset=utf-8"), Some(true));
        assert_eq!(allowed_type("TEXT/PLAIN"), Some(false));
        assert_eq!(allowed_type("application/pdf"), None);
        assert_eq!(allowed_type(""), None);
    }

    #[tokio::test]
    async fn unpinned_hosts_and_plain_http_are_refused_before_any_request() {
        let t = FetchPage {
            egress: Egress::new("fetch_page", &["docs.rs"], false, HTTP_TIMEOUT).expect("e"),
            max_chars: 1000,
        };
        for url in [
            "https://evil.example/x",
            "http://docs.rs/x",
            "https://user:pw@docs.rs/",
            "https://127.0.0.1/",
        ] {
            let e = t.call(json!({ "url": url })).await.expect_err(url);
            assert!(
                e.to_string().contains("refused") || e.to_string().contains("not"),
                "{url}: {e}"
            );
        }
        assert!(
            t.spec().untrusted_output && t.spec().effect == Effect::Read && !t.spec().remote_ok
        );
    }

    #[tokio::test]
    async fn enabled_without_hosts_fails_startup() {
        let mut cfg = cg_core::config::Config::default();
        cfg.connectors.insert(
            "fetch_page".into(),
            toml::Value::Table(toml::from_str("enabled = true").expect("t")),
        );
        let secrets = cg_core::secrets::SecretStore::new(std::env::temp_dir());
        assert!(crate::build_all(&cfg, &secrets).await.is_err());
    }
}
