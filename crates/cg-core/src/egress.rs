//! Pinned egress. Every outbound HTTP request in the workspace goes through an
//! [`Egress`] that names its connector and the exact hosts it may reach.
//!
//! * HTTPS only, except loopback HTTP for local model servers;
//! * exact host match (no suffix matching, so `api.x.ai.evil.com` fails);
//! * redirects are refused, so a pinned host cannot bounce the request;
//! * proxy environment variables are ignored (`no_proxy`), so a stray
//!   `HTTPS_PROXY` cannot route traffic through a third party;
//! * no telemetry, tracing exporters or crash reporters exist in the build.

use std::net::IpAddr;
use std::time::Duration;

use reqwest::{Client, Method, RequestBuilder};
use url::Url;

#[derive(Debug, thiserror::Error)]
pub enum EgressError {
    #[error("egress refused for {connector}: {reason}")]
    Refused {
        connector: &'static str,
        reason: String,
    },
    #[error("http client: {0}")]
    Client(#[from] reqwest::Error),
}

pub fn is_loopback_url(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        Some(url::Host::Domain(d)) => d.eq_ignore_ascii_case("localhost"),
        None => false,
    }
}

#[derive(Clone)]
pub struct Egress {
    connector: &'static str,
    hosts: Vec<String>,
    allow_loopback_http: bool,
    client: Client,
}

impl Egress {
    pub fn new(
        connector: &'static str,
        hosts: &[&str],
        allow_loopback_http: bool,
        timeout: Duration,
    ) -> Result<Self, EgressError> {
        let client = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .timeout(timeout)
            .connect_timeout(Duration::from_secs(15))
            .user_agent(concat!("cg-researcher/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self {
            connector,
            hosts: hosts.iter().map(|h| h.to_ascii_lowercase()).collect(),
            allow_loopback_http,
            client,
        })
    }

    pub fn connector(&self) -> &'static str {
        self.connector
    }
    pub fn hosts(&self) -> &[String] {
        &self.hosts
    }

    pub fn check(&self, url: &Url) -> Result<(), EgressError> {
        let refuse = |reason: String| EgressError::Refused {
            connector: self.connector,
            reason,
        };
        if !url.username().is_empty() || url.password().is_some() {
            return Err(refuse("credentials in URL".into()));
        }
        let loopback = is_loopback_url(url);
        match url.scheme() {
            "https" => {}
            "http" if loopback && self.allow_loopback_http => {}
            s => return Err(refuse(format!("scheme {s} not allowed"))),
        }
        if loopback && self.allow_loopback_http {
            return Ok(());
        }
        let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
        if host.parse::<IpAddr>().is_ok() {
            return Err(refuse("IP-literal hosts are not pinned".into()));
        }
        if self.hosts.contains(&host) {
            Ok(())
        } else {
            Err(refuse(format!("host {host} is not pinned")))
        }
    }

    pub fn request(&self, method: Method, url: &str) -> Result<RequestBuilder, EgressError> {
        let parsed = Url::parse(url).map_err(|e| EgressError::Refused {
            connector: self.connector,
            reason: e.to_string(),
        })?;
        self.check(&parsed)?;
        Ok(self.client.request(method, parsed))
    }
    pub fn get(&self, url: &str) -> Result<RequestBuilder, EgressError> {
        self.request(Method::GET, url)
    }
    pub fn post(&self, url: &str) -> Result<RequestBuilder, EgressError> {
        self.request(Method::POST, url)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(loopback: bool) -> Egress {
        Egress::new("test", &["api.x.ai"], loopback, Duration::from_secs(1)).expect("client")
    }

    #[test]
    fn exact_host_https_only() {
        let g = e(false);
        assert!(
            g.check(&Url::parse("https://api.x.ai/v1").expect("u"))
                .is_ok()
        );
        assert!(
            g.check(&Url::parse("http://api.x.ai/v1").expect("u"))
                .is_err()
        );
        assert!(
            g.check(&Url::parse("https://api.x.ai.evil.com/").expect("u"))
                .is_err()
        );
        assert!(g.check(&Url::parse("https://x.ai/").expect("u")).is_err());
        assert!(
            g.check(&Url::parse("https://user:pw@api.x.ai/").expect("u"))
                .is_err()
        );
        assert!(
            g.check(&Url::parse("https://1.2.3.4/").expect("u"))
                .is_err()
        );
    }

    #[test]
    fn loopback_http_only_when_allowed() {
        assert!(
            e(true)
                .check(&Url::parse("http://127.0.0.1:11434/v1").expect("u"))
                .is_ok()
        );
        assert!(
            e(false)
                .check(&Url::parse("http://127.0.0.1:11434/v1").expect("u"))
                .is_err()
        );
        assert!(
            e(true)
                .check(&Url::parse("http://10.0.0.2:11434/v1").expect("u"))
                .is_err()
        );
    }
}
