//! Pinned egress. Every outbound HTTP request in the workspace goes through an
//! [`Egress`] that names its connector and the exact hosts it may reach.
//!
//! * HTTPS only, except loopback HTTP for local model servers;
//! * exact host match (no suffix matching, so `api.x.ai.evil.com` fails);
//! * redirects are refused, so a pinned host cannot bounce the request;
//! * proxy environment variables are ignored (`no_proxy`), so a stray
//!   `HTTPS_PROXY` cannot route traffic through a third party;
//! * no telemetry, tracing exporters or crash reporters exist in the build.
//!
//! TLS (rustls, never OpenSSL):
//!
//! * a client that may not use loopback HTTP is built `https_only`, so the
//!   reqwest client itself refuses `http://` even if a caller skipped
//!   [`Egress::check`]; it also pins a TLS 1.2 floor, which is what rustls
//!   ships today, written down so a backend change cannot lower it silently;
//! * [`Egress::new_tls13`] is the external-model client (API key + prompt on
//!   the wire): TLS 1.3 only and, by default, Mozilla's root program compiled
//!   in from `webpki-root-certs` instead of the OS trust store. A root CA
//!   installed locally (MDM profile, corporate TLS inspection, malware with
//!   admin rights) is then not trusted for those hosts. [`TlsRoots::System`]
//!   restores the OS store; it is a `cg.toml`-only setting, not a UI one.
//! * No certificate pinning: providers rotate intermediates and leaf keys, and a
//!   stale pin is an outage. The pinned host list plus root choice is the line.

use std::net::IpAddr;
use std::time::Duration;

use reqwest::tls::Version;
use reqwest::{Certificate, Client, ClientBuilder, Method, RequestBuilder};
use url::Url;

/// Trust anchors for the external-model client (`external.tls_roots`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TlsRoots {
    /// Mozilla's root program only (`webpki-root-certs`, updated with the crate).
    /// Locally installed roots are ignored. No OCSP/CRL revocation checks.
    #[default]
    Mozilla,
    /// The OS trust store via rustls-platform-verifier (on macOS: Security.framework,
    /// including admin- or MDM-installed roots and Apple's revocation checks).
    System,
}

fn mozilla_roots() -> Result<Vec<Certificate>, EgressError> {
    webpki_root_certs::TLS_SERVER_ROOT_CERTS
        .iter()
        .map(|c| Certificate::from_der(c.as_ref()).map_err(EgressError::Client))
        .collect()
}

fn base_builder(timeout: Duration) -> ClientBuilder {
    Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .timeout(timeout)
        .connect_timeout(Duration::from_secs(15))
        .user_agent(concat!("cg-researcher/", env!("CARGO_PKG_VERSION")))
}

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
        let mut b = base_builder(timeout);
        if !allow_loopback_http {
            b = b.https_only(true).tls_version_min(Version::TLS_1_2);
        }
        Ok(Self {
            connector,
            hosts: hosts.iter().map(|h| h.to_ascii_lowercase()).collect(),
            allow_loopback_http,
            client: b.build()?,
        })
    }

    /// Remote model APIs: pinned HTTPS hosts, TLS 1.3 only, `roots` as trust anchors.
    /// Never allows loopback HTTP (loopback mocks use [`Egress::new`]).
    pub fn new_tls13(
        connector: &'static str,
        hosts: &[&str],
        timeout: Duration,
        roots: TlsRoots,
    ) -> Result<Self, EgressError> {
        let mut b = base_builder(timeout)
            .https_only(true)
            .tls_version_min(Version::TLS_1_3);
        if roots == TlsRoots::Mozilla {
            b = b.tls_certs_only(mozilla_roots()?);
        }
        Ok(Self {
            connector,
            hosts: hosts.iter().map(|h| h.to_ascii_lowercase()).collect(),
            allow_loopback_http: false,
            client: b.build()?,
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

    /// Accept one connection on 127.0.0.1, read the first TLS record, and return the
    /// protocol versions the client offered in its ClientHello `supported_versions`
    /// extension (RFC 8446 4.2.1). This is the wire, not the builder's config.
    async fn offered_versions(eg: Egress) -> Vec<u16> {
        use tokio::io::AsyncReadExt;
        let l = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = l.local_addr().expect("addr").port();
        let client = eg.client.clone();
        let req = tokio::spawn(async move {
            // Bypasses check() on purpose: this tests the client, not the pin list.
            let _ = client
                .get(format!("https://localhost:{port}/"))
                .send()
                .await;
        });
        let (mut s, _) = l.accept().await.expect("accept");
        let mut hdr = [0u8; 5];
        s.read_exact(&mut hdr).await.expect("record header");
        assert_eq!(hdr[0], 22, "handshake record");
        let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
        let mut b = vec![0u8; len];
        s.read_exact(&mut b).await.expect("record body");
        drop(s);
        req.abort();
        assert_eq!(b[0], 1, "ClientHello");
        // type(1) len(3) version(2) random(32)
        let mut i = 38;
        i += 1 + b[i] as usize; // session id
        i += 2 + u16::from_be_bytes([b[i], b[i + 1]]) as usize; // cipher suites
        i += 1 + b[i] as usize; // compression
        let end = i + 2 + u16::from_be_bytes([b[i], b[i + 1]]) as usize;
        i += 2;
        while i + 4 <= end {
            let ty = u16::from_be_bytes([b[i], b[i + 1]]);
            let n = u16::from_be_bytes([b[i + 2], b[i + 3]]) as usize;
            if ty == 0x002b {
                let list = &b[i + 5..i + 4 + n];
                return list
                    .chunks(2)
                    .map(|c| u16::from_be_bytes([c[0], c[1]]))
                    .collect();
            }
            i += 4 + n;
        }
        panic!("no supported_versions extension");
    }

    const TLS12: u16 = 0x0303;
    const TLS13: u16 = 0x0304;

    #[tokio::test]
    async fn external_client_offers_only_tls13() {
        for roots in [TlsRoots::Mozilla, TlsRoots::System] {
            let eg = Egress::new_tls13("t", &["localhost"], Duration::from_secs(2), roots)
                .expect("client");
            let v = offered_versions(eg).await;
            assert_eq!(v, vec![TLS13], "{roots:?}: {v:x?}");
        }
    }

    #[tokio::test]
    async fn non_loopback_client_floor_is_tls12() {
        let v = offered_versions(e(false)).await;
        assert!(v.contains(&TLS13) && v.contains(&TLS12), "{v:x?}");
        assert!(v.iter().all(|&x| x >= TLS12), "nothing below 1.2: {v:x?}");
    }

    #[tokio::test]
    async fn https_only_client_refuses_http_before_connecting() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        l.set_nonblocking(true).expect("nb");
        let url = format!("http://127.0.0.1:{}/", l.local_addr().expect("a").port());
        let ext =
            Egress::new_tls13("t", &[], Duration::from_secs(2), TlsRoots::Mozilla).expect("client");
        for c in [e(false).client, ext.client] {
            let err = c.get(&url).send().await.expect_err("http must be refused");
            assert!(
                err.is_builder(),
                "refused by the client, not the network: {err}"
            );
        }
        assert!(l.accept().is_err(), "no TCP connection was ever made");
        // The loopback-HTTP client (local models) still may use http.
        assert!(e(true).client.get(&url).build().is_ok());
    }

    #[test]
    fn mozilla_roots_are_compiled_in() {
        let r = mozilla_roots().expect("parse");
        assert!(
            r.len() > 100,
            "Mozilla root program has well over 100 roots"
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
