//! Google OAuth for Gmail/Calendar: installed-app loopback flow with PKCE
//! (RFC 8252 + RFC 7636). The refresh token is stored via SecretStore::store
//! (macOS Keychain, else an owner-only file). Access tokens live in memory.

use std::time::{Duration, Instant};

use base64::Engine;
use cg_core::egress::Egress;
use cg_core::secrets::{Secret, SecretStore};
use cg_core::tools::ToolError;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

use crate::common::{ct_eq, egress, json_body, random_token, send};

pub const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
pub const AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
pub const SCOPE_GMAIL_READ: &str = "https://www.googleapis.com/auth/gmail.readonly";
pub const SCOPE_GMAIL_COMPOSE: &str = "https://www.googleapis.com/auth/gmail.compose";
pub const SCOPE_GMAIL_SEND: &str = "https://www.googleapis.com/auth/gmail.send";
pub const SCOPE_CAL_EVENTS: &str = "https://www.googleapis.com/auth/calendar.events";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct GoogleCreds {
    pub enabled: bool,
    pub client_id_ref: String,
    pub client_secret_ref: String,
    pub refresh_token_ref: String,
    pub max_results: usize,
    pub calendar_id: String,
}
impl Default for GoogleCreds {
    fn default() -> Self {
        Self {
            enabled: false,
            client_id_ref: "env:GOOGLE_CLIENT_ID".into(),
            client_secret_ref: "env:GOOGLE_CLIENT_SECRET".into(),
            refresh_token_ref: "file:google_refresh_token".into(),
            max_results: 10,
            calendar_id: "primary".into(),
        }
    }
}

pub struct GoogleAuth {
    egress: Egress,
    token_url: String,
    client_id: Secret,
    client_secret: Secret,
    refresh: Secret,
    cached: Mutex<Option<(Secret, Instant)>>,
}

impl GoogleAuth {
    pub async fn from_config(c: &GoogleCreds, secrets: &SecretStore) -> anyhow::Result<Self> {
        let client_id = secrets
            .resolve(&c.client_id_ref)
            .await
            .map_err(|e| anyhow::anyhow!("google client_id: {e}"))?;
        let client_secret = secrets
            .resolve(&c.client_secret_ref)
            .await
            .map_err(|e| anyhow::anyhow!("google client_secret: {e}"))?;
        let refresh = secrets.resolve(&c.refresh_token_ref).await.map_err(|e| {
            anyhow::anyhow!("google refresh token ({e}); run `cg-researcher google-auth` first")
        })?;
        Ok(Self::new(
            egress("google_oauth", &["oauth2.googleapis.com"])?,
            TOKEN_URL.into(),
            client_id,
            client_secret,
            refresh,
        ))
    }

    pub(crate) fn new(
        egress: Egress,
        token_url: String,
        client_id: Secret,
        client_secret: Secret,
        refresh: Secret,
    ) -> Self {
        Self {
            egress,
            token_url,
            client_id,
            client_secret,
            refresh,
            cached: Mutex::new(None),
        }
    }

    pub async fn access_token(&self) -> Result<Secret, ToolError> {
        let mut g = self.cached.lock().await;
        if let Some((tok, exp)) = g.as_ref()
            && Instant::now() + Duration::from_secs(60) < *exp
        {
            return Ok(tok.clone());
        }
        let req = self
            .egress
            .post(&self.token_url)
            .map_err(ToolError::failed)?
            .form(&[
                ("client_id", self.client_id.expose()),
                ("client_secret", self.client_secret.expose()),
                ("refresh_token", self.refresh.expose()),
                ("grant_type", "refresh_token"),
            ]);
        let (status, body) = send(req).await?;
        if status != 200 {
            return Err(ToolError::Failed(format!(
                "Google token refresh HTTP {status}; re-run `cg-researcher google-auth`"
            )));
        }
        let v = json_body(&body)?;
        let tok = v["access_token"]
            .as_str()
            .ok_or_else(|| ToolError::Failed("no access_token".into()))?;
        let ttl = v["expires_in"].as_u64().unwrap_or(3600).min(3600);
        let tok = Secret::minted(tok.to_string());
        *g = Some((tok.clone(), Instant::now() + Duration::from_secs(ttl)));
        Ok(tok)
    }
}

pub fn pkce_pair() -> anyhow::Result<(String, String)> {
    let verifier = random_token(48)?;
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(Sha256::digest(verifier.as_bytes()));
    Ok((verifier, challenge))
}

/// Run the loopback authorization. Prints the consent URL (and returns it to
/// `on_url` so the CLI can `open` it), waits up to 5 minutes for exactly one
/// redirect to 127.0.0.1, exchanges the code and stores the refresh token.
pub async fn authorize(
    client_id: &Secret,
    client_secret: &Secret,
    scopes: &[&str],
    secrets: &SecretStore,
    on_url: impl FnOnce(&str),
) -> anyhow::Result<String> {
    anyhow::ensure!(
        !scopes.is_empty(),
        "no Google connector is enabled; nothing to authorize"
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let redirect = format!("http://127.0.0.1:{}", listener.local_addr()?.port());
    let (verifier, challenge) = pkce_pair()?;
    let state = random_token(24)?;
    let mut url = url::Url::parse(AUTH_URL)?;
    url.query_pairs_mut()
        .append_pair("client_id", client_id.expose())
        .append_pair("redirect_uri", &redirect)
        .append_pair("response_type", "code")
        .append_pair("scope", &scopes.join(" "))
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("state", &state)
        .append_pair("access_type", "offline")
        .append_pair("prompt", "consent");
    on_url(url.as_str());

    let (code, got_state) = tokio::time::timeout(Duration::from_secs(300), async {
        loop {
            let (mut s, peer) = listener.accept().await?;
            if !peer.ip().is_loopback() {
                continue;
            }
            // Any local process can connect here: an idle connection (or a
            // browser preconnect) must not block the real redirect, and a
            // request without our `state` must neither finish nor abort the flow.
            let mut buf = vec![0u8; 8192];
            let Ok(Ok(n)) = tokio::time::timeout(Duration::from_secs(10), s.read(&mut buf)).await else {
                continue;
            };
            let head = String::from_utf8_lossy(&buf[..n]).to_string();
            let target = head.lines().next().and_then(|l| l.split_whitespace().nth(1)).unwrap_or("/").to_string();
            let Ok(u) = url::Url::parse(&format!("http://127.0.0.1{target}")) else {
                continue;
            };
            let q: std::collections::HashMap<_, _> = u.query_pairs().into_owned().collect();
            let ours = q.get("state").is_some_and(|st| ct_eq(st, &state));
            let page = if ours && q.contains_key("code") { "cg-researcher: authorized. You can close this tab." } else { "cg-researcher: authorization failed." };
            let _ = s
                .write_all(format!("HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{page}", page.len()).as_bytes())
                .await;
            if !ours {
                continue;
            }
            if let Some(e) = q.get("error") {
                anyhow::bail!("Google returned error: {}", cg_core::sanitizer::redact(e));
            }
            if let (Some(c), Some(st)) = (q.get("code"), q.get("state")) {
                return Ok::<_, anyhow::Error>((c.clone(), st.clone()));
            }
        }
    })
    .await
    .map_err(|_| anyhow::anyhow!("timed out waiting for the Google redirect"))??;
    anyhow::ensure!(
        ct_eq(&got_state, &state),
        "OAuth state mismatch (possible CSRF); aborting"
    );

    let eg = egress("google_oauth", &["oauth2.googleapis.com"])?;
    let req = eg.post(TOKEN_URL)?.form(&[
        ("client_id", client_id.expose()),
        ("client_secret", client_secret.expose()),
        ("code", code.as_str()),
        ("code_verifier", verifier.as_str()),
        ("grant_type", "authorization_code"),
        ("redirect_uri", redirect.as_str()),
    ]);
    let (status, body) = send(req).await.map_err(|e| anyhow::anyhow!("{e}"))?;
    anyhow::ensure!(status == 200, "token exchange HTTP {status}");
    let v = json_body(&body).map_err(|e| anyhow::anyhow!("{e}"))?;
    let refresh = v["refresh_token"].as_str().ok_or_else(|| {
        anyhow::anyhow!("Google sent no refresh_token (revoke prior grant and retry)")
    })?;
    let reference = secrets.store("google_refresh_token", refresh).await?;
    Ok(reference)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stray_local_requests_neither_finish_nor_abort_the_flow() {
        use tokio::io::AsyncWriteExt;
        let (tx, rx) = tokio::sync::oneshot::channel::<String>();
        // The flow ends in an error before anything is stored.
        let secrets = SecretStore::new(std::env::temp_dir());
        let flow = tokio::spawn(async move {
            authorize(
                &Secret::minted("client-id-test".into()),
                &Secret::minted("client-secret-test".into()),
                &["https://www.googleapis.com/auth/gmail.readonly"],
                &secrets,
                |u| {
                    let _ = tx.send(u.to_string());
                },
            )
            .await
        });
        let u = url::Url::parse(&rx.await.expect("url")).expect("parse");
        let q: std::collections::HashMap<_, _> = u.query_pairs().into_owned().collect();
        let port = url::Url::parse(&q["redirect_uri"])
            .expect("r")
            .port()
            .expect("port");
        let state = q["state"].clone();
        for path in [
            "GET http://[bad HTTP/1.1".to_string(),
            "GET /?code=stolen&state=wrong HTTP/1.1".to_string(),
            "GET /?error=access_denied&state=wrong HTTP/1.1".to_string(),
            format!("GET /?error=access_denied&state={state} HTTP/1.1"),
        ] {
            let mut c = tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .expect("c");
            c.write_all(format!("{path}\r\nhost: x\r\n\r\n").as_bytes())
                .await
                .expect("w");
            let mut sink = Vec::new();
            let _ = tokio::io::AsyncReadExt::read_to_end(&mut c, &mut sink).await;
        }
        let e = flow
            .await
            .expect("join")
            .expect_err("only our state ends it");
        assert!(e.to_string().contains("Google returned error"), "{e}");
    }
    use crate::common::mock;
    use std::sync::Arc;

    #[test]
    fn pkce_is_s256_of_verifier() {
        let (v, c) = pkce_pair().expect("pkce");
        assert!(v.len() >= 43 && v.len() <= 128);
        assert_eq!(
            c,
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(v.as_bytes()))
        );
    }

    #[tokio::test]
    async fn refresh_is_cached() {
        let m = mock::serve(Arc::new(|_, body| {
            assert!(body.contains("grant_type=refresh_token"));
            (
                200,
                r#"{"access_token":"ya29.test-token-abcdef","expires_in":3599}"#.into(),
            )
        }))
        .await;
        let a = GoogleAuth::new(
            mock::loopback_egress(),
            format!("{}/token", m.base),
            Secret::minted("cid".into()),
            Secret::minted("csecret-xyz".into()),
            Secret::minted("1//refresh-abc".into()),
        );
        assert_eq!(
            a.access_token().await.expect("tok").expose(),
            "ya29.test-token-abcdef"
        );
        let _ = a.access_token().await.expect("tok");
        assert_eq!(m.seen.lock().expect("lock").len(), 1);
        assert!(
            !cg_core::sanitizer::redact("x ya29.test-token-abcdef y")
                .contains("ya29.test-token-abcdef")
        );
    }
}
