//! Shared helpers: config sections, bounded bodies, validation.

use std::time::Duration;

use cg_core::egress::Egress;
use cg_core::tools::ToolError;
use serde::de::DeserializeOwned;

/// Hard cap for any connector response body.
pub const MAX_BODY: usize = 4 * 1024 * 1024;
pub const HTTP_TIMEOUT: Duration = Duration::from_secs(30);

/// Parse `[connectors.<name>]` strictly. A missing section is the default
/// (disabled). Unknown keys and mistyped values are startup errors.
pub fn section<T: DeserializeOwned + Default>(
    connectors: &toml::Table,
    name: &str,
) -> anyhow::Result<T> {
    match connectors.get(name) {
        None => Ok(T::default()),
        Some(v) => v
            .clone()
            .try_into()
            .map_err(|e| anyhow::anyhow!("[connectors.{name}]: {e}")),
    }
}

/// Read a response body with a hard size cap (no unbounded `.bytes()`).
pub async fn read_capped(mut resp: reqwest::Response, max: usize) -> Result<Vec<u8>, ToolError> {
    if resp.content_length().is_some_and(|n| n as usize > max) {
        return Err(ToolError::Failed("response too large".into()));
    }
    let mut out = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| ToolError::failed(e.without_url()))?
    {
        if out.len() + chunk.len() > max {
            return Err(ToolError::Failed("response too large".into()));
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

/// Send a request and return (status, capped body). Errors never carry URLs
/// (bot tokens live in Telegram URLs).
pub async fn send(req: reqwest::RequestBuilder) -> Result<(u16, Vec<u8>), ToolError> {
    let resp = req
        .send()
        .await
        .map_err(|e| ToolError::failed(e.without_url()))?;
    let status = resp.status().as_u16();
    let body = read_capped(resp, MAX_BODY).await?;
    Ok((status, body))
}

pub fn json_body(body: &[u8]) -> Result<serde_json::Value, ToolError> {
    serde_json::from_slice(body).map_err(|_| ToolError::Failed("invalid JSON from provider".into()))
}

pub fn egress(name: &'static str, hosts: &[&str]) -> anyhow::Result<Egress> {
    Ok(Egress::new(name, hosts, false, HTTP_TIMEOUT)?)
}

/// Clip to `max` chars on a char boundary.
pub fn clip(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max).collect();
    out.push_str(" …[truncated]");
    out
}

pub fn arg_str<'a>(
    args: &'a serde_json::Value,
    key: &str,
    min: usize,
    max: usize,
) -> Result<&'a str, ToolError> {
    let v = args
        .get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| ToolError::BadArgs(format!("`{key}` must be a string")))?;
    let n = v.chars().count();
    if n < min || n > max {
        return Err(ToolError::BadArgs(format!(
            "`{key}` must be {min}-{max} characters"
        )));
    }
    Ok(v)
}

pub fn arg_usize(
    args: &serde_json::Value,
    key: &str,
    default: usize,
    min: usize,
    max: usize,
) -> Result<usize, ToolError> {
    match args.get(key) {
        None | Some(serde_json::Value::Null) => Ok(default),
        Some(v) => {
            let n = v
                .as_u64()
                .ok_or_else(|| ToolError::BadArgs(format!("`{key}` must be an integer")))?
                as usize;
            if n < min || n > max {
                return Err(ToolError::BadArgs(format!("`{key}` must be {min}-{max}")));
            }
            Ok(n)
        }
    }
}

/// Strict E.164: `+` then 7-15 digits, no leading zero.
pub fn is_e164(s: &str) -> bool {
    let Some(d) = s.strip_prefix('+') else {
        return false;
    };
    (7..=15).contains(&d.len()) && d.bytes().all(|b| b.is_ascii_digit()) && !d.starts_with('0')
}

/// Constant-time string equality (PINs, OAuth state).
pub fn ct_eq(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq;
    a.len() == b.len() && bool::from(a.as_bytes().ct_eq(b.as_bytes()))
}

pub fn random_token(bytes: usize) -> anyhow::Result<String> {
    use base64::Engine;
    let mut b = vec![0u8; bytes];
    getrandom::fill(&mut b).map_err(|_| anyhow::anyhow!("OS RNG unavailable"))?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b))
}

#[cfg(test)]
pub mod mock {
    //! Minimal loopback HTTP/1.1 server for connector tests. Never binds
    //! anything but 127.0.0.1:0.
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    pub type Responder = Arc<dyn Fn(&str, &str) -> (u16, String) + Send + Sync>;

    pub struct Mock {
        pub base: String,
        pub seen: Arc<Mutex<Vec<(String, String)>>>,
    }

    pub async fn serve(responder: Responder) -> Mock {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = l.local_addr().expect("addr");
        let seen: Arc<Mutex<Vec<(String, String)>>> = Arc::default();
        let seen2 = seen.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut s, _)) = l.accept().await else {
                    return;
                };
                let r = responder.clone();
                let seen = seen2.clone();
                tokio::spawn(async move {
                    let mut buf = Vec::new();
                    let mut tmp = [0u8; 4096];
                    loop {
                        let Ok(n) = s.read(&mut tmp).await else {
                            return;
                        };
                        if n == 0 {
                            return;
                        }
                        buf.extend_from_slice(&tmp[..n]);
                        if let Some(end) = find(&buf, b"\r\n\r\n") {
                            let head = String::from_utf8_lossy(&buf[..end]).to_string();
                            let cl = head
                                .lines()
                                .find_map(|l| {
                                    let (k, v) = l.split_once(':')?;
                                    k.eq_ignore_ascii_case("content-length")
                                        .then(|| v.trim().parse::<usize>().ok())
                                        .flatten()
                                })
                                .unwrap_or(0);
                            while buf.len() < end + 4 + cl {
                                let Ok(n) = s.read(&mut tmp).await else {
                                    return;
                                };
                                if n == 0 {
                                    break;
                                }
                                buf.extend_from_slice(&tmp[..n]);
                            }
                            let line = head.lines().next().unwrap_or_default().to_string();
                            let body = String::from_utf8_lossy(&buf[end + 4..]).to_string();
                            seen.lock()
                                .expect("lock")
                                .push((format!("{line}\n{head}"), body.clone()));
                            let (code, out) = r(&line, &body);
                            let resp = format!(
                                "HTTP/1.1 {code} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{out}",
                                out.len()
                            );
                            let _ = s.write_all(resp.as_bytes()).await;
                            return;
                        }
                    }
                });
            }
        });
        Mock {
            base: format!("http://{addr}"),
            seen,
        }
    }

    fn find(h: &[u8], n: &[u8]) -> Option<usize> {
        h.windows(n.len()).position(|w| w == n)
    }

    pub fn loopback_egress() -> cg_core::egress::Egress {
        cg_core::egress::Egress::new("test", &[], true, std::time::Duration::from_secs(5))
            .expect("egress")
    }
}
