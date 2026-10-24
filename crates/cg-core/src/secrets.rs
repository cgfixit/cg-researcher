//! Secret references. Config never holds a secret value, only a reference:
//!
//! * `env:NAME`                      — process environment
//! * `op://vault/item/field`         — 1Password CLI (`op read`)
//! * `keychain:service/account`      — macOS Keychain (`/usr/bin/security`)
//! * `file:relative/path`            — owner-only file under `<home>/secrets`
//!
//! Every resolved value is registered with the global [`redactor`] so it is
//! scrubbed from model output, logs and error text.

use std::path::{Path, PathBuf};
use std::sync::{OnceLock, RwLock};

use crate::sandbox::clean_command;

#[derive(Debug, thiserror::Error)]
pub enum SecretError {
    #[error("secret reference is empty")]
    Empty,
    #[error("unsupported secret reference scheme")]
    Scheme,
    #[error("secret {0} is not set")]
    Missing(String),
    #[error("secret backend failed: {0}")]
    Backend(String),
}

/// Values that must never leave the process.
pub struct Redactor {
    values: RwLock<Vec<String>>,
}

pub fn redactor() -> &'static Redactor {
    static R: OnceLock<Redactor> = OnceLock::new();
    R.get_or_init(|| Redactor {
        values: RwLock::new(Vec::new()),
    })
}

impl Redactor {
    pub fn register(&self, value: &str) {
        if value.len() < 6 {
            return; // too short to redact without mangling prose
        }
        let mut v = self.values.write().unwrap_or_else(|p| p.into_inner());
        if !v.iter().any(|x| x == value) {
            v.push(value.to_string());
            v.sort_by_key(|s| std::cmp::Reverse(s.len()));
        }
    }
    pub fn scrub(&self, text: &str) -> String {
        let v = self.values.read().unwrap_or_else(|p| p.into_inner());
        let mut out = text.to_string();
        for s in v.iter() {
            if out.contains(s.as_str()) {
                out = out.replace(s.as_str(), "[REDACTED]");
            }
        }
        out
    }
}

#[derive(Clone)]
pub struct SecretStore {
    secrets_dir: PathBuf,
    op_path: Option<PathBuf>,
}

/// Wrapper that never prints its contents.
#[derive(Clone)]
pub struct Secret(String);
impl Secret {
    pub fn expose(&self) -> &str {
        &self.0
    }
    /// Wrap a value the process obtained itself (OAuth access token, test
    /// fixture). Registers it with the redactor first.
    pub fn minted(value: String) -> Self {
        redactor().register(&value);
        Self(value)
    }
}
impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret([REDACTED])")
    }
}

const OP_CANDIDATES: &[&str] = &["/opt/homebrew/bin/op", "/usr/local/bin/op", "/usr/bin/op"];

pub fn find_op() -> Option<PathBuf> {
    OP_CANDIDATES
        .iter()
        .map(PathBuf::from)
        .find(|p| p.is_file())
}

impl SecretStore {
    pub fn new(secrets_dir: impl Into<PathBuf>) -> Self {
        Self {
            secrets_dir: secrets_dir.into(),
            op_path: find_op(),
        }
    }

    pub fn with_op_path(mut self, p: Option<PathBuf>) -> Self {
        if p.is_some() {
            self.op_path = p;
        }
        self
    }

    pub fn secrets_dir(&self) -> &Path {
        &self.secrets_dir
    }

    pub async fn resolve(&self, reference: &str) -> Result<Secret, SecretError> {
        let r = reference.trim();
        if r.is_empty() {
            return Err(SecretError::Empty);
        }
        let value = if let Some(name) = r.strip_prefix("env:") {
            std::env::var(name).map_err(|_| SecretError::Missing(name.into()))?
        } else if r.starts_with("op://") {
            let op = self
                .op_path
                .clone()
                .ok_or_else(|| SecretError::Backend("1Password CLI `op` not found".into()))?;
            let out = clean_command(
                &op,
                &[
                    "OP_SERVICE_ACCOUNT_TOKEN",
                    "OP_ACCOUNT",
                    "OP_CONNECT_HOST",
                    "OP_CONNECT_TOKEN",
                ],
            )
            .args(["read", "--no-newline", r])
            .output()
            .await
            .map_err(|e| SecretError::Backend(e.to_string()))?;
            if !out.status.success() {
                return Err(SecretError::Backend("op read failed".into()));
            }
            String::from_utf8(out.stdout).map_err(|_| SecretError::Backend("non-utf8".into()))?
        } else if let Some(rest) = r.strip_prefix("keychain:") {
            let (service, account) = rest.split_once('/').ok_or(SecretError::Scheme)?;
            let out = clean_command(Path::new("/usr/bin/security"), &[])
                .args(["find-generic-password", "-s", service, "-a", account, "-w"])
                .output()
                .await
                .map_err(|e| SecretError::Backend(e.to_string()))?;
            if !out.status.success() {
                return Err(SecretError::Missing(rest.into()));
            }
            String::from_utf8(out.stdout)
                .map_err(|_| SecretError::Backend("non-utf8".into()))?
                .trim_end()
                .to_string()
        } else if let Some(rel) = r.strip_prefix("file:") {
            let p = crate::paths::confined(&self.secrets_dir, rel).ok_or(SecretError::Scheme)?;
            std::fs::read_to_string(&p)
                .map_err(|_| SecretError::Missing(rel.into()))?
                .trim()
                .to_string()
        } else {
            return Err(SecretError::Scheme);
        };
        if value.is_empty() {
            return Err(SecretError::Missing(r.into()));
        }
        redactor().register(&value);
        Ok(Secret(value))
    }

    /// Store a secret the agent itself minted (e.g. an OAuth refresh token):
    /// macOS Keychain when available, else an owner-only file.
    pub async fn store(&self, name: &str, value: &str) -> Result<String, SecretError> {
        redactor().register(value);
        if cfg!(target_os = "macos") && Path::new("/usr/bin/security").is_file() {
            // `-w` on argv is visible to same-user `ps` for the call's lifetime;
            // acceptable under the single-operator model, documented in SECURITY.md.
            let st = clean_command(Path::new("/usr/bin/security"), &[])
                .args([
                    "add-generic-password",
                    "-U",
                    "-s",
                    "cg-agent",
                    "-a",
                    name,
                    "-w",
                    value,
                ])
                .status()
                .await
                .map_err(|e| SecretError::Backend(e.to_string()))?;
            if st.success() {
                return Ok(format!("keychain:cg-agent/{name}"));
            }
        }
        cg_audit::private_dir(&self.secrets_dir)
            .map_err(|e| SecretError::Backend(e.to_string()))?;
        let p = crate::paths::confined(&self.secrets_dir, name).ok_or(SecretError::Scheme)?;
        crate::fsutil::write_private(&p, value.as_bytes())
            .map_err(|e| SecretError::Backend(e.to_string()))?;
        Ok(format!("file:{name}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn env_and_file_refs_resolve_and_are_redacted() {
        let dir = tempfile::tempdir().expect("tmp");
        let store = SecretStore::new(dir.path());
        // cargo sets CARGO_MANIFEST_DIR for test processes at run time.
        let s = store.resolve("env:CARGO_MANIFEST_DIR").await.expect("env");
        assert!(!s.expose().is_empty());
        assert_eq!(format!("{s:?}"), "Secret([REDACTED])");
        std::fs::write(dir.path().join("tok"), "filetoken-abcdef\n").expect("w");
        assert_eq!(
            store.resolve("file:tok").await.expect("file").expose(),
            "filetoken-abcdef"
        );
        assert_eq!(redactor().scrub("x filetoken-abcdef y"), "x [REDACTED] y");
        assert!(store.resolve("file:../escape").await.is_err());
        assert!(store.resolve("plain-value").await.is_err());
        assert!(store.resolve("env:CG_DEFINITELY_UNSET_VAR").await.is_err());
    }
}
