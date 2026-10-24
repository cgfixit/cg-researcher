//! Data-directory layout. Everything lives under one owner-only home.

use std::path::{Path, PathBuf};

pub fn default_home() -> PathBuf {
    if let Ok(h) = std::env::var("CG_HOME")
        && !h.is_empty()
    {
        return PathBuf::from(h);
    }
    let base = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .unwrap_or_else(|| ".".into());
    PathBuf::from(base).join(".cg-agent")
}

pub struct Layout {
    pub home: PathBuf,
}

impl Layout {
    pub fn new(home: impl Into<PathBuf>) -> Self {
        Self { home: home.into() }
    }
    pub fn config(&self) -> PathBuf {
        self.home.join("cg.toml")
    }
    pub fn secrets(&self) -> PathBuf {
        self.home.join("secrets")
    }
    pub fn audit_key(&self) -> PathBuf {
        self.secrets().join("audit.key")
    }
    pub fn api_key(&self) -> PathBuf {
        self.secrets().join("api.key")
    }
    pub fn logs(&self) -> PathBuf {
        self.home.join("logs")
    }
    pub fn audit_log(&self) -> PathBuf {
        self.logs().join("audit.pb")
    }
    pub fn index_db(&self) -> PathBuf {
        self.home.join("index").join("rag.sqlite3")
    }
    /// UI settings overlay (whitelisted keys only, owner-only file).
    pub fn settings(&self) -> PathBuf {
        self.home.join("ui-settings.toml")
    }
    pub fn state(&self) -> PathBuf {
        self.home.join("state")
    }
    /// Create every directory owner-only.
    pub fn ensure(&self) -> std::io::Result<()> {
        for d in [
            &self.home,
            &self.secrets(),
            &self.logs(),
            &self.home.join("index"),
            &self.state(),
            &self.home.join("corpus"),
        ] {
            cg_audit::private_dir(d)?;
        }
        Ok(())
    }
}

/// Resolve `rel` under `root`, refusing absolute paths and `..` escapes.
pub fn confined(root: &Path, rel: &str) -> Option<PathBuf> {
    let p = Path::new(rel);
    if p.is_absolute() {
        return None;
    }
    let mut out = root.to_path_buf();
    for c in p.components() {
        match c {
            std::path::Component::Normal(s) => out.push(s),
            std::path::Component::CurDir => {}
            _ => return None,
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn confined_refuses_escapes() {
        let r = Path::new("/tmp/home");
        assert!(confined(r, "../etc/passwd").is_none());
        assert!(confined(r, "/etc/passwd").is_none());
        assert_eq!(confined(r, "a/b").expect("ok"), Path::new("/tmp/home/a/b"));
    }
}
