//! Atomic, owner-only file writes.

use std::io::Write;
use std::path::Path;

pub fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| std::io::Error::other("no parent"))?;
    cg_audit::private_dir(dir)?;
    let mut nonce = [0u8; 8];
    getrandom::fill(&mut nonce).map_err(|_| std::io::Error::other("random"))?;
    let tmp = dir.join(format!(".{}.tmp", hex::encode(nonce)));
    {
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        let mut f = o.open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}
