//! Tamper-evident audit log: protobuf frames, HMAC-chained, owner-only files.
//!
//! * Format: `proto/cg_audit.proto`, length-delimited (`prost`).
//! * Integrity: each record's MAC covers the previous MAC, so edits, deletions
//!   and reordering are detected by [`verify`].
//! * Privacy: queries, senders and tool arguments are stored only as keyed
//!   HMAC fingerprints (CyClaw rule 7). There is no unkeyed fallback.
//! * Files are created `0600` in a `0700` directory on Unix.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, KeyInit, Mac};
use prost::Message;
use sha2::Sha256;

pub mod pb {
    include!(concat!(env!("OUT_DIR"), "/cg.audit.v1.rs"));
}
pub use pb::{AuditRecord, Origin, ToolDecision};

type HmacSha256 = Hmac<Sha256>;

/// Largest frame accepted on read; anything bigger is corruption.
const MAX_FRAME: usize = 256 * 1024;
/// Free-text fields are cut to this many characters before writing.
pub const MAX_DETAIL_CHARS: usize = 512;

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("audit io: {0}")]
    Io(#[from] std::io::Error),
    #[error("audit key must be 32 bytes")]
    BadKey,
    #[error("audit chain broken at record {0}")]
    Tampered(u64),
    #[error("audit frame is corrupt")]
    Corrupt,
    #[error("random source unavailable")]
    Random,
}

/// Owner-only directory create.
pub fn private_dir(path: &Path) -> std::io::Result<()> {
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn private_open(path: &Path, append: bool) -> std::io::Result<File> {
    let mut o = OpenOptions::new();
    o.create(true);
    if append {
        o.append(true);
    } else {
        o.write(true).truncate(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let f = o.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(f)
}

/// Load a 32-byte key, creating it with the OS CSPRNG on first use.
pub fn load_or_create_key(path: &Path) -> Result<[u8; 32], AuditError> {
    if path.exists() {
        let mut buf = Vec::new();
        File::open(path)?.read_to_end(&mut buf)?;
        return buf.try_into().map_err(|_| AuditError::BadKey);
    }
    if let Some(parent) = path.parent() {
        private_dir(parent)?;
    }
    let mut key = [0u8; 32];
    getrandom::fill(&mut key).map_err(|_| AuditError::Random)?;
    let mut f = private_open(path, false)?;
    f.write_all(&key)?;
    f.sync_all()?;
    Ok(key)
}

/// Keys derived from the master so the fingerprint key never equals the MAC key.
#[derive(Clone)]
pub struct Keys {
    mac: [u8; 32],
    fingerprint: [u8; 32],
}

fn derive(master: &[u8; 32], label: &[u8]) -> [u8; 32] {
    let mut m = HmacSha256::new_from_slice(master).expect("hmac accepts any key length");
    m.update(label);
    m.finalize().into_bytes().into()
}

impl Keys {
    pub fn from_master(master: &[u8; 32]) -> Self {
        Self {
            mac: derive(master, b"cg-audit/mac/v1"),
            fingerprint: derive(master, b"cg-audit/fp/v1"),
        }
    }
    /// Keyed fingerprint of sensitive text (first 16 bytes, hex).
    pub fn fingerprint(&self, text: &str) -> String {
        if text.is_empty() {
            return String::new();
        }
        let mut m = HmacSha256::new_from_slice(&self.fingerprint).expect("hmac key");
        m.update(text.as_bytes());
        hex::encode(&m.finalize().into_bytes()[..16])
    }
    fn mac(&self, prev: &[u8], body: &[u8]) -> Vec<u8> {
        let mut m = HmacSha256::new_from_slice(&self.mac).expect("hmac key");
        m.update(&(prev.len() as u32).to_be_bytes());
        m.update(prev);
        m.update(body);
        m.finalize().into_bytes().to_vec()
    }
    fn check(&self, prev: &[u8], body: &[u8], tag: &[u8]) -> bool {
        let mut m = HmacSha256::new_from_slice(&self.mac).expect("hmac key");
        m.update(&(prev.len() as u32).to_be_bytes());
        m.update(prev);
        m.update(body);
        m.verify_slice(tag).is_ok()
    }
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn cut(s: &mut String) {
    if s.chars().count() > MAX_DETAIL_CHARS {
        *s = s.chars().take(MAX_DETAIL_CHARS).collect();
    }
}

/// Decode every frame in a file. Errors on a truncated or oversized frame.
pub fn read_all(path: &Path) -> Result<Vec<AuditRecord>, AuditError> {
    let mut bytes = Vec::new();
    match File::open(path) {
        Ok(mut f) => {
            f.read_to_end(&mut bytes)?;
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    }
    let mut buf = bytes.as_slice();
    let mut out = Vec::new();
    while !buf.is_empty() {
        let len =
            prost::encoding::decode_varint(&mut buf).map_err(|_| AuditError::Corrupt)? as usize;
        if len > MAX_FRAME || len > buf.len() {
            return Err(AuditError::Corrupt);
        }
        let (frame, rest) = buf.split_at(len);
        out.push(AuditRecord::decode(frame).map_err(|_| AuditError::Corrupt)?);
        buf = rest;
    }
    Ok(out)
}

/// Verify the whole chain. Returns the number of records.
pub fn verify(path: &Path, keys: &Keys) -> Result<u64, AuditError> {
    let mut prev: Vec<u8> = Vec::new();
    let mut n = 0u64;
    for (i, rec) in read_all(path)?.into_iter().enumerate() {
        let i = i as u64;
        if rec.seq != i || rec.prev_mac != prev {
            return Err(AuditError::Tampered(i));
        }
        let tag = rec.mac.clone();
        let mut body = rec;
        body.mac.clear();
        if !keys.check(&prev, &body.encode_to_vec(), &tag) {
            return Err(AuditError::Tampered(i));
        }
        prev = tag;
        n += 1;
    }
    Ok(n)
}

pub struct AuditLog {
    path: PathBuf,
    keys: Keys,
    state: Mutex<(u64, Vec<u8>)>,
}

impl AuditLog {
    /// Open (and verify) the log. A broken chain refuses to open: fix or
    /// rotate the file deliberately, never append past tampering.
    pub fn open(path: impl Into<PathBuf>, master: &[u8; 32]) -> Result<Self, AuditError> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            private_dir(parent)?;
        }
        let keys = Keys::from_master(master);
        let records = read_all(&path)?;
        verify(&path, &keys)?;
        let (seq, prev) = records
            .last()
            .map_or((0, Vec::new()), |r| (r.seq + 1, r.mac.clone()));
        drop(private_open(&path, true)?);
        Ok(Self {
            path,
            keys,
            state: Mutex::new((seq, prev)),
        })
    }

    pub fn keys(&self) -> &Keys {
        &self.keys
    }
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append one record. `seq`, `ts`, `prev_mac` and `mac` are filled here.
    pub fn append(&self, mut rec: AuditRecord) -> Result<u64, AuditError> {
        cut(&mut rec.detail);
        cut(&mut rec.outcome);
        for t in &mut rec.tools {
            cut(&mut t.reason);
        }
        let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        rec.seq = st.0;
        if rec.ts_unix_ms == 0 {
            rec.ts_unix_ms = now_ms();
        }
        rec.prev_mac = st.1.clone();
        rec.mac.clear();
        let tag = self.keys.mac(&st.1, &rec.encode_to_vec());
        rec.mac = tag.clone();
        let frame = rec.encode_length_delimited_to_vec();
        let mut f = private_open(&self.path, true)?;
        f.write_all(&frame)?;
        f.sync_data()?;
        let seq = st.0;
        *st = (seq + 1, tag);
        Ok(seq)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(event: &str) -> AuditRecord {
        AuditRecord {
            event: event.into(),
            ..Default::default()
        }
    }

    #[test]
    fn chain_round_trips_and_verifies() {
        let dir = tempfile::tempdir().expect("tmp");
        let p = dir.path().join("a/audit.pb");
        let key = [7u8; 32];
        let log = AuditLog::open(&p, &key).expect("open");
        for i in 0..5 {
            log.append(rec(&format!("e{i}"))).expect("append");
        }
        assert_eq!(verify(&p, &Keys::from_master(&key)).expect("verify"), 5);
        // Reopen continues the chain.
        let log = AuditLog::open(&p, &key).expect("reopen");
        assert_eq!(log.append(rec("e5")).expect("append"), 5);
        assert_eq!(verify(&p, &Keys::from_master(&key)).expect("verify"), 6);
    }

    #[test]
    fn edit_and_truncation_are_detected() {
        let dir = tempfile::tempdir().expect("tmp");
        let p = dir.path().join("audit.pb");
        let key = [9u8; 32];
        let log = AuditLog::open(&p, &key).expect("open");
        log.append(rec("aaaa")).expect("a");
        log.append(rec("bbbb")).expect("b");
        let mut bytes = fs::read(&p).expect("read");
        let pos = bytes.windows(4).position(|w| w == b"aaaa").expect("find");
        bytes[pos] = b'z';
        fs::write(&p, &bytes).expect("write");
        assert!(matches!(
            verify(&p, &Keys::from_master(&key)),
            Err(AuditError::Tampered(0))
        ));
        assert!(AuditLog::open(&p, &key).is_err());
        // Wrong key fails too.
        let p2 = dir.path().join("b.pb");
        AuditLog::open(&p2, &key)
            .expect("o")
            .append(rec("x"))
            .expect("x");
        assert!(verify(&p2, &Keys::from_master(&[1u8; 32])).is_err());
    }

    #[test]
    fn fingerprints_are_keyed_and_stable() {
        let a = Keys::from_master(&[1u8; 32]);
        let b = Keys::from_master(&[2u8; 32]);
        assert_eq!(a.fingerprint("hello"), a.fingerprint("hello"));
        assert_ne!(a.fingerprint("hello"), b.fingerprint("hello"));
        assert_eq!(a.fingerprint(""), "");
    }

    #[cfg(unix)]
    #[test]
    fn files_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tmp");
        let p = dir.path().join("logs/audit.pb");
        AuditLog::open(&p, &[3u8; 32])
            .expect("open")
            .append(rec("x"))
            .expect("x");
        assert_eq!(
            fs::metadata(&p).expect("m").permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(p.parent().expect("p"))
                .expect("m")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        let k = dir.path().join("keys/k");
        load_or_create_key(&k).expect("key");
        assert_eq!(
            fs::metadata(&k).expect("m").permissions().mode() & 0o777,
            0o600
        );
    }
}
