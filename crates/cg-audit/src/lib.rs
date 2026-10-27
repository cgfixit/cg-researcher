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
    #[error("audit record too large to store")]
    TooLarge,
    #[error("random source unavailable")]
    Random,
    #[error("audit log truncated: head says {expected} records, file has {found}")]
    Truncated { expected: u64, found: u64 },
    #[error("audit head anchor missing or invalid")]
    BadHead,
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
    fn head_tag(&self, count: u64, last: &[u8]) -> Vec<u8> {
        self.mac(b"HEAD", &head_body(count, last))
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
    cut_to(s, MAX_DETAIL_CHARS);
}

fn cut_to(s: &mut String, max: usize) {
    if s.chars().count() > max {
        *s = s.chars().take(max).collect();
    }
}

/// Tool decisions kept per record; one model round can request any number.
const MAX_TOOLS: usize = 32;
const MAX_PATH: usize = 128;
const MAX_NAME_CHARS: usize = 128;

/// Bound every field a model or caller can grow, so a record always fits in
/// one `MAX_FRAME` (`read_all` refuses larger frames, and a log it cannot
/// read is a log the app refuses to open). Worst case is about 150 KiB.
fn bound(rec: &mut AuditRecord) {
    for f in [
        &mut rec.event,
        &mut rec.answer_model,
        &mut rec.outcome,
        &mut rec.query_fingerprint,
        &mut rec.sender_fingerprint,
    ] {
        cut_to(f, MAX_NAME_CHARS);
    }
    rec.node_path.truncate(MAX_PATH);
    for n in &mut rec.node_path {
        cut_to(n, MAX_NAME_CHARS);
    }
    let omitted = rec.tools.len().saturating_sub(MAX_TOOLS);
    rec.tools.truncate(MAX_TOOLS);
    for t in &mut rec.tools {
        cut_to(&mut t.tool, MAX_NAME_CHARS);
        cut_to(&mut t.decision, MAX_NAME_CHARS);
        cut_to(&mut t.args_fingerprint, MAX_NAME_CHARS);
        cut(&mut t.reason);
    }
    if omitted > 0 {
        rec.detail = format!("[{omitted} tool decisions omitted] {}", rec.detail);
    }
    cut(&mut rec.detail);
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

fn head_body(count: u64, last: &[u8]) -> Vec<u8> {
    let mut body = b"cg-audit/head/v1".to_vec();
    body.extend_from_slice(&count.to_be_bytes());
    body.extend_from_slice(last);
    body
}

/// Path of the head anchor written next to the log (`audit.pb.head`).
pub fn head_path(log: &Path) -> PathBuf {
    let mut p = log.as_os_str().to_owned();
    p.push(".head");
    PathBuf::from(p)
}

fn write_head(log: &Path, keys: &Keys, count: u64, last: &[u8]) -> Result<(), AuditError> {
    let mut buf = Vec::with_capacity(8 + 1 + last.len() + 32);
    buf.extend_from_slice(&count.to_be_bytes());
    buf.push(u8::try_from(last.len()).map_err(|_| AuditError::BadHead)?);
    buf.extend_from_slice(last);
    buf.extend_from_slice(&keys.head_tag(count, last));
    let head = head_path(log);
    let tmp = head.with_extension("head.tmp");
    let mut f = private_open(&tmp, false)?;
    f.write_all(&buf)?;
    f.sync_all()?;
    fs::rename(&tmp, &head)?;
    Ok(())
}

fn read_head(log: &Path, keys: &Keys) -> Result<Option<(u64, Vec<u8>)>, AuditError> {
    let bytes = match fs::read(head_path(log)) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    if bytes.len() < 9 {
        return Err(AuditError::BadHead);
    }
    let count = u64::from_be_bytes(bytes[..8].try_into().map_err(|_| AuditError::BadHead)?);
    let n = usize::from(bytes[8]);
    let rest = &bytes[9..];
    if rest.len() != n + 32 {
        return Err(AuditError::BadHead);
    }
    let (last, tag) = rest.split_at(n);
    if !keys.check(b"HEAD", &head_body(count, last), tag) {
        return Err(AuditError::BadHead);
    }
    Ok(Some((count, last.to_vec())))
}

/// [`verify`] plus the signed head anchor, which catches whole-record tail
/// truncation. The head may lag the log by at most one record (crash between
/// the log fsync and the head rename), never lead it.
///
/// Limit: a same-user attacker who can read the audit key can forge a head
/// for a truncated log. Detecting that needs an off-host anchor.
pub fn verify_full(path: &Path, keys: &Keys) -> Result<u64, AuditError> {
    let n = verify(path, keys)?;
    let records = read_all(path)?;
    match read_head(path, keys)? {
        None if n == 0 => Ok(0),
        None => Err(AuditError::BadHead),
        Some((count, last)) => {
            if count > n {
                return Err(AuditError::Truncated {
                    expected: count,
                    found: n,
                });
            }
            if n - count > 1 {
                return Err(AuditError::BadHead);
            }
            let expect_last = if count == 0 {
                Vec::new()
            } else {
                usize::try_from(count - 1)
                    .ok()
                    .and_then(|i| records.get(i))
                    .map(|r| r.mac.clone())
                    .ok_or(AuditError::BadHead)?
            };
            if expect_last != last {
                return Err(AuditError::BadHead);
            }
            Ok(n)
        }
    }
}

pub struct AuditLog {
    path: PathBuf,
    keys: Keys,
    /// (next seq, last mac, log length we last saw). The length lets us
    /// notice another process's appends cheaply.
    state: Mutex<(u64, Vec<u8>, u64)>,
}

fn lock_path(log: &Path) -> PathBuf {
    let mut p = log.as_os_str().to_owned();
    p.push(".lock");
    PathBuf::from(p)
}

fn file_len(path: &Path) -> Result<u64, AuditError> {
    match fs::metadata(path) {
        Ok(m) => Ok(m.len()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(e) => Err(e.into()),
    }
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
        let lock = private_open(&lock_path(&path), true)?;
        lock.lock()?;
        let records = read_all(&path)?;
        verify_full(&path, &keys)?;
        let (seq, prev) = records
            .last()
            .map_or((0, Vec::new()), |r| (r.seq + 1, r.mac.clone()));
        drop(private_open(&path, true)?);
        let len = file_len(&path)?;
        drop(lock);
        Ok(Self {
            path,
            keys,
            state: Mutex::new((seq, prev, len)),
        })
    }

    /// [`verify_full`] under the cross-process lock, so a concurrent append
    /// in another process can't show up as a torn frame.
    pub fn verify_now(&self) -> Result<u64, AuditError> {
        let _g = self.state.lock().unwrap_or_else(|p| p.into_inner());
        let lock = private_open(&lock_path(&self.path), true)?;
        lock.lock()?;
        verify_full(&self.path, &self.keys)
    }

    pub fn keys(&self) -> &Keys {
        &self.keys
    }
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append one record. `seq`, `ts`, `prev_mac` and `mac` are filled here.
    pub fn append(&self, mut rec: AuditRecord) -> Result<u64, AuditError> {
        bound(&mut rec);
        // prev_mac + mac add 2 x 32 bytes after this check.
        if rec.encoded_len() + 128 > MAX_FRAME {
            return Err(AuditError::TooLarge);
        }
        let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
        // Cross-process exclusion: `serve`, `chat` and the scheduled
        // `maintain` job may all append. Without this each process would
        // chain from its own stale tail and fork the log.
        let lock = private_open(&lock_path(&self.path), true)?;
        lock.lock()?;
        let len = file_len(&self.path)?;
        if len != st.2 {
            // Someone else appended: re-verify and continue from the real tail
            // (never append past tampering).
            verify_full(&self.path, &self.keys)?;
            let records = read_all(&self.path)?;
            let (seq, prev) = records
                .last()
                .map_or((0, Vec::new()), |r| (r.seq + 1, r.mac.clone()));
            *st = (seq, prev, len);
        }
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
        write_head(&self.path, &self.keys, st.0 + 1, &tag)?;
        let seq = st.0;
        *st = (seq + 1, tag, len + frame.len() as u64);
        drop(lock); // releases the advisory lock
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
    fn oversized_fields_are_bounded_and_the_log_stays_readable() {
        let dir = tempfile::tempdir().expect("tmp");
        let p = dir.path().join("audit.pb");
        let key = [3u8; 32];
        let log = AuditLog::open(&p, &key).expect("open");
        // Unbounded, this record would encode to ~80 MB, far over MAX_FRAME.
        let huge = "\u{1F600}".repeat(5_000);
        let mut r = rec(&huge);
        r.answer_model = huge.clone();
        r.outcome = huge.clone();
        r.detail = huge.clone();
        r.node_path = vec![huge.clone(); 500];
        r.tools = (0..1_000)
            .map(|_| ToolDecision {
                tool: huge.clone(),
                decision: huge.clone(),
                reason: huge.clone(),
                args_fingerprint: huge.clone(),
                duration_ms: 1,
            })
            .collect();
        log.append(r).expect("bounded record appends");
        log.append(rec("after")).expect("chain continues");
        let all = read_all(&p).expect("log still reads");
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].tools.len(), MAX_TOOLS);
        assert!(all[0].detail.starts_with("[968 tool decisions omitted]"));
        assert_eq!(verify(&p, &Keys::from_master(&key)).expect("verify"), 2);
        AuditLog::open(&p, &key).expect("reopens");
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
    fn whole_record_tail_truncation_is_detected_by_head() {
        let dir = tempfile::tempdir().expect("tmp");
        let p = dir.path().join("audit.pb");
        let key = [3u8; 32];
        let keys = Keys::from_master(&key);
        let log = AuditLog::open(&p, &key).expect("open");
        for i in 0..3 {
            log.append(rec(&format!("r{i}"))).expect("append");
        }
        assert_eq!(verify_full(&p, &keys).expect("ok"), 3);
        // Drop the last whole frame: the chain alone still verifies...
        let recs = read_all(&p).expect("read");
        let keep: Vec<u8> = recs[..2]
            .iter()
            .flat_map(|r| r.encode_length_delimited_to_vec())
            .collect();
        fs::write(&p, keep).expect("w");
        assert_eq!(verify(&p, &keys).expect("chain ok"), 2);
        // ...but the head anchor does not, and open refuses.
        assert!(matches!(
            verify_full(&p, &keys),
            Err(AuditError::Truncated {
                expected: 3,
                found: 2
            })
        ));
        assert!(AuditLog::open(&p, &key).is_err());
        // A deleted or forged-without-key head is refused too.
        fs::remove_file(head_path(&p)).expect("rm");
        assert!(matches!(verify_full(&p, &keys), Err(AuditError::BadHead)));
        fs::write(head_path(&p), [0u8; 73]).expect("w");
        assert!(matches!(verify_full(&p, &keys), Err(AuditError::BadHead)));
    }

    #[test]
    fn head_may_lag_by_one_record_after_a_crash() {
        let dir = tempfile::tempdir().expect("tmp");
        let p = dir.path().join("audit.pb");
        let key = [4u8; 32];
        let keys = Keys::from_master(&key);
        let log = AuditLog::open(&p, &key).expect("open");
        log.append(rec("a")).expect("a");
        let head_after_one = fs::read(head_path(&p)).expect("h");
        log.append(rec("b")).expect("b");
        fs::write(head_path(&p), &head_after_one).expect("w");
        assert_eq!(verify_full(&p, &keys).expect("lag of one is ok"), 2);
        log.append(rec("c")).expect("c");
        fs::write(head_path(&p), &head_after_one).expect("w");
        assert!(verify_full(&p, &keys).is_err(), "lag of two is not");
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

    #[test]
    fn two_writers_on_one_log_keep_a_single_chain() {
        // Models `serve` + `chat` (or the launchd maintenance job) appending
        // concurrently from separate handles.
        let dir = tempfile::tempdir().expect("tmp");
        let p = dir.path().join("audit.pb");
        let key = [5u8; 32];
        let a = AuditLog::open(&p, &key).expect("a");
        let b = AuditLog::open(&p, &key).expect("b");
        a.append(rec("a0")).expect("a0");
        b.append(rec("b0")).expect("b0");
        a.append(rec("a1")).expect("a1");
        let ts: Vec<_> = (0..4)
            .map(|i| {
                let p = p.clone();
                std::thread::spawn(move || {
                    let l = AuditLog::open(&p, &key).expect("open");
                    for j in 0..5 {
                        l.append(rec(&format!("t{i}-{j}"))).expect("append");
                    }
                })
            })
            .collect();
        for t in ts {
            t.join().expect("join");
        }
        assert_eq!(
            verify_full(&p, &Keys::from_master(&key)).expect("verify"),
            23
        );
    }
}
