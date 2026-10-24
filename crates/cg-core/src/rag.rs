//! Hybrid retrieval: BM25 + cosine over local embeddings, fused with RRF
//! (k = 60) — the same shape as CyClaw's Chroma + BM25 + RRF, with SQLite as
//! the store. Embeddings come from the local model server; if it is down the
//! retriever degrades to BM25 alone and the score threshold scales with it.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use rusqlite::{Connection, params};

use crate::llm::OpenAiCompat;

pub const RRF_K: f64 = 60.0;

#[derive(Debug, Clone)]
pub struct Chunk {
    pub id: i64,
    pub source: String,
    pub text: String,
    pub embedding: Option<Vec<f32>>,
}

#[derive(Debug, Clone)]
pub struct Hit {
    pub source: String,
    pub text: String,
    pub rrf: f64,
    pub cosine: Option<f64>,
}

#[derive(Debug, Clone, Default)]
pub struct Retrieval {
    pub hits: Vec<Hit>,
    pub top_score: f64,
    pub top_cosine: Option<f64>,
    /// Number of ranked lists that contributed (1 = BM25 only).
    pub lists: usize,
}

pub fn tokenize(text: &str) -> Vec<String> {
    const STOP: &[&str] = &[
        "the", "a", "an", "and", "or", "of", "to", "in", "is", "it", "for", "on", "with", "as",
        "at", "by", "be", "this", "that", "what", "how", "my", "me", "i", "you", "are", "was",
        "do", "does",
    ];
    text.split(|c: char| !c.is_alphanumeric())
        .filter(|t| t.len() > 1)
        .map(|t| t.to_lowercase())
        .filter(|t| !STOP.contains(&t.as_str()))
        .collect()
}

pub fn chunk_text(text: &str, size: usize, overlap: usize) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut out = Vec::new();
    let mut start = 0;
    while start < chars.len() {
        let mut end = (start + size).min(chars.len());
        // Prefer to break on whitespace.
        if end < chars.len()
            && let Some(ws) = chars[start..end].iter().rposition(|c| c.is_whitespace())
            && ws > size / 2
        {
            end = start + ws;
        }
        let piece: String = chars[start..end].iter().collect();
        if !piece.trim().is_empty() {
            out.push(piece.trim().to_string());
        }
        if end == chars.len() {
            break;
        }
        start = end.saturating_sub(overlap).max(start + 1);
    }
    out
}

fn cosine(a: &[f32], b: &[f32]) -> f64 {
    if a.len() != b.len() || a.is_empty() {
        return 0.0;
    }
    let (mut dot, mut na, mut nb) = (0f64, 0f64, 0f64);
    for (x, y) in a.iter().zip(b) {
        dot += f64::from(*x) * f64::from(*y);
        na += f64::from(*x).powi(2);
        nb += f64::from(*y).powi(2);
    }
    if na == 0.0 || nb == 0.0 {
        0.0
    } else {
        dot / (na.sqrt() * nb.sqrt())
    }
}

fn bm25_rank(chunks: &[Chunk], query: &[String]) -> Vec<(usize, f64)> {
    let (k1, b) = (1.5, 0.75);
    let docs: Vec<Vec<String>> = chunks.iter().map(|c| tokenize(&c.text)).collect();
    let n = docs.len() as f64;
    let avg = docs.iter().map(Vec::len).sum::<usize>() as f64 / n.max(1.0);
    let mut df: HashMap<&str, f64> = HashMap::new();
    for d in &docs {
        let mut seen: Vec<&str> = d.iter().map(String::as_str).collect();
        seen.sort_unstable();
        seen.dedup();
        for t in seen {
            *df.entry(t).or_default() += 1.0;
        }
    }
    let mut scored: Vec<(usize, f64)> = docs
        .iter()
        .enumerate()
        .filter_map(|(i, d)| {
            let len = d.len() as f64;
            let mut s = 0.0;
            for q in query {
                let tf = d.iter().filter(|t| *t == q).count() as f64;
                if tf == 0.0 {
                    continue;
                }
                let dfq = df.get(q.as_str()).copied().unwrap_or(0.0);
                let idf = ((n - dfq + 0.5) / (dfq + 0.5) + 1.0).ln();
                s += idf * tf * (k1 + 1.0) / (tf + k1 * (1.0 - b + b * len / avg.max(1.0)));
            }
            (s > 0.0).then_some((i, s))
        })
        .collect();
    scored.sort_by(|a, b| b.1.total_cmp(&a.1));
    scored
}

/// Fuse ranked lists of chunk indices with reciprocal-rank fusion.
pub fn rrf(lists: &[Vec<usize>]) -> Vec<(usize, f64)> {
    let mut acc: HashMap<usize, f64> = HashMap::new();
    for list in lists {
        for (rank, idx) in list.iter().enumerate() {
            *acc.entry(*idx).or_default() += 1.0 / (RRF_K + rank as f64 + 1.0);
        }
    }
    let mut v: Vec<(usize, f64)> = acc.into_iter().collect();
    v.sort_by(|a, b| b.1.total_cmp(&a.1).then(a.0.cmp(&b.0)));
    v
}

pub struct Index {
    db: PathBuf,
}

impl Index {
    pub fn open(db: impl Into<PathBuf>) -> anyhow::Result<Self> {
        let db = db.into();
        if let Some(p) = db.parent() {
            cg_audit::private_dir(p)?;
        }
        let c = Connection::open(&db)?;
        c.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE IF NOT EXISTS chunks(
               id INTEGER PRIMARY KEY, source TEXT NOT NULL, ord INTEGER NOT NULL,
               text TEXT NOT NULL, embedding BLOB);
             CREATE TABLE IF NOT EXISTS meta(k TEXT PRIMARY KEY, v TEXT NOT NULL);",
        )?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(Self { db })
    }

    fn conn(&self) -> rusqlite::Result<Connection> {
        Connection::open(&self.db)
    }

    pub fn load(&self) -> anyhow::Result<Vec<Chunk>> {
        let c = self.conn()?;
        let mut st = c.prepare("SELECT id, source, text, embedding FROM chunks ORDER BY id")?;
        let rows = st.query_map([], |r| {
            let blob: Option<Vec<u8>> = r.get(3)?;
            Ok(Chunk {
                id: r.get(0)?,
                source: r.get(1)?,
                text: r.get(2)?,
                embedding: blob.map(|b| {
                    b.as_chunks::<4>()
                        .0
                        .iter()
                        .map(|x| f32::from_le_bytes(*x))
                        .collect()
                }),
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Rebuild the index from `corpus`. Returns (files, chunks, embedded).
    pub async fn rebuild(
        &self,
        corpus: &Path,
        llm: Option<&OpenAiCompat>,
        embed_model: &str,
        size: usize,
        overlap: usize,
        limits: &crate::config::AttachmentConfig,
    ) -> anyhow::Result<(usize, usize, usize)> {
        let mut files = Vec::new();
        collect_files(corpus, &mut files, 0)?;
        let mut pieces: Vec<(String, usize, String)> = Vec::new();
        for f in &files {
            let bytes = std::fs::read(f)?;
            let name = f
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();
            let Ok(att) = crate::attachments::parse(&name, &bytes, limits) else {
                continue;
            };
            let Some(text) = att.text else { continue };
            let rel = f
                .strip_prefix(corpus)
                .unwrap_or(f)
                .to_string_lossy()
                .into_owned();
            for (i, ch) in chunk_text(&text, size, overlap).into_iter().enumerate() {
                pieces.push((rel.clone(), i, ch));
            }
        }
        let mut embeddings: Vec<Option<Vec<f32>>> = vec![None; pieces.len()];
        let mut embedded = 0;
        if let Some(llm) = llm {
            for (bi, batch) in pieces.chunks(32).enumerate() {
                let inputs: Vec<String> = batch.iter().map(|p| p.2.clone()).collect();
                match llm.embed(embed_model, &inputs).await {
                    Ok(vs) => {
                        for (j, v) in vs.into_iter().enumerate() {
                            embeddings[bi * 32 + j] = Some(v);
                            embedded += 1;
                        }
                    }
                    Err(e) => {
                        tracing::warn!("embedding failed, index will be keyword-only: {e}");
                        break;
                    }
                }
            }
        }
        let mut c = self.conn()?;
        let tx = c.transaction()?;
        tx.execute("DELETE FROM chunks", [])?;
        for ((src, ord, text), emb) in pieces.iter().zip(&embeddings) {
            let blob: Option<Vec<u8>> = emb
                .as_ref()
                .map(|v| v.iter().flat_map(|x| x.to_le_bytes()).collect());
            tx.execute(
                "INSERT INTO chunks(source, ord, text, embedding) VALUES (?1, ?2, ?3, ?4)",
                params![src, *ord as i64, text, blob],
            )?;
        }
        tx.execute(
            "INSERT OR REPLACE INTO meta(k, v) VALUES ('embed_model', ?1)",
            params![embed_model],
        )?;
        tx.commit()?;
        Ok((files.len(), pieces.len(), embedded))
    }
}

fn collect_files(dir: &Path, out: &mut Vec<PathBuf>, depth: usize) -> std::io::Result<()> {
    if depth > 8 || !dir.is_dir() {
        return Ok(());
    }
    for e in std::fs::read_dir(dir)? {
        let e = e?;
        let ft = e.file_type()?;
        if ft.is_symlink() {
            continue; // never follow links out of the corpus
        }
        let p = e.path();
        if ft.is_dir() {
            collect_files(&p, out, depth + 1)?;
        } else if matches!(
            p.extension()
                .and_then(|s| s.to_str())
                .map(str::to_ascii_lowercase)
                .as_deref(),
            Some("md" | "markdown" | "txt" | "docx")
        ) {
            out.push(p);
        }
    }
    out.sort();
    Ok(())
}

/// In-memory retriever over a loaded index.
pub struct Retriever {
    chunks: Vec<Chunk>,
}

impl Retriever {
    pub fn new(chunks: Vec<Chunk>) -> Self {
        Self { chunks }
    }
    pub fn len(&self) -> usize {
        self.chunks.len()
    }
    pub fn is_empty(&self) -> bool {
        self.chunks.is_empty()
    }

    pub fn search(&self, query: &str, query_embedding: Option<&[f32]>, top_k: usize) -> Retrieval {
        if self.chunks.is_empty() {
            return Retrieval::default();
        }
        let q = tokenize(query);
        let bm: Vec<usize> = bm25_rank(&self.chunks, &q)
            .into_iter()
            .take(50)
            .map(|x| x.0)
            .collect();
        let mut lists = vec![bm];
        let mut cos_by_idx: HashMap<usize, f64> = HashMap::new();
        if let Some(qe) = query_embedding {
            let mut v: Vec<(usize, f64)> = self
                .chunks
                .iter()
                .enumerate()
                .filter_map(|(i, c)| c.embedding.as_ref().map(|e| (i, cosine(qe, e))))
                .collect();
            if !v.is_empty() {
                v.sort_by(|a, b| b.1.total_cmp(&a.1));
                for (i, s) in &v {
                    cos_by_idx.insert(*i, *s);
                }
                lists.push(v.into_iter().take(50).map(|x| x.0).collect());
            }
        }
        let n_lists = lists.len();
        let fused = rrf(&lists);
        let hits: Vec<Hit> = fused
            .into_iter()
            .take(top_k)
            .map(|(i, s)| Hit {
                source: self.chunks[i].source.clone(),
                text: self.chunks[i].text.clone(),
                rrf: s,
                cosine: cos_by_idx.get(&i).copied(),
            })
            .collect();
        Retrieval {
            top_score: hits.first().map_or(0.0, |h| h.rrf),
            top_cosine: hits.first().and_then(|h| h.cosine),
            lists: n_lists,
            hits,
        }
    }
}

/// CyClaw's score router: RRF ≥ threshold AND (no cosine OR cosine ≥ floor).
/// The RRF threshold assumes two lists; with one list it is halved so a
/// keyword-only index can still pass on a strong match.
pub fn is_confident(r: &Retrieval, min_score: f64, min_semantic: f64) -> bool {
    if r.hits.is_empty() {
        return false;
    }
    let threshold = min_score * (r.lists.max(1) as f64 / 2.0);
    r.top_score >= threshold && r.top_cosine.is_none_or(|c| c >= min_semantic)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ch(i: i64, t: &str, e: Option<Vec<f32>>) -> Chunk {
        Chunk {
            id: i,
            source: format!("d{i}.md"),
            text: t.into(),
            embedding: e,
        }
    }

    #[test]
    fn rrf_matches_formula() {
        let f = rrf(&[vec![0, 1], vec![0, 2]]);
        assert_eq!(f[0].0, 0);
        assert!((f[0].1 - 2.0 / 61.0).abs() < 1e-12);
    }

    #[test]
    fn hybrid_search_ranks_and_gates() {
        let r = Retriever::new(vec![
            ch(
                1,
                "veeam backup repository immutability hardened linux",
                Some(vec![1.0, 0.0]),
            ),
            ch(
                2,
                "pasta recipe with tomatoes and basil",
                Some(vec![0.0, 1.0]),
            ),
        ]);
        let hit = r.search("veeam immutability", Some(&[0.9, 0.1]), 3);
        assert_eq!(hit.hits[0].source, "d1.md");
        assert_eq!(hit.lists, 2);
        assert!(is_confident(&hit, 0.028, 0.30));
        let miss = r.search("veeam immutability", Some(&[0.0, 1.0]), 3);
        // cosine of the top fused hit is below the floor -> not confident
        assert!(!is_confident(&miss, 0.028, 0.99));
        let kw = r.search("veeam", None, 3);
        assert_eq!(kw.lists, 1);
        assert!(is_confident(&kw, 0.028, 0.30));
        assert!(!is_confident(&r.search("zzz", None, 3), 0.028, 0.30));
    }

    #[test]
    fn chunker_overlaps_and_terminates() {
        let t = "word ".repeat(500);
        let c = chunk_text(&t, 100, 20);
        assert!(c.len() > 20 && c.iter().all(|x| x.len() <= 100));
        assert_eq!(chunk_text("", 100, 20).len(), 0);
    }
}
