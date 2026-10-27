//! Long-form research: an outer loop of ordinary turns.
//!
//! plan (one turn) → one turn per sub-question → synthesis (one turn).
//!
//! Every step is a normal `run_turn`, so the graph, both gates, taint and the
//! audit chain apply unchanged; nothing here widens what a single turn may do.
//! Steps run as `Origin::System` with a `DenyAll` confirmer and
//! `confirm_online = Some(false)`: writes are never auto-approved (only CLI
//! turns can be) and are declined, and no step leaves the machine through an
//! external model. Per-query consent (gate 3) is untouched.
//!
//! State is a job file under `state/research/<id>/` (owner-only, atomic
//! writes) saved after every step, so a killed or budget-stopped job resumes
//! where it stopped. Audit records carry ids and counts, never question text
//! (turn records already fingerprint the queries).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use cg_core::agent::{Agent, TurnRequest};
use cg_core::attachments;
use cg_core::tools::{DenyAll, Origin};
use serde::{Deserialize, Serialize};

pub const MAX_SUBQUESTIONS: usize = 12;
const MAX_SUBQUESTION_CHARS: usize = 300;
const PLAN_MARKER: &str = "Return only a JSON array of sub-questions";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Step {
    pub question: String,
    pub answer: String,
    pub model: String,
    pub sources: Vec<String>,
    pub tainted: bool,
    pub blocked: bool,
    pub secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Job {
    pub id: String,
    pub question: String,
    pub created: u64,
    pub max_subquestions: usize,
    /// None until the planning turn has run.
    pub plan: Option<Vec<String>>,
    pub steps: Vec<Step>,
    /// The synthesized answer; reset whenever new steps complete.
    pub report: Option<String>,
    pub report_tainted: bool,
}

impl Job {
    pub fn new(id: String, question: String, max_subquestions: usize) -> Self {
        Self {
            id,
            question,
            created: now(),
            max_subquestions: max_subquestions.clamp(1, MAX_SUBQUESTIONS),
            plan: None,
            steps: Vec::new(),
            report: None,
            report_tainted: false,
        }
    }

    pub fn remaining(&self) -> usize {
        self.plan
            .as_ref()
            .map_or(0, |p| p.len().saturating_sub(self.steps.len()))
    }
}

pub struct Opts {
    /// Wall-clock budget for this invocation; a resumed job gets a fresh one.
    pub budget: Duration,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Job ids are generated here; a resumed id must look like one, so it can
/// never name a path outside the research directory.
pub fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 40 && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

pub fn new_id() -> anyhow::Result<String> {
    let mut b = [0u8; 3];
    getrandom::fill(&mut b).map_err(|_| anyhow::anyhow!("random"))?;
    Ok(format!("r{}-{}", now(), hex::encode(b)))
}

pub fn job_dir(state: &Path, id: &str) -> PathBuf {
    state.join("research").join(id)
}

pub fn save(dir: &Path, job: &Job) -> anyhow::Result<()> {
    cg_core::fsutil::write_private(&dir.join("job.json"), &serde_json::to_vec_pretty(job)?)?;
    Ok(())
}

pub fn load(dir: &Path) -> anyhow::Result<Job> {
    let bytes = std::fs::read(dir.join("job.json"))
        .map_err(|e| anyhow::anyhow!("no research job at {}: {e}", dir.display()))?;
    Ok(serde_json::from_slice(&bytes)?)
}

pub fn plan_prompt(question: &str, n: usize) -> String {
    format!(
        "Break this research question into at most {n} focused sub-questions that can each be \
         answered from the local notes or a web search. {PLAN_MARKER}, no prose.\n\n\
         Research question: {question}"
    )
}

/// Parse the planner's answer strictly: the first JSON array of strings in
/// the text, trimmed, length-capped, de-duplicated. The model's output is
/// untrusted; each item is only ever used as the query of a further ordinary
/// turn, which `guardrail_input` scans like any other query.
pub fn parse_plan(answer: &str, max: usize) -> Option<Vec<String>> {
    // The first `[` that starts a JSON array of strings; whatever follows it
    // (a citation like "[1]", more prose) is ignored.
    let items: Vec<String> = answer.match_indices('[').find_map(|(i, _)| {
        serde_json::Deserializer::from_str(&answer[i..])
            .into_iter::<Vec<String>>()
            .next()?
            .ok()
    })?;
    let mut out: Vec<String> = Vec::new();
    for q in items {
        let q: String = q
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .chars()
            .take(MAX_SUBQUESTION_CHARS)
            .collect();
        if !q.is_empty() && !out.iter().any(|o| o.eq_ignore_ascii_case(&q)) {
            out.push(q);
        }
        if out.len() == max {
            break;
        }
    }
    (!out.is_empty()).then_some(out)
}

pub fn step_prompt(question: &str, sub: &str) -> String {
    format!("{sub}\n\n(This is one step of a larger research question: {question})")
}

/// The finished steps as one Markdown document, each answer capped so the
/// whole fits in one attachment.
pub fn notes(job: &Job, max_chars: usize) -> String {
    let per = (max_chars / job.steps.len().max(1))
        .saturating_sub(200)
        .max(200);
    let mut s = format!("# Research notes\n\nQuestion: {}\n", job.question);
    for (i, st) in job.steps.iter().enumerate() {
        let answer: String = st.answer.chars().take(per).collect();
        s.push_str(&format!("\n## {}. {}\n\n{answer}\n", i + 1, st.question));
        if !st.sources.is_empty() {
            s.push_str(&format!("\nSources: {}\n", st.sources.join(", ")));
        }
    }
    s
}

pub fn synth_prompt(question: &str) -> String {
    format!(
        "Using the attached research notes, write a complete answer to: {question}\n\
         Cite the sources named in the notes, and say what is still missing or uncertain."
    )
}

pub fn report_markdown(job: &Job) -> String {
    let mut s = format!("# {}\n\n", job.question);
    if job.report_tainted {
        s.push_str("_Built from protected context (corpus, attachments or tool output)._\n\n");
    }
    s.push_str(job.report.as_deref().unwrap_or("(not synthesized yet)"));
    s.push_str("\n\n---\n\n## Steps\n");
    for (i, st) in job.steps.iter().enumerate() {
        s.push_str(&format!(
            "\n### {}. {}\n\n{}\n\n_{}{}{} · {}s_\n",
            i + 1,
            st.question,
            st.answer,
            st.model,
            if st.tainted {
                " · protected context"
            } else {
                ""
            },
            if st.blocked {
                " · blocked by guardrail"
            } else {
                ""
            },
            st.secs
        ));
        if !st.sources.is_empty() {
            s.push_str(&format!("\nSources: {}\n", st.sources.join(", ")));
        }
    }
    s
}

/// The local model was unreachable or failed. Nothing from such a turn is
/// saved, so `--resume` retries it instead of keeping the error text.
fn failed(r: &cg_core::agent::TurnResult) -> bool {
    r.answer_model == "local-error"
}

fn request(query: String, attachments: Vec<attachments::Attachment>) -> TurnRequest {
    TurnRequest {
        query,
        origin: Origin::System,
        sender: "research".into(),
        attachments,
        confirm_online: Some(false),
        prefer_external: false,
        confirmer: Arc::new(DenyAll),
    }
}

/// Run (or resume) a job until it is synthesized or the budget runs out.
/// Returns true when the report covers every planned step.
pub async fn run(
    agent: &Agent,
    dir: &Path,
    job: &mut Job,
    opts: &Opts,
    event: &dyn Fn(&str, String),
) -> anyhow::Result<bool> {
    let deadline = Instant::now() + opts.budget;
    if job.plan.is_none() {
        eprintln!("[research {}] planning", job.id);
        let r = agent
            .run(request(
                plan_prompt(&job.question, job.max_subquestions),
                Vec::new(),
            ))
            .await;
        anyhow::ensure!(
            !failed(&r),
            "planning turn failed: {}; nothing saved, retry with `cg-researcher research --resume {}`",
            r.answer,
            job.id
        );
        let plan = parse_plan(&r.answer, job.max_subquestions).unwrap_or_else(|| {
            eprintln!(
                "[research {}] planner gave no usable list; researching the question directly",
                job.id
            );
            vec![job.question.clone()]
        });
        event(
            "research_plan",
            format!("job={} subquestions={}", job.id, plan.len()),
        );
        job.plan = Some(plan);
        save(dir, job)?;
    }
    let plan = job.plan.clone().unwrap_or_default();
    let mut ran = 0usize;
    while job.steps.len() < plan.len() {
        if Instant::now() >= deadline {
            event(
                "research_budget",
                format!("job={} done={} of={}", job.id, job.steps.len(), plan.len()),
            );
            eprintln!(
                "[research {}] time budget reached after {}/{} steps",
                job.id,
                job.steps.len(),
                plan.len()
            );
            break;
        }
        let i = job.steps.len();
        let sub = &plan[i];
        eprintln!("[research {}] step {}/{}: {sub}", job.id, i + 1, plan.len());
        let t = Instant::now();
        let r = agent
            .run(request(step_prompt(&job.question, sub), Vec::new()))
            .await;
        anyhow::ensure!(
            !failed(&r),
            "step {} failed: {}; {} step(s) saved, continue with `cg-researcher research --resume {}`",
            i + 1,
            r.answer,
            job.steps.len(),
            job.id
        );
        job.steps.push(Step {
            question: sub.clone(),
            answer: r.answer,
            model: r.answer_model,
            sources: r.sources,
            tainted: r.tainted,
            blocked: r.blocked,
            secs: t.elapsed().as_secs(),
        });
        job.report = None;
        save(dir, job)?;
        event(
            "research_step",
            format!(
                "job={} step={} of={} tainted={} blocked={}",
                job.id,
                i + 1,
                plan.len(),
                r.tainted,
                r.blocked
            ),
        );
        ran += 1;
    }
    let complete = job.steps.len() == plan.len();
    if job.report.is_none() && !job.steps.is_empty() {
        eprintln!("[research {}] synthesizing", job.id);
        let lim = &agent.config().attachments;
        // Size the notes to the model's context so every step keeps a fair
        // share, instead of the turn cutting the attachment's tail off.
        let room = agent.local_tuning().1.context_chars.min(lim.max_text_chars);
        let text = notes(job, room);
        let att = attachments::parse("research-notes.md", text.as_bytes(), lim)?;
        let r = agent
            .run(request(synth_prompt(&job.question), vec![att]))
            .await;
        anyhow::ensure!(
            !failed(&r),
            "synthesis failed: {}; steps are saved, retry with `cg-researcher research --resume {}`",
            r.answer,
            job.id
        );
        // A guardrail block is deterministic (retrying would block again), so
        // it is recorded as the outcome, with the steps still in the report.
        job.report = Some(if r.blocked {
            "(The synthesis turn was blocked by the input guardrail, usually because collected \
             text matched an injection pattern. The individual steps are below.)"
                .to_string()
        } else {
            r.answer
        });
        job.report_tainted = r.tainted;
        save(dir, job)?;
    }
    if job.report.is_some() {
        cg_core::fsutil::write_private(&dir.join("report.md"), report_markdown(job).as_bytes())?;
    }
    event(
        "research_done",
        format!(
            "job={} ran={ran} done={} of={} complete={complete}",
            job.id,
            job.steps.len(),
            plan.len()
        ),
    );
    Ok(complete)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_is_parsed_strictly_and_deduplicated() {
        let p = parse_plan(r#"Sure: ["A?", " a? ", "", "B  \n c?"] trailing"#, 6).expect("plan");
        assert_eq!(
            parse_plan(r#"Per [1]: ["X?", "Y?"] (see [2])"#, 6),
            Some(vec!["X?".to_string(), "Y?".to_string()])
        );
        assert_eq!(p, vec!["A?".to_string(), "B c?".to_string()]);
        assert_eq!(parse_plan(r#"["1","2","3"]"#, 2).map(|p| p.len()), Some(2));
        assert!(parse_plan("no list here", 6).is_none());
        assert!(parse_plan("[1, 2]", 6).is_none(), "non-strings are refused");
        assert!(parse_plan(r#"["", "  "]"#, 6).is_none());
        let long = format!(r#"["{}"]"#, "x".repeat(1000));
        assert_eq!(
            parse_plan(&long, 6).expect("plan")[0].len(),
            MAX_SUBQUESTION_CHARS
        );
    }

    #[test]
    fn resumed_ids_cannot_escape_the_research_dir() {
        assert!(valid_id(&new_id().expect("id")));
        for bad in ["", "../x", "a/b", "..", "a b", "x.json", &"a".repeat(41)] {
            assert!(!valid_id(bad), "{bad:?}");
        }
    }

    #[test]
    fn notes_fit_the_attachment_cap_and_jobs_round_trip() {
        let dir = tempfile::tempdir().expect("tmp");
        let mut job = Job::new("r1-abc".into(), "Q".into(), 99);
        assert_eq!(job.max_subquestions, MAX_SUBQUESTIONS);
        job.plan = Some(vec!["a".into(), "b".into()]);
        job.steps.push(Step {
            question: "a".into(),
            answer: "y".repeat(50_000),
            model: "local".into(),
            sources: vec!["n.md".into()],
            tainted: true,
            blocked: false,
            secs: 1,
        });
        assert_eq!(job.remaining(), 1);
        assert!(notes(&job, 10_000).chars().count() < 10_500);
        save(dir.path(), &job).expect("save");
        assert_eq!(load(dir.path()).expect("load"), job);
    }
}
