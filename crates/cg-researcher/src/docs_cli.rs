//! Docs may only name CLI commands that exist (issue #17: the user guide
//! documented a `config set` that was never implemented). The clap `Cli` in
//! `main.rs` is the single source of truth; this test walks every Markdown
//! file an operator or agent reads and fails on a command it does not know.
//! To document a new command, add it to `Cmd` first.

use clap::CommandFactory;
use std::path::{Path, PathBuf};

/// Bare backtick spans starting with one of these words are read as commands
/// even without a `cg-researcher` prefix (how #17 slipped in: "by `config set`").
const BARE_COMMAND_NOUNS: &[&str] = &["config"];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn doc_files() -> Vec<PathBuf> {
    let root = repo_root();
    let mut out = vec![
        root.join("README.md"),
        root.join("CLAUDE.md"),
        root.join("SECURITY.md"),
        root.join("INVARIANTS.md"),
    ];
    for dir in ["docs", ".claude"] {
        collect_md(&root.join(dir), &mut out);
    }
    out.retain(|p| p.is_file());
    out
}

fn collect_md(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            collect_md(&p, out);
        } else if p.extension().is_some_and(|x| x == "md") {
            out.push(p);
        }
    }
}

/// Command-like snippets: inline backtick spans, and lines inside ``` fences.
fn snippets(text: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut fenced = false;
    for (i, line) in text.lines().enumerate() {
        if line.trim_start().starts_with("```") {
            fenced = !fenced;
            continue;
        }
        if fenced {
            out.push((i + 1, line.to_string()));
            continue;
        }
        let mut parts = line.split('`');
        parts.next();
        while let Some(span) = parts.next() {
            out.push((i + 1, span.to_string()));
            parts.next();
        }
    }
    out
}

fn is_word(t: &str) -> bool {
    !t.is_empty() && t.chars().all(|c| c.is_ascii_lowercase() || c == '-') && !t.starts_with('-')
}

/// The command words a snippet invokes, or None if it is not a command.
fn command_words(snippet: &str, top: &clap::Command) -> Option<Vec<String>> {
    let toks: Vec<&str> = snippet.split_whitespace().collect();
    let start = toks
        .iter()
        .position(|t| *t == "cg-researcher" || t.ends_with("bin/cg-researcher"));
    let rest: Vec<&str> = match start {
        Some(s) => toks[s + 1..].to_vec(),
        None => {
            let first = *toks.first()?;
            let known_parent = top
                .find_subcommand(first)
                .is_some_and(|c| c.has_subcommands());
            if toks.len() >= 2 && (BARE_COMMAND_NOUNS.contains(&first) || known_parent) {
                toks
            } else {
                return None;
            }
        }
    };
    let mut words = Vec::new();
    let mut it = rest.into_iter();
    while let Some(t) = it.next() {
        if t == "--home" {
            it.next();
        } else if t.starts_with('-') {
            continue;
        } else if is_word(t) {
            words.push(t.to_string());
        } else {
            break;
        }
    }
    if words.is_empty() { None } else { Some(words) }
}

fn check(words: &[String], top: &clap::Command) -> Result<(), String> {
    let mut cmd = top;
    for w in words {
        if !cmd.has_subcommands() {
            return Ok(());
        }
        match cmd.find_subcommand(w) {
            Some(c) => cmd = c,
            None => {
                let known: Vec<_> = cmd.get_subcommands().map(|c| c.get_name()).collect();
                return Err(format!(
                    "`{w}` is not a subcommand of `{}` (known: {known:?})",
                    cmd.get_name()
                ));
            }
        }
    }
    Ok(())
}

fn violations(text: &str, top: &clap::Command) -> Vec<String> {
    snippets(text)
        .into_iter()
        .filter_map(|(line, s)| {
            let words = command_words(&s, top)?;
            check(&words, top)
                .err()
                .map(|e| format!("line {line}: `{}`: {e}", s.trim()))
        })
        .collect()
}

#[test]
fn docs_name_only_real_cli_commands() {
    let top = crate::Cli::command();
    let mut bad = Vec::new();
    for f in doc_files() {
        let text = std::fs::read_to_string(&f).unwrap_or_default();
        for v in violations(&text, &top) {
            bad.push(format!("{}: {v}", f.display()));
        }
    }
    assert!(
        bad.is_empty(),
        "docs name CLI commands that crates/cg-researcher/src/main.rs (`Cmd`) does not define; \
         add the command to `Cmd` or fix the doc:\n{}",
        bad.join("\n")
    );
}

#[test]
fn catches_issue_17_config_set() {
    let top = crate::Cli::command();
    let past = "A mismatch is refused at load, by `config set` and by the UI (HTTP 400),";
    assert_eq!(violations(past, &top).len(), 1);
    assert_eq!(violations("run `cg-researcher audit purge`", &top).len(), 1);
    assert!(violations("`cg-researcher --home \"$H\" audit verify`", &top).is_empty());
    assert!(violations("`cg-researcher ui --print`", &top).is_empty());
}
