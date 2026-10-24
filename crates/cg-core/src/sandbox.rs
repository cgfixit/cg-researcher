//! Child processes and the telemetry kill switch.
//!
//! Children (`op`, `security`, `arp`, `ip`) run by absolute path with a
//! cleared environment, so no inherited token, proxy or SDK telemetry flag
//! leaks in. The kill-switch variables are set on every child.

use std::path::Path;

use tokio::process::Command;

/// Opt-out variables honoured by common SDKs/CLIs. Harmless when unused.
pub const TELEMETRY_KILL: &[(&str, &str)] = &[
    ("DO_NOT_TRACK", "1"),
    ("HF_HUB_DISABLE_TELEMETRY", "1"),
    ("ANONYMIZED_TELEMETRY", "False"),
    ("OTEL_SDK_DISABLED", "true"),
    ("OTEL_TRACES_EXPORTER", "none"),
    ("OTEL_METRICS_EXPORTER", "none"),
    ("OTEL_LOGS_EXPORTER", "none"),
    ("SCARF_NO_ANALYTICS", "true"),
    ("OLLAMA_NOPRUNE", "1"),
    ("HOMEBREW_NO_ANALYTICS", "1"),
    ("DOTNET_CLI_TELEMETRY_OPTOUT", "1"),
    ("POWERSHELL_TELEMETRY_OPTOUT", "1"),
    ("AZURE_CORE_COLLECT_TELEMETRY", "0"),
    ("CHECKPOINT_DISABLE", "1"),
    ("SAM_CLI_TELEMETRY", "0"),
    ("STRIPE_CLI_TELEMETRY_OPTOUT", "1"),
    ("VCPKG_DISABLE_METRICS", "1"),
    ("NEXT_TELEMETRY_DISABLED", "1"),
    ("NUXT_TELEMETRY_DISABLED", "1"),
    ("GATSBY_TELEMETRY_DISABLED", "1"),
    ("ASTRO_TELEMETRY_DISABLED", "1"),
    ("TURBO_TELEMETRY_DISABLED", "1"),
];

pub const SAFE_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";

/// Inherited variables a child may keep (the process still cannot see
/// anything else: the env is cleared first).
pub const INHERITED: &[&str] = &["HOME", "USER", "LANG", "TMPDIR", "SystemRoot"];

/// The one definition of a child's environment: cleared, fixed `PATH`,
/// [`INHERITED`] plus `pass_through` copied from our own env, kill switches
/// set, stdin closed. Every spawn site uses this (or [`clean_command`]), so
/// the policy cannot drift between call sites (I2).
pub fn apply_clean_env(c: &mut std::process::Command, pass_through: &[&str]) {
    c.env_clear();
    c.env("PATH", SAFE_PATH);
    for k in INHERITED.iter().chain(pass_through) {
        if let Ok(v) = std::env::var(k) {
            c.env(k, v);
        }
    }
    for (k, v) in TELEMETRY_KILL {
        c.env(k, v);
    }
    c.stdin(std::process::Stdio::null());
}

/// A command with a cleared environment plus an explicit pass-through list.
pub fn clean_command(program: &Path, pass_through: &[&str]) -> Command {
    let mut c = Command::new(program);
    apply_clean_env(c.as_std_mut(), pass_through);
    c.kill_on_drop(true);
    c
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn child_env_is_cleared_and_killswitched() {
        let c = clean_command(Path::new("/bin/true"), &[]);
        let envs: std::collections::HashMap<_, _> = c
            .as_std()
            .get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.map(|v| v.to_string_lossy().into_owned()),
                )
            })
            .collect();
        assert_eq!(
            envs.get("PATH").cloned().flatten().as_deref(),
            Some(SAFE_PATH)
        );
        for (k, v) in TELEMETRY_KILL {
            assert_eq!(envs.get(*k).cloned().flatten().as_deref(), Some(*v), "{k}");
        }
        for leaked in [
            "SERPAPI_API_KEY",
            "XAI_API_KEY",
            "TWILIO_AUTH_TOKEN",
            "TELEGRAM_BOT_TOKEN",
        ] {
            assert!(
                !envs.contains_key(leaked),
                "{leaked} must not be passed through"
            );
        }
    }

    /// `get_envs()` only lists what we set explicitly, so the test above
    /// would still pass without `env_clear()`. Run a real child and read
    /// what it actually sees: nothing but the allowlist and the switches.
    #[test]
    fn a_real_child_sees_only_the_allowlist() {
        let env_bin = Path::new("/usr/bin/env");
        if !env_bin.is_file() {
            eprintln!("skip: /usr/bin/env missing");
            return;
        }
        let out = clean_command(env_bin, &["CG_TEST_PASS"])
            .as_std_mut()
            .output()
            .expect("spawn env");
        assert!(out.status.success());
        let allowed: Vec<&str> = ["PATH", "CG_TEST_PASS"]
            .into_iter()
            .chain(INHERITED.iter().copied())
            .chain(TELEMETRY_KILL.iter().map(|(k, _)| *k))
            .collect();
        let text = String::from_utf8_lossy(&out.stdout);
        let seen: Vec<&str> = text
            .lines()
            .filter_map(|l| l.split_once('=').map(|(k, _)| k))
            .collect();
        assert!(!seen.is_empty());
        for k in &seen {
            assert!(allowed.contains(k), "child inherited {k}");
        }
        // cargo always sets these in the test env; a cleared child never sees them.
        assert!(!seen.iter().any(|k| k.starts_with("CARGO")));
    }
}
