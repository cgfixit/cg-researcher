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
];

pub const SAFE_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";

/// A command with a cleared environment plus an explicit pass-through list.
pub fn clean_command(program: &Path, pass_through: &[&str]) -> Command {
    let mut c = Command::new(program);
    c.env_clear();
    c.env("PATH", SAFE_PATH);
    for k in ["HOME", "USER", "LANG", "TMPDIR", "SystemRoot"] {
        if let Ok(v) = std::env::var(k) {
            c.env(k, v);
        }
    }
    for k in pass_through {
        if let Ok(v) = std::env::var(k) {
            c.env(k, v);
        }
    }
    for (k, v) in TELEMETRY_KILL {
        c.env(k, v);
    }
    c.stdin(std::process::Stdio::null());
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
}
