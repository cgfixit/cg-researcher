//! UI settings overlay: a small TOML file the web UI writes, deep-merged over
//! `cg.toml` at load. Only whitelisted keys may appear, so the UI can switch
//! models and tune rules but can never touch bind address, loopback rules,
//! write-tool approval, connectors or secrets paths it was not given.
//! Changes that loosen policy are reported by [`relaxations`] so the server
//! can demand an explicit acknowledgement and audit them.

use std::path::Path;

use crate::config::{Config, Mode};

/// Dotted keys the overlay may set. `external.rules.*` is a prefix.
pub const ALLOWED: &[&str] = &[
    "app.mode",
    "llm.model",
    "llm.vision_model",
    "llm.max_tokens",
    "llm.temperature",
    "external.enabled",
    "external.provider",
    "external.model",
    "external.xai_region",
    "external.anthropic_key_ref",
    "external.xai_key_ref",
    "external.rules.send_local_context",
    "external.rules.allow_telegram",
    "external.rules.allow_images",
    "external.rules.allow_attachment_text",
    "external.rules.max_calls_per_hour",
    "external.rules.max_calls_per_day",
    "external.rules.max_output_tokens",
    "external.rules.temperature",
    "external.rules.max_outbound_chars",
];

fn walk(prefix: &str, t: &toml::Table, out: &mut Vec<String>) {
    for (k, v) in t {
        let key = if prefix.is_empty() {
            k.clone()
        } else {
            format!("{prefix}.{k}")
        };
        match v {
            toml::Value::Table(sub) => walk(&key, sub, out),
            _ => out.push(key),
        }
    }
}

pub fn leaf_keys(t: &toml::Table) -> Vec<String> {
    let mut v = Vec::new();
    walk("", t, &mut v);
    v
}

pub fn check_overlay(t: &toml::Table) -> anyhow::Result<()> {
    for k in leaf_keys(t) {
        anyhow::ensure!(
            ALLOWED.contains(&k.as_str()),
            "settings overlay may not set `{k}`"
        );
    }
    // Key refs may only name that provider's own stored key (what the Keys
    // tab writes). Any other file or Keychain item would be sent to the
    // provider as its API key: `file:api.key` or `file:audit.key` would ship
    // a local secret off the machine.
    for (k, name) in [
        ("anthropic_key_ref", "anthropic_api_key"),
        ("xai_key_ref", "xai_api_key"),
    ] {
        if let Some(v) = t
            .get("external")
            .and_then(|e| e.get(k))
            .and_then(|v| v.as_str())
        {
            anyhow::ensure!(
                v == format!("keychain:cg-researcher/{name}") || v == format!("file:{name}"),
                "external.{k} from the UI must be keychain:cg-researcher/{name} or file:{name}"
            );
        }
    }
    Ok(())
}

/// Recursive merge: tables merge, everything else replaces.
pub fn merge(base: &mut toml::Table, over: &toml::Table) {
    for (k, v) in over {
        match (base.get_mut(k), v) {
            (Some(toml::Value::Table(b)), toml::Value::Table(o)) => merge(b, o),
            _ => {
                base.insert(k.clone(), v.clone());
            }
        }
    }
}

/// Human-readable list of policy loosenings from `old` to `new`.
pub fn relaxations(old: &Config, new: &Config) -> Vec<&'static str> {
    let mut r = Vec::new();
    let (o, n) = (&old.external, &new.external);
    if old.app.mode == Mode::Offline && new.app.mode == Mode::Hybrid {
        r.push("mode offline → hybrid");
    }
    if !o.enabled && n.enabled {
        r.push("external fallback enabled");
    }
    if o.provider != n.provider {
        r.push("external provider changed");
    }
    if !o.rules.send_local_context && n.rules.send_local_context {
        r.push("local corpus context may leave the machine");
    }
    if !o.rules.allow_telegram && n.rules.allow_telegram {
        r.push("Telegram may consent to external calls");
    }
    if !o.rules.allow_images && n.rules.allow_images {
        r.push("images may leave the machine");
    }
    if !o.rules.allow_attachment_text && n.rules.allow_attachment_text {
        r.push("attachment text may leave the machine");
    }
    if n.rules.max_calls_per_hour > o.rules.max_calls_per_hour
        || n.rules.max_calls_per_day > o.rules.max_calls_per_day
    {
        r.push("external call budget raised");
    }
    if n.rules.max_outbound_chars > o.rules.max_outbound_chars {
        r.push("outbound size cap raised");
    }
    r
}

/// Read the overlay (missing file = empty table).
pub fn read(path: &Path) -> anyhow::Result<toml::Table> {
    match std::fs::read_to_string(path) {
        Ok(s) => Ok(toml::from_str(&s)?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(toml::Table::new()),
        Err(e) => Err(e.into()),
    }
}

/// Atomically write the overlay, owner-only.
pub fn write(path: &Path, t: &toml::Table) -> anyhow::Result<()> {
    check_overlay(t)?;
    let text = format!(
        "# Written by the cg-researcher UI. Whitelisted keys only; merged over cg.toml.\n{}",
        toml::to_string(t)?
    );
    let tmp = path.with_extension("toml.tmp");
    crate::fsutil::write_private(&tmp, text.as_bytes())?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Set one dotted key in a table, creating intermediate tables.
pub fn set(t: &mut toml::Table, dotted: &str, v: toml::Value) -> anyhow::Result<()> {
    anyhow::ensure!(
        ALLOWED.contains(&dotted),
        "setting `{dotted}` is not allowed"
    );
    let parts: Vec<&str> = dotted.split('.').collect();
    let mut cur = t;
    for p in &parts[..parts.len() - 1] {
        let e = cur
            .entry((*p).to_string())
            .or_insert_with(|| toml::Value::Table(toml::Table::new()));
        cur = e
            .as_table_mut()
            .ok_or_else(|| anyhow::anyhow!("`{p}` is not a table"))?;
    }
    cur.insert(parts[parts.len() - 1].to_string(), v);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg_with(overlay: &str) -> anyhow::Result<Config> {
        let dir = tempfile::tempdir()?;
        let base = dir.path().join("cg.toml");
        std::fs::write(
            &base,
            "[llm]\nmodel = \"qwen3:8b\"\n[server]\nport = 8797\n",
        )?;
        let ov = dir.path().join("ui-settings.toml");
        std::fs::write(&ov, overlay)?;
        Config::load_with_overlay(&base, Some(&ov))
    }

    #[test]
    fn overlay_merges_whitelisted_keys() {
        let c = cfg_with(
            "[llm]\nmodel = \"llama3.2:3b\"\n[external]\nprovider = \"xai\"\n[external.rules]\nmax_calls_per_hour = 5\n",
        )
        .expect("ok");
        assert_eq!(c.llm.model, "llama3.2:3b");
        assert_eq!(c.server.port, 8797, "base keys survive");
        assert_eq!(c.external.provider, crate::external::Provider::Xai);
        assert_eq!(c.external.rules.max_calls_per_hour, 5);
        assert!(!c.external.rules.send_local_context);
    }

    #[test]
    fn overlay_cannot_touch_dangerous_keys() {
        for bad in [
            "[server]\nhost = \"0.0.0.0\"\n",
            "[llm]\nallow_non_loopback = true\n",
            "[llm]\nbase_url = \"https://evil.example/v1\"\n",
            "[tools]\nauto_approve_writes = true\n",
            "[connectors.telegram]\nenabled = true\n",
            "[external]\nanthropic_key_ref = \"env:HOME\"\n",
            "[external]\nanthropic_key_ref = \"file:api.key\"\n",
            "[external]\nxai_key_ref = \"file:audit.key\"\n",
            "[external]\nxai_key_ref = \"keychain:cg-researcher/anthropic_api_key\"\n",
            "[external]\ntls_roots = \"system\"\n",
            "[external.rules]\nsend_local_contxt = true\n",
        ] {
            assert!(cfg_with(bad).is_err(), "{bad}");
        }
        for good in [
            "[external]\nanthropic_key_ref = \"file:anthropic_api_key\"\n",
            "[external]\nxai_key_ref = \"keychain:cg-researcher/xai_api_key\"\n",
        ] {
            assert!(cfg_with(good).is_ok(), "{good}");
        }
        // Whitelisted key with an invalid value still fails validation.
        assert!(cfg_with("[external.rules]\ntemperature = 9.0\n").is_err());
        assert!(cfg_with("[llm]\nmodel = \"x; rm -rf /\"\n").is_err());
    }

    #[test]
    fn relaxations_are_detected() {
        let a = Config::default();
        let mut b = a.clone();
        assert!(relaxations(&a, &b).is_empty());
        b.app.mode = Mode::Hybrid;
        b.external.enabled = true;
        b.external.rules.send_local_context = true;
        b.external.rules.max_calls_per_day += 1;
        assert_eq!(relaxations(&a, &b).len(), 4);
        // Tightening is never a relaxation.
        let mut c = a.clone();
        c.external.rules.max_calls_per_hour = 1;
        assert!(relaxations(&a, &c).is_empty());
    }

    #[test]
    fn set_and_write_round_trip_owner_only() {
        let dir = tempfile::tempdir().expect("tmp");
        let p = dir.path().join("ui-settings.toml");
        let mut t = toml::Table::new();
        set(
            &mut t,
            "external.rules.allow_images",
            toml::Value::Boolean(true),
        )
        .expect("set");
        assert!(set(&mut t, "server.host", toml::Value::String("0.0.0.0".into())).is_err());
        write(&p, &t).expect("write");
        assert_eq!(read(&p).expect("read"), t);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&p).expect("m").permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }
}
