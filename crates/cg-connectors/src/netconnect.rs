//! netconnect: local-network neighbour discovery from the OS ARP/neighbour
//! cache. No packets are sent; the tool only reads what the OS already knows.
//! Fixed absolute binary paths, cleared environment, IPv4 only, and results
//! are filtered to operator-allowlisted private CIDRs.

use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use cg_core::sandbox::clean_command;
use cg_core::tools::{Effect, Tool, ToolError, ToolSpec};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{Ctx, Parts};

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct NetConfig {
    pub enabled: bool,
    pub allowed_cidrs: Vec<String>,
    /// Also expose `net_connections` (macOS): a numeric snapshot from the
    /// bundled CyClaw-Net-Viewer `netboard --cli -n -a` at ~/.cg-researcher/bin/netboard.
    pub include_connections: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cidr {
    net: u32,
    prefix: u8,
}

impl Cidr {
    pub fn parse(s: &str) -> Result<Self, String> {
        let (ip, p) = s
            .trim()
            .split_once('/')
            .ok_or_else(|| format!("{s}: expected a.b.c.d/n"))?;
        let ip: Ipv4Addr = ip.parse().map_err(|_| format!("{s}: IPv4 only"))?;
        let prefix: u8 = p.parse().map_err(|_| format!("{s}: bad prefix"))?;
        if prefix > 32 {
            return Err(format!("{s}: bad prefix"));
        }
        let c = Self {
            net: u32::from(ip) & mask(prefix),
            prefix,
        };
        const PRIVATE: &[(u32, u8)] = &[
            (0x0A00_0000, 8),
            (0xAC10_0000, 12),
            (0xC0A8_0000, 16),
            (0x7F00_0000, 8),
        ];
        if !PRIVATE
            .iter()
            .any(|&(n, p)| prefix >= p && (c.net & mask(p)) == n)
        {
            return Err(format!(
                "{s}: must sit inside 10/8, 172.16/12, 192.168/16 or 127/8"
            ));
        }
        if prefix < 16 {
            return Err(format!("{s}: prefix must be /16 or narrower"));
        }
        Ok(c)
    }
    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        (u32::from(ip) & mask(self.prefix)) == self.net
    }
}

fn mask(p: u8) -> u32 {
    if p == 0 { 0 } else { u32::MAX << (32 - p) }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Neighbor {
    pub ip: Ipv4Addr,
    pub mac: String,
}

/// Normalise `a:b:c:d:e:f` / `aa-bb-..` to lowercase colon form; reject
/// broadcast, all-zero and IPv4 multicast MACs.
pub fn normalize_mac(raw: &str) -> Option<String> {
    let parts: Vec<&str> = raw.split([':', '-']).collect();
    if parts.len() != 6 {
        return None;
    }
    let mut bytes = [0u8; 6];
    for (i, p) in parts.iter().enumerate() {
        if p.is_empty() || p.len() > 2 {
            return None;
        }
        bytes[i] = u8::from_str_radix(p, 16).ok()?;
    }
    if bytes == [0xff; 6]
        || bytes == [0; 6]
        || (bytes[0] == 0x01 && bytes[1] == 0x00 && bytes[2] == 0x5e)
    {
        return None;
    }
    Some(
        bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(":"),
    )
}

/// Parse macOS `arp -an`, Linux `ip neigh show`, or Windows `arp -a` output.
pub fn parse_neighbors(text: &str) -> Vec<Neighbor> {
    let mut out = Vec::new();
    for line in text.lines().take(4096) {
        let mut ip = None;
        let mut mac = None;
        for tok in line.split_whitespace() {
            let t = tok.trim_matches(|c| c == '(' || c == ')');
            if ip.is_none()
                && let Ok(a) = t.parse::<Ipv4Addr>()
            {
                ip = Some(a);
            } else if mac.is_none()
                && let Some(m) = normalize_mac(t)
            {
                mac = Some(m);
            }
        }
        if let (Some(ip), Some(mac)) = (ip, mac)
            && !out.iter().any(|n: &Neighbor| n.ip == ip)
        {
            out.push(Neighbor { ip, mac });
        }
    }
    out.sort_by_key(|n| n.ip);
    out
}

fn neighbor_command() -> Option<(&'static str, &'static [&'static str])> {
    let cands: &[(&str, &[&str])] = if cfg!(target_os = "macos") {
        &[("/usr/sbin/arp", &["-an"])]
    } else if cfg!(target_os = "windows") {
        &[("C:\\Windows\\System32\\ARP.EXE", &["-a"])]
    } else {
        &[
            ("/usr/sbin/ip", &["neigh", "show"]),
            ("/sbin/ip", &["neigh", "show"]),
            ("/usr/bin/ip", &["neigh", "show"]),
        ]
    };
    cands.iter().copied().find(|(p, _)| Path::new(p).is_file())
}

pub struct NetNeighbors {
    cidrs: Vec<Cidr>,
}

pub async fn build(ctx: &Ctx<'_>) -> anyhow::Result<Parts> {
    let c: NetConfig = crate::common::section(ctx.connectors, "netconnect")?;
    if !c.enabled {
        return Ok(Parts::default());
    }
    if c.allowed_cidrs.is_empty() {
        anyhow::bail!("netconnect is enabled but allowed_cidrs is empty");
    }
    let cidrs = c
        .allowed_cidrs
        .iter()
        .map(|s| Cidr::parse(s))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow::anyhow!("netconnect: {e}"))?;
    if neighbor_command().is_none() {
        anyhow::bail!("netconnect: no arp/ip binary at the fixed system paths");
    }
    let mut tools: Vec<Arc<dyn Tool>> = vec![Arc::new(NetNeighbors { cidrs })];
    if c.include_connections {
        let nb = ctx.cfg.home().join("bin").join("netboard");
        anyhow::ensure!(
            cfg!(target_os = "macos") && nb.is_file(),
            "netconnect.include_connections needs macOS and {} (install.sh --with-netviewer)",
            nb.display()
        );
        tools.push(Arc::new(NetConnections { netboard: nb }));
    }
    Ok(Parts {
        tools,
        ..Default::default()
    })
}

/// CyClaw-Net-Viewer integration: read-only socket snapshot, numeric (`-n`,
/// no reverse DNS), all states (`-a`). Process names are attacker-choosable,
/// so output is untrusted.
pub struct NetConnections {
    netboard: std::path::PathBuf,
}

#[async_trait]
impl Tool for NetConnections {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "net_connections",
            description: "Snapshot of this Mac's TCP/UDP sockets with owning process (CyClaw-Net-Viewer, numeric). Optional `process` filters by name or pid.",
            parameters: json!({"type":"object","properties":{"process":{"type":"string","maxLength":64}},"additionalProperties":false}),
            effect: Effect::Read,
            untrusted_output: true,
            remote_ok: false,
        }
    }
    async fn call(&self, args: Value) -> Result<String, ToolError> {
        let mut cmd = clean_command(&self.netboard, &[]);
        cmd.args(["--cli", "-n", "-a"]);
        if let Some(p) = args.get("process").and_then(|v| v.as_str()) {
            if p.is_empty()
                || p.starts_with('-')
                || !p
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "._ -".contains(c))
            {
                return Err(ToolError::BadArgs("process must be a name or pid".into()));
            }
            cmd.arg(p);
        }
        let out = tokio::time::timeout(std::time::Duration::from_secs(20), cmd.output())
            .await
            .map_err(|_| ToolError::Failed("netboard timed out".into()))?
            .map_err(ToolError::failed)?;
        let text =
            String::from_utf8_lossy(&out.stdout[..out.stdout.len().min(256 * 1024)]).to_string();
        Ok(crate::common::clip(&text, 12_000))
    }
}

#[async_trait]
impl Tool for NetNeighbors {
    fn spec(&self) -> ToolSpec {
        ToolSpec {
            name: "net_neighbors",
            description: "List IPv4 devices the OS has recently seen on the local network (ARP cache), limited to allowlisted subnets.",
            parameters: json!({"type": "object", "properties": {}, "additionalProperties": false}),
            effect: Effect::Read,
            untrusted_output: false,
            remote_ok: false,
        }
    }

    async fn call(&self, _args: Value) -> Result<String, ToolError> {
        let (bin, args) = neighbor_command()
            .ok_or_else(|| ToolError::NotConfigured("arp binary missing".into()))?;
        let out = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            clean_command(Path::new(bin), &[]).args(args).output(),
        )
        .await
        .map_err(|_| ToolError::Failed("neighbour listing timed out".into()))?
        .map_err(ToolError::failed)?;
        if !out.status.success() {
            return Err(ToolError::Failed("neighbour listing failed".into()));
        }
        let text = String::from_utf8_lossy(&out.stdout[..out.stdout.len().min(1 << 20)]);
        let rows: Vec<_> = parse_neighbors(&text)
            .into_iter()
            .filter(|n| self.cidrs.iter().any(|c| c.contains(n.ip)))
            .collect();
        if rows.is_empty() {
            return Ok("no neighbours in the allowlisted subnets".into());
        }
        Ok(rows
            .iter()
            .map(|n| format!("{}\t{}", n.ip, n.mac))
            .collect::<Vec<_>>()
            .join("\n"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_must_be_private_and_narrow() {
        assert!(Cidr::parse("192.168.1.0/24").is_ok());
        assert!(Cidr::parse("10.1.0.0/16").is_ok());
        assert!(Cidr::parse("127.0.0.0/24").is_ok());
        for bad in [
            "8.8.8.0/24",
            "172.32.0.0/16",
            "10.0.0.0/8",
            "0.0.0.0/0",
            "192.168.1.0",
            "fe80::/64",
            "192.168.1.0/33",
        ] {
            assert!(Cidr::parse(bad).is_err(), "{bad}");
        }
        let c = Cidr::parse("192.168.1.77/24").expect("ok");
        assert!(c.contains("192.168.1.5".parse().expect("ip")));
        assert!(!c.contains("192.168.2.5".parse().expect("ip")));
    }

    #[test]
    fn parses_all_three_formats() {
        let mac = "? (192.168.1.1) at a0:b1:c:d:e:f on en0 ifscope [ethernet]\n? (192.168.1.255) at ff:ff:ff:ff:ff:ff on en0\n? (192.168.1.9) at (incomplete) on en0";
        let lin = "192.168.1.20 dev eth0 lladdr AA:BB:CC:DD:EE:FF REACHABLE\nfe80::1 dev eth0 lladdr 11:22:33:44:55:66 STALE";
        let win = "  192.168.1.30          00-11-22-33-44-55     dynamic\n  224.0.0.22            01-00-5e-00-00-16     static";
        let r = parse_neighbors(&format!("{mac}\n{lin}\n{win}"));
        assert_eq!(
            r,
            vec![
                Neighbor {
                    ip: "192.168.1.1".parse().expect("ip"),
                    mac: "a0:b1:0c:0d:0e:0f".into()
                },
                Neighbor {
                    ip: "192.168.1.20".parse().expect("ip"),
                    mac: "aa:bb:cc:dd:ee:ff".into()
                },
                Neighbor {
                    ip: "192.168.1.30".parse().expect("ip"),
                    mac: "00:11:22:33:44:55".into()
                },
            ]
        );
    }
}
