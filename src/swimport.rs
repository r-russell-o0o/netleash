//! Import blocked programs from simplewall (Henry++), from its `profile.xml`.
//!
//! simplewall blocks every program that isn't allowed: the programs listed
//! in its profile are allowed when checked and blocked when not. NetLeash
//! allows by default, so only programs the profile lists can carry over.
//! Which directions simplewall blocks comes from `simplewall.ini` next to the
//! profile (BlockOutboundConnections, BlockInboundConnections, UseStealthMode;
//! all on by default).
//!
//! | simplewall                                   | NetLeash                         |
//! |----------------------------------------------|----------------------------------|
//! | unchecked (blocked) program                  | block, in the directions simplewall blocks |
//! | enabled user Block rule for programs, with no address, port, protocol or IP version | block outbound / inbound / both |
//! | checked (allowed) program, Allow rules       | skipped: NetLeash allows by default |
//! | blocked program that an Allow rule opens up for some addresses | skipped: NetLeash can't express it |
//! | rules with addresses/ports, built-in rules, services, Store apps | skipped, with the reason |
//!
//! Only plain-XML profiles can be read; simplewall can also save them
//! compressed or encrypted. Files are only read, never written.

use crate::catalog::expand_env;
use crate::nlimport::{Plan, Skipped};
use crate::state::{Rule, app_key, file_name};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const MAX_FILE: u64 = 64 * 1024 * 1024;

/// Where simplewall keeps its profile: `%APPDATA%\Henry++\simplewall`, or
/// next to simplewall.exe in a portable install. NetLeash runs as SYSTEM, so
/// look in every user's profile and take the most recently saved file.
pub fn default_path() -> Option<PathBuf> {
    let drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into());
    let mut found: Vec<PathBuf> = std::fs::read_dir(format!(r"{drive}\Users"))
        .into_iter()
        .flatten()
        .flatten()
        .map(|u| {
            u.path()
                .join(r"AppData\Roaming\Henry++\simplewall\profile.xml")
        })
        .collect();
    for var in ["ProgramFiles", "ProgramFiles(x86)"] {
        if let Ok(pf) = std::env::var(var) {
            found.push(Path::new(&pf).join(r"simplewall\profile.xml"));
        }
    }
    found
        .into_iter()
        .filter_map(|p| Some((std::fs::metadata(&p).ok()?.modified().ok()?, p)))
        .max()
        .map(|(_, p)| p)
}

/// What simplewall blocks for programs that aren't allowed: (in, out).
pub fn default_blocks(ini: &str) -> (bool, bool) {
    let get = |key: &str| {
        ini.lines()
            .filter_map(|l| l.split_once('='))
            .find(|(k, _)| k.trim().eq_ignore_ascii_case(key))
            .is_none_or(|(_, v)| !v.trim().eq_ignore_ascii_case("false"))
    };
    (
        get("BlockInboundConnections") || get("UseStealthMode"),
        get("BlockOutboundConnections"),
    )
}

fn attr<'a>(n: roxmltree::Node<'a, '_>, name: &str) -> &'a str {
    n.attribute(name).unwrap_or("").trim()
}

fn flag(n: roxmltree::Node, name: &str) -> bool {
    attr(n, name).eq_ignore_ascii_case("true")
}

/// A path from the profile, or `None` for a service name or Store app SID.
fn program(s: &str) -> Option<String> {
    let p = expand_env(s.trim());
    p.contains('\\').then_some(p)
}

fn items<'a, 'i>(
    root: roxmltree::Node<'a, 'i>,
    section: &str,
) -> impl Iterator<Item = roxmltree::Node<'a, 'i>> {
    root.children()
        .filter(move |c| c.tag_name().name() == section)
        .flat_map(|s| s.children().filter(|c| c.tag_name().name() == "item"))
}

/// Turn simplewall's profile into NetLeash rules (one per program).
/// `blocks` is what simplewall blocks for unchecked programs: (in, out).
pub fn parse(xml: &str, blocks: (bool, bool)) -> Result<(Vec<Rule>, Vec<Skipped>), String> {
    let doc = roxmltree::Document::parse_with_options(
        xml,
        roxmltree::ParsingOptions {
            allow_dtd: false,
            ..Default::default()
        },
    )
    .map_err(|e| format!("not a readable XML file: {e}"))?;
    let root = doc.root_element();
    if root.tag_name().name() != "root" || attr(root, "type") != "3" {
        return Err("not a simplewall profile (no <root type=\"3\">)".into());
    }
    let mut rules: BTreeMap<String, Rule> = BTreeMap::new();
    let mut skipped = Vec::new();
    let mut skip = |what: String, reason: &str| {
        skipped.push(Skipped {
            what,
            reason: reason.to_string(),
        })
    };

    // Programs an enabled Allow rule opens up for some traffic.
    let mut partly_allowed: BTreeMap<String, String> = BTreeMap::new();
    for r in items(root, "rules_custom") {
        if flag(r, "is_enabled") && !flag(r, "is_block") {
            for p in attr(r, "apps").split('|').filter_map(program) {
                partly_allowed.insert(app_key(&p), attr(r, "name").to_string());
            }
        }
    }

    for a in items(root, "apps") {
        let raw = attr(a, "path");
        if raw.is_empty() {
            continue;
        }
        let allowed = flag(a, "is_enabled");
        let what = format!(
            "{} — {}",
            if allowed { "Allowed" } else { "Blocked" },
            file_name(raw)
        );
        if allowed {
            skip(what, "Allow: NetLeash allows everything not blocked");
            continue;
        }
        let Some(path) = program(raw) else {
            skip(what, "Windows service or Store app, not a program file");
            continue;
        };
        if path.starts_with(r"\device\") || path.starts_with(r"\Device\") {
            skip(
                what,
                "device path simplewall couldn't resolve to a drive letter",
            );
            continue;
        }
        if let Some(rule) = partly_allowed.get(&app_key(&path)) {
            skip(
                what,
                &format!("blocked except what rule \"{rule}\" allows; NetLeash can't express that"),
            );
            continue;
        }
        if blocks == (false, false) {
            skip(
                what,
                "simplewall is set not to block programs it doesn't allow",
            );
            continue;
        }
        let e = rules.entry(app_key(&path)).or_insert_with(|| Rule {
            path,
            ..Default::default()
        });
        e.block_in |= blocks.0;
        e.block_out |= blocks.1;
    }

    for r in items(root, "rules_custom") {
        let name = attr(r, "name");
        let block = flag(r, "is_block");
        let what = format!("{} rule — {name}", if block { "Block" } else { "Allow" });
        if !block {
            skip(what, "Allow: NetLeash allows everything not blocked");
            continue;
        }
        if !flag(r, "is_enabled") {
            skip(what, "disabled in simplewall");
            continue;
        }
        let mut limits = Vec::new();
        if !attr(r, "rule").is_empty() || !attr(r, "rule_remote").is_empty() {
            limits.push("remote addresses/ports");
        }
        if !attr(r, "rule_local").is_empty() {
            limits.push("local addresses/ports");
        }
        if !matches!(attr(r, "protocol"), "" | "0") {
            limits.push("a protocol");
        }
        if !matches!(attr(r, "version"), "" | "0") {
            limits.push("IPv4 or IPv6 only");
        }
        if !limits.is_empty() {
            skip(
                what,
                &format!(
                    "limited to {}; NetLeash blocks a program's traffic as a whole",
                    limits.join(", ")
                ),
            );
            continue;
        }
        // FWP_DIRECTION: 0 outbound (the default), 1 inbound, 2 both.
        let (inbound, outbound) = match attr(r, "dir") {
            "" | "0" => (false, true),
            "1" => (true, false),
            "2" => (true, true),
            d => {
                skip(what, &format!("unknown direction \"{d}\""));
                continue;
            }
        };
        let apps: Vec<&str> = attr(r, "apps")
            .split('|')
            .filter(|s| !s.trim().is_empty())
            .collect();
        if apps.is_empty() {
            skip(what, "applies to all programs, not specific ones");
            continue;
        }
        for app in apps {
            let Some(path) = program(app) else {
                skip(
                    format!("{what} ({app})"),
                    "Windows service or Store app, not a program file",
                );
                continue;
            };
            let e = rules.entry(app_key(&path)).or_insert_with(|| Rule {
                path,
                ..Default::default()
            });
            e.block_in |= inbound;
            e.block_out |= outbound;
        }
    }

    for r in items(root, "rules_config") {
        if attr(r, "apps").is_empty() {
            continue; // just switches a built-in rule on or off
        }
        skip(
            format!("Built-in rule — {}", attr(r, "name")),
            "built-in rule for addresses/ports, applied to programs; not per program",
        );
    }
    Ok((rules.into_values().collect(), skipped))
}

/// The profile as text. simplewall writes UTF-8, but accept UTF-16 too.
fn decode(bytes: &[u8]) -> Result<String, String> {
    if bytes.starts_with(b"SWC") {
        return Err(
            "simplewall saved this profile compressed or encrypted; set simplewall's \
                    profile type to Plain (it re-saves the file), then read it again"
                .into(),
        );
    }
    if let Some(rest) = bytes.strip_prefix(&[0xFF, 0xFE]) {
        let units: Vec<u16> = rest
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        return Ok(String::from_utf16_lossy(&units));
    }
    let bytes = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
    String::from_utf8(bytes.to_vec()).map_err(|_| "not a UTF-8 text file".into())
}

/// Read and parse a simplewall profile, without changing anything.
pub fn plan(path: &Path) -> Result<Plan, String> {
    let meta = std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if meta.len() > MAX_FILE {
        return Err(format!("{} is unexpectedly large", path.display()));
    }
    let bytes = std::fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let ini = path
        .parent()
        .and_then(|d| std::fs::read(d.join("simplewall.ini")).ok())
        .and_then(|b| decode(&b).ok())
        .unwrap_or_default();
    let (rules, skipped) = parse(&decode(&bytes)?, default_blocks(&ini))?;
    Ok(crate::nlimport::finish(
        path.display().to_string(),
        rules,
        skipped,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"<?xml version="1.0" ?>
<root timestamp="1761000000" type="3" version="5">
	<apps>
		<item path="C:\Games\launcher.exe" timestamp="1" />
		<item path="%ProgramFiles%\Tool\tool.exe" timestamp="1" is_enabled="false" />
		<item path="C:\Web\browser.exe" timestamp="1" is_enabled="true" />
		<item path="C:\Chat\chat.exe" timestamp="1" />
		<item path="S-1-15-2-1234" timestamp="1" />
		<item path="wuauserv" timestamp="1" />
	</apps>
	<rules_custom>
		<item name="No inbound for browser" dir="1" apps="C:\Web\browser.exe" is_block="true" is_enabled="true" />
		<item name="Chat server" rule="chat.example.com" protocol="6" apps="C:\Chat\chat.exe" is_enabled="true" />
		<item name="Block both" dir="2" apps="C:\X\a.exe|C:\X\b.exe|Dnscache" is_block="true" is_enabled="true" />
		<item name="Block DNS" rule="53" apps="C:\Y\y.exe" is_block="true" is_enabled="true" />
		<item name="Off" apps="C:\Z\z.exe" is_block="true" />
		<item name="Everyone" is_block="true" is_enabled="true" />
		<item name="v6 only" version="23" apps="C:\V\v.exe" is_block="true" is_enabled="true" />
	</rules_custom>
	<rules_config>
		<item name="DNS" is_enabled="false" />
		<item name="Windows Update service" apps="C:\Tools\wu.exe" is_enabled="true" />
	</rules_config>
</root>"#;

    fn find<'a>(rules: &'a [Rule], path: &str) -> &'a Rule {
        rules.iter().find(|r| r.path == path).unwrap()
    }

    #[test]
    fn imports_blocked_programs_and_block_rules() {
        let (rules, skipped) = parse(SAMPLE, (true, true)).unwrap();
        // Unchecked programs: blocked both ways, as simplewall does by default.
        assert!(find(&rules, r"C:\Games\launcher.exe").blocks_all());
        let pf = std::env::var("ProgramFiles").unwrap();
        assert!(find(&rules, &format!(r"{pf}\Tool\tool.exe")).blocks_all());
        // An allowed program with an unrestricted inbound Block rule.
        let w = find(&rules, r"C:\Web\browser.exe");
        assert!(w.block_in && !w.block_out);
        // dir="2" with two programs and a service.
        assert!(find(&rules, r"C:\X\a.exe").blocks_all());
        assert!(find(&rules, r"C:\X\b.exe").blocks_all());
        assert_eq!(rules.len(), 5);

        let reasons: Vec<&str> = skipped.iter().map(|s| s.reason.as_str()).collect();
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("rule \"Chat server\" allows"))
        );
        assert!(reasons.iter().any(|r| r.contains("remote addresses/ports")));
        assert!(reasons.iter().any(|r| r.contains("IPv4 or IPv6 only")));
        assert!(reasons.contains(&"disabled in simplewall"));
        assert!(reasons.contains(&"applies to all programs, not specific ones"));
        assert!(reasons.iter().any(|r| r.starts_with("built-in rule")));
        assert_eq!(
            reasons
                .iter()
                .filter(|r| r.starts_with("Windows service or Store app"))
                .count(),
            3
        );
        // The allowed browser, and the Allow rule itself.
        assert_eq!(reasons.iter().filter(|r| r.starts_with("Allow")).count(), 2);
        assert_eq!(skipped.len(), 11);
    }

    #[test]
    fn follows_simplewalls_default_directions() {
        let ini = "[simplewall]\r\nBlockOutboundConnections=true\r\nUseStealthMode=false\r\nBlockInboundConnections=false\r\n";
        assert_eq!(default_blocks(ini), (false, true));
        assert_eq!(default_blocks(""), (true, true));
        let (rules, _) = parse(SAMPLE, (false, true)).unwrap();
        let l = find(&rules, r"C:\Games\launcher.exe");
        assert!(l.block_out && !l.block_in);
        let (rules, skipped) = parse(SAMPLE, (false, false)).unwrap();
        assert!(!rules.iter().any(|r| r.path == r"C:\Games\launcher.exe"));
        assert!(
            skipped
                .iter()
                .any(|s| s.reason.contains("set not to block"))
        );
    }

    #[test]
    fn rejects_other_files() {
        assert!(
            parse("<NLSvcSettings/>", (true, true))
                .unwrap_err()
                .contains("not a simplewall")
        );
        assert!(decode(b"SWC1....").unwrap_err().contains("Plain"));
        let utf16: Vec<u8> = [0xFF, 0xFE]
            .into_iter()
            .chain("<root/>".encode_utf16().flat_map(u16::to_le_bytes))
            .collect();
        assert_eq!(decode(&utf16).unwrap(), "<root/>");
    }
}
