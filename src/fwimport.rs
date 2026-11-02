//! Import per-program Block rules from Windows Defender Firewall.
//!
//! Windows keeps its rules in the registry as one string each
//! (`v2.33|Action=Block|Active=TRUE|Dir=Out|App=C:\x.exe|Name=...|`). This
//! also covers Windows Firewall Control, which manages that same rule store.
//!
//! | Windows Firewall                          | NetLeash                         |
//! |-------------------------------------------|----------------------------------|
//! | enabled Block rule for a program, Out/In  | block outbound / inbound         |
//! | ... with remote address "Internet" only   | internet-only block              |
//! | ... on some network types only (Public...) | block on every network, listed in the preview |
//! | Allow                                     | skipped: NetLeash allows by default |
//! | disabled rules, rules without a program, protocols, ports, other addresses, services, users, interfaces, Store apps | skipped, with the reason |
//!
//! The rules are only read, never written.

use crate::catalog::expand_env;
use crate::nlimport::{Plan, Skipped};
use crate::state::{Rule, app_key, file_name};
use std::collections::{BTreeMap, HashMap, HashSet};

pub const SOURCE: &str = "Windows Firewall";

/// A rule's `key=value` fields. `Profile` and a few others may repeat.
fn fields(rule: &str) -> Vec<(&str, &str)> {
    rule.split('|')
        .filter_map(|f| f.split_once('='))
        .map(|(k, v)| (k.trim(), v.trim()))
        .collect()
}

/// Why a Block rule covers only part of a program's traffic, if it does.
/// `Ok((internet, profiles))`: `internet` = only its internet traffic;
/// `profiles` = the network types it is limited to, if not all. NetLeash has
/// no network types, so such a rule is imported as a block on every network
/// (the user chose that over skipping them) and listed in the preview.
fn scope(f: &[(&str, &str)]) -> Result<(bool, Option<String>), String> {
    let mut profiles = Vec::new();
    let mut remote = Vec::new();
    let mut extra: Vec<&str> = Vec::new();
    for &(k, v) in f {
        let what = match k {
            "Action" | "Active" | "Dir" | "App" | "Name" | "Desc" | "EmbedCtxt" | "Edge"
            | "Defer" | "Platform" | "Platform2" => continue,
            "Profile" => {
                profiles.push(v.to_lowercase());
                continue;
            }
            _ if k.starts_with("RA") => {
                remote.push(v);
                continue;
            }
            "Protocol" | "ICMP4" | "ICMP6" => "protocol",
            _ if k.starts_with("LPort") || k.starts_with("RPort") => "ports",
            _ if k.starts_with("LA") => "local addresses",
            "Svc" => "a Windows service",
            "IF" | "IFType" => "network interfaces",
            "LUAuth" | "LUOwn" => "users",
            _ => k,
        };
        if !extra.contains(&what) {
            extra.push(what);
        }
    }
    let mut why = Vec::new();
    if !extra.is_empty() {
        why.push(format!("only for certain {}", extra.join(", ")));
    }
    let limited = (!profiles.is_empty()
        && !["domain", "private", "public"]
            .iter()
            .all(|p| profiles.iter().any(|q| q == p)))
    .then(|| profiles.join(" and "));
    // Windows' "Internet" keyword (stored as IntErnet): everything but the
    // local network, which is what an internet-only block does.
    let internet = !remote.is_empty() && remote.iter().all(|v| v.eq_ignore_ascii_case("internet"));
    if !remote.is_empty() && !internet {
        why.push(format!("only for remote addresses {}", remote.join(", ")));
    }
    if why.is_empty() {
        Ok((internet, limited))
    } else {
        Err(format!(
            "{}; NetLeash blocks a program's traffic as a whole",
            why.join(", ")
        ))
    }
}

/// A rule's identity apart from its protocol and description.
fn signature(f: &[(&str, &str)]) -> String {
    let mut parts: Vec<String> = f
        .iter()
        .filter(|(k, _)| !matches!(*k, "Protocol" | "Name" | "Desc" | "EmbedCtxt"))
        .map(|(k, v)| format!("{k}={}", v.to_lowercase()))
        .collect();
    parts.sort();
    parts.join("|")
}

/// Block rules that come as a TCP + UDP pair (what Windows creates when you
/// block a program at its "allow access?" prompt): together they cover the
/// program's traffic, so the pair counts as "any protocol".
fn tcp_udp_pairs(rule_strings: &[String]) -> HashSet<String> {
    let mut seen: HashMap<String, (bool, bool)> = HashMap::new();
    for s in rule_strings {
        let f = fields(s);
        match f.iter().find(|(k, _)| *k == "Protocol").map(|(_, v)| *v) {
            Some("6") => seen.entry(signature(&f)).or_default().0 = true,
            Some("17") => seen.entry(signature(&f)).or_default().1 = true,
            _ => {}
        }
    }
    seen.into_iter()
        .filter(|(_, both)| *both == (true, true))
        .map(|(sig, _)| sig)
        .collect()
}

/// Turn Windows Firewall rule strings into NetLeash rules (one per program).
/// The third list names rules that were limited to some network types in
/// Windows and now block on every network.
pub fn parse(rule_strings: &[String]) -> (Vec<Rule>, Vec<Skipped>, Vec<String>) {
    let mut rules: BTreeMap<String, Rule> = BTreeMap::new();
    let mut skipped = Vec::new();
    let mut widened = Vec::new();
    let pairs = tcp_udp_pairs(rule_strings);
    for s in rule_strings {
        let mut f = fields(s);
        if pairs.contains(&signature(&f)) {
            f.retain(|&(k, v)| !(k == "Protocol" && matches!(v, "6" | "17")));
        }
        let get = |key: &str| {
            f.iter()
                .find(|(k, _)| *k == key)
                .map(|(_, v)| *v)
                .unwrap_or("")
        };
        let (action, dir, app) = (get("Action"), get("Dir"), get("App"));
        let path = expand_env(app);
        let name = match get("Name") {
            n if n.is_empty() || n.starts_with('@') => {
                // "@FirewallAPI.dll,-28502": a resource reference, not a name.
                if path.is_empty() {
                    n.to_string()
                } else {
                    file_name(&path)
                }
            }
            n => n.to_string(),
        };
        let what = format!("{action} {dir} — {name}");
        let mut skip = |reason: &str| {
            skipped.push(Skipped {
                what: what.clone(),
                reason: reason.to_string(),
            })
        };
        if action != "Block" {
            skip(if action == "Allow" {
                "Allow: NetLeash allows everything not blocked"
            } else {
                "rule type NetLeash doesn't support"
            });
            continue;
        }
        if !get("Active").eq_ignore_ascii_case("TRUE") {
            skip("disabled in Windows Firewall");
            continue;
        }
        if !get("PFN").is_empty() || !get("AppPkgId").is_empty() {
            skip("Windows Store app, identified by package rather than path");
            continue;
        }
        if path.is_empty() {
            skip("applies to all programs, not a specific one");
            continue;
        }
        if !path.contains('\\') {
            skip(&format!("\"{path}\" is not a program file"));
            continue;
        }
        let (inbound, outbound) = match dir {
            "In" => (true, false),
            "Out" => (false, true),
            _ => {
                skip(&format!("unknown direction \"{dir}\""));
                continue;
            }
        };
        let internet = match scope(&f) {
            Ok((i, None)) => i,
            Ok((i, Some(profiles))) => {
                let note = format!("{what} (Windows: {profiles} networks only)");
                if !widened.contains(&note) {
                    widened.push(note);
                }
                i
            }
            Err(reason) => {
                skip(&reason);
                continue;
            }
        };
        let e = rules.entry(app_key(&path)).or_insert_with(|| Rule {
            path: path.clone(),
            ..Default::default()
        });
        // Several Block rules on one program: a full block wins over an
        // internet-only one.
        e.internet_only = internet && (e.internet_only || !e.blocks_any());
        e.block_in |= inbound;
        e.block_out |= outbound;
    }
    (rules.into_values().collect(), skipped, widened)
}

/// Read Windows Firewall's rules, without changing anything.
pub fn plan() -> Result<Plan, String> {
    let strings = crate::catalog::firewall_rule_strings()?;
    let (rules, skipped, widened) = parse(&strings);
    let mut plan = crate::nlimport::finish(SOURCE.into(), rules, skipped);
    plan.widened = widened;
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<String> {
        [
            r"v2.33|Action=Block|Active=TRUE|Dir=Out|App=C:\Games\launcher.exe|Name=No launcher|",
            r"v2.33|Action=Block|Active=TRUE|Dir=In|App=C:\Games\launcher.exe|Name=@FirewallAPI.dll,-1|",
            r"v2.33|Action=Block|Active=TRUE|Dir=Out|App=%ProgramFiles%\Tool\tool.exe|Name=Tool|Profile=Domain|Profile=Private|Profile=Public|",
            r"v2.33|Action=Block|Active=TRUE|Dir=Out|App=C:\Web\browser.exe|Name=Web|RA42=IntErnet|RA62=IntErnet|",
            r"v2.33|Action=Block|Active=TRUE|Dir=Out|App=C:\Lan\lan.exe|Name=Lan|RA4=LocalSubnet|RA6=LocalSubnet|",
            r"v2.33|Action=Block|Active=TRUE|Dir=Out|Protocol=6|RPort=443|App=C:\P\p.exe|Name=Port|",
            r"v2.33|Action=Block|Active=TRUE|Dir=In|Profile=Public|App=C:\Pub\pub.exe|Name=Pub|",
            r"v2.33|Action=Block|Active=FALSE|Dir=Out|App=C:\Off\off.exe|Name=Off|",
            r"v2.33|Action=Block|Active=TRUE|Dir=Out|Svc=wuauserv|Name=Svc|",
            r"v2.33|Action=Block|Active=TRUE|Dir=Out|App=C:\S\svchost.exe|Svc=Dnscache|Name=Svc app|",
            r"v2.33|Action=Allow|Active=TRUE|Dir=In|App=C:\Games\launcher.exe|Name=Allow launcher|",
            r"v2.33|Action=Block|Active=TRUE|Dir=Out|App=C:\Store\x.exe|PFN=Contoso.App_123|Name=Store|",
            r"v2.33|Action=Block|Active=TRUE|Dir=Out|App=System|Name=Kernel|",
            r"v2.31|Action=Block|Active=TRUE|Dir=In|Protocol=6|App=C:\Pair\pair.exe|Name=Pair|",
            r"v2.31|Action=Block|Active=TRUE|Dir=In|Protocol=17|App=C:\Pair\pair.exe|Name=Pair|",
            r"v2.31|Action=Block|Active=TRUE|Dir=In|Protocol=6|Profile=Public|App=C:\Half\half.exe|Name=Half|",
            r"v2.31|Action=Block|Active=TRUE|Dir=In|Protocol=17|Profile=Public|App=C:\Half\half.exe|Name=Half|",
        ]
        .map(String::from)
        .to_vec()
    }

    fn find<'a>(rules: &'a [Rule], path: &str) -> &'a Rule {
        rules.iter().find(|r| r.path == path).unwrap()
    }

    #[test]
    fn imports_per_program_blocks() {
        let (rules, skipped, widened) = parse(&sample());
        // Two one-way Block rules on one program combine.
        let l = find(&rules, r"C:\Games\launcher.exe");
        assert!(l.block_in && l.block_out && !l.internet_only);
        // Environment variables expand; all three profiles = every network.
        let pf = std::env::var("ProgramFiles").unwrap();
        assert!(find(&rules, &format!(r"{pf}\Tool\tool.exe")).block_out);
        // Remote address "Internet" = an internet-only block.
        let w = find(&rules, r"C:\Web\browser.exe");
        assert!(w.block_out && !w.block_in && w.internet_only);
        // A TCP + UDP pair counts as any protocol.
        let p = find(&rules, r"C:\Pair\pair.exe");
        assert!(p.block_in && !p.block_out);
        // Limited to some network types: blocked on every network, and listed.
        assert!(find(&rules, r"C:\Pub\pub.exe").block_in);
        let h = find(&rules, r"C:\Half\half.exe");
        assert!(h.block_in && !h.block_out);
        assert_eq!(widened.len(), 2, "{widened:?}");
        assert!(
            widened
                .iter()
                .all(|w| w.ends_with("(Windows: public networks only)"))
        );
        assert_eq!(rules.len(), 6);

        let reasons: Vec<&str> = skipped.iter().map(|s| s.reason.as_str()).collect();
        assert!(reasons.iter().any(|r| r.contains("LocalSubnet")));
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("certain protocol, ports"))
        );
        assert!(reasons.contains(&"disabled in Windows Firewall"));
        assert!(reasons.contains(&"applies to all programs, not a specific one"));
        assert!(reasons.iter().any(|r| r.contains("a Windows service")));
        assert!(reasons.iter().any(|r| r.starts_with("Allow")));
        assert!(reasons.iter().any(|r| r.contains("Store app")));
        assert!(reasons.iter().any(|r| r.contains("\"System\" is not")));
        assert_eq!(skipped.len(), 8);
    }

    #[test]
    fn names_rules_by_program_when_the_name_is_a_resource() {
        let (_, skipped, _) = parse(&[
            r"v2.33|Action=Block|Active=FALSE|Dir=In|App=C:\x\y.exe|Name=@FirewallAPI.dll,-1|"
                .to_string(),
        ]);
        assert_eq!(skipped[0].what, "Block In — y.exe");
    }
}
