//! Import rules from NetLimiter 5's `nl_settings.xml`.
//!
//! NetLimiter stores *rules* (firewall allow/deny/ask, limits, ignores) that
//! each point to a *filter* (which traffic: an app path, a zone such as
//! "Internet", address or port ranges). NetLeash rules are per application,
//! so only rules whose filter is exactly "this executable" carry over:
//!
//! | NetLimiter                         | NetLeash                       |
//! |------------------------------------|--------------------------------|
//! | firewall Deny, direction Out/In/Both | block outbound / inbound / both |
//! | limit, direction Out/In/Both       | upload / download limit        |
//! | Allow                              | skipped: NetLeash allows by default |
//! | Ask                                | skipped: no ask mode yet       |
//! | Deny on a program combined with the "Internet" zone | internet-only block (local network stays reachable) |
//! | disabled rules, ignore rules, other zones, address/port filters, Store apps | skipped, with the reason |
//!
//! The file is only read, never written.

use crate::state::{Rule, app_key};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};
use std::path::Path;

pub const DEFAULT_PATH: &str = r"C:\ProgramData\Locktime\NetLimiter\5\nl_settings.xml";
const XSI: &str = "http://www.w3.org/2001/XMLSchema-instance";
const MAX_FILE: u64 = 64 * 1024 * 1024;

#[derive(Serialize, Debug, PartialEq, Eq)]
pub struct Skipped {
    pub what: String,
    pub reason: String,
}

#[derive(Serialize, Debug)]
pub struct Plan {
    pub source: String,
    pub rules: Vec<Rule>,
    pub skipped: Vec<Skipped>,
    /// Imported rules whose executable does not exist right now. They are
    /// kept (the program may be installed later or on a drive that is offline);
    /// Windows can only enforce a block once the file exists.
    pub missing_files: Vec<String>,
}

struct Func {
    kind: String,
    matches: bool,
    paths: Vec<String>,
}

struct Filter {
    name: String,
    funcs: Vec<Func>,
    /// Composite filters combine other filters (e.g. a program AND "Internet").
    base: Vec<String>,
}

fn norm_id(s: &str) -> String {
    s.trim().trim_matches(['{', '}']).to_lowercase()
}

fn child<'a, 'i>(n: roxmltree::Node<'a, 'i>, name: &str) -> Option<roxmltree::Node<'a, 'i>> {
    n.children().find(|c| c.tag_name().name() == name)
}

fn text(n: roxmltree::Node, name: &str) -> String {
    child(n, name)
        .and_then(|c| c.text())
        .unwrap_or("")
        .trim()
        .to_string()
}

fn xsi_type(n: roxmltree::Node) -> String {
    n.attribute((XSI, "type")).unwrap_or("").to_string()
}

fn parse_filters(root: roxmltree::Node) -> HashMap<String, Filter> {
    let mut out = HashMap::new();
    let Some(filters) = child(root, "Filters") else {
        return out;
    };
    for f in filters
        .children()
        .filter(|c| c.tag_name().name() == "filter")
    {
        let funcs = child(f, "FunctionList")
            .map(|fl| {
                fl.children()
                    .filter(|c| c.tag_name().name() == "function")
                    .map(|func| Func {
                        kind: xsi_type(func),
                        matches: text(func, "match") != "false",
                        paths: child(func, "Values")
                            .map(|v| {
                                v.children()
                                    .filter(|c| c.tag_name().name() == "value")
                                    .map(|val| text(val, "Path"))
                                    .filter(|p| !p.is_empty())
                                    .collect()
                            })
                            .unwrap_or_default(),
                    })
                    .collect()
            })
            .unwrap_or_default();
        let display = text(f, "DisplayName");
        let name = if display.is_empty() {
            text(f, "Name")
        } else {
            display
        };
        let base = child(f, "BaseFilters")
            .map(|b| {
                b.children()
                    .filter_map(|c| c.text())
                    .map(norm_id)
                    .filter(|id| !id.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        out.insert(norm_id(&text(f, "Id")), Filter { name, funcs, base });
    }
    out
}

/// NetLimiter's built-in "Internet" zone: one IsInternetTraffic condition.
fn is_internet(f: &Filter) -> bool {
    f.base.is_empty()
        && !f.funcs.is_empty()
        && f.funcs
            .iter()
            .all(|x| x.kind == "FFIsInternetTraffic" && x.matches)
}

/// Which app paths a filter selects and whether only their internet traffic,
/// or why it can't be expressed per app.
fn app_paths(
    filter: &Filter,
    all: &HashMap<String, Filter>,
) -> Result<(Vec<String>, bool), String> {
    // A program AND "Internet" (NetLimiter's usual composite).
    if let [a, b] = filter.base.as_slice()
        && let (Some(a), Some(b)) = (all.get(a), all.get(b))
    {
        let app = match (is_internet(a), is_internet(b)) {
            (true, false) => Some(b),
            (false, true) => Some(a),
            _ => None,
        };
        if let Some(app) = app
            && let Ok((paths, false)) = app_paths(app, all)
        {
            return Ok((paths, true));
        }
    }
    if !filter.base.is_empty() {
        let parts: Vec<String> = filter
            .base
            .iter()
            .map(|id| {
                all.get(id)
                    .map_or_else(|| "?".to_string(), |f| f.name.clone())
            })
            .collect();
        return Err(format!(
            "combines filters ({}); NetLeash can't restrict a rule to part of a program's traffic",
            parts.join(" + ")
        ));
    }
    let app: Vec<&Func> = filter
        .funcs
        .iter()
        .filter(|f| f.kind == "FFAppIdEqual")
        .collect();
    if app.is_empty() {
        return Err(format!(
            "applies to \"{}\", not to specific programs",
            filter.name
        ));
    }
    let others: Vec<&str> = filter
        .funcs
        .iter()
        .filter(|f| f.kind != "FFAppIdEqual")
        .map(|f| f.kind.trim_start_matches("FF"))
        .collect();
    if !others.is_empty() {
        return Err(format!(
            "has extra conditions NetLeash can't express ({})",
            others.join(", ")
        ));
    }
    if app.iter().any(|f| !f.matches) {
        return Err("matches every program *except* the listed one".into());
    }
    Ok((
        app.iter().flat_map(|f| f.paths.iter().cloned()).collect(),
        false,
    ))
}

/// Turn NetLimiter's settings XML into NetLeash rules (one per program).
pub fn parse(xml: &str) -> Result<(Vec<Rule>, Vec<Skipped>), String> {
    let doc = roxmltree::Document::parse_with_options(
        xml,
        roxmltree::ParsingOptions {
            allow_dtd: false,
            ..Default::default()
        },
    )
    .map_err(|e| format!("not a readable XML file: {e}"))?;
    let root = doc.root_element();
    if root.tag_name().name() != "NLSvcSettings" {
        return Err("not a NetLimiter settings file (no <NLSvcSettings>)".into());
    }
    let filters = parse_filters(root);
    let mut rules: BTreeMap<String, Rule> = BTreeMap::new();
    let mut skipped = Vec::new();

    let Some(rule_list) = child(root, "Rules") else {
        return Ok((Vec::new(), skipped));
    };
    for r in rule_list
        .children()
        .filter(|c| c.tag_name().name() == "rule")
    {
        let kind = xsi_type(r);
        let filter = filters.get(&norm_id(&text(r, "FilterId")));
        let label = filter.map(|f| f.name.clone()).unwrap_or_else(|| "?".into());
        let action = text(r, "action");
        let what = match kind.as_str() {
            "fwRule" => format!("{action} {} — {label}", text(r, "Dir")),
            "limitRule" => format!("Limit {} — {label}", text(r, "Dir")),
            other => format!("{other} — {label}"),
        };
        let mut skip = |reason: &str| {
            skipped.push(Skipped {
                what: what.clone(),
                reason: reason.to_string(),
            })
        };
        if text(r, "IsEnabled") == "false" {
            skip("disabled in NetLimiter");
            continue;
        }
        match (kind.as_str(), action.as_str()) {
            ("fwRule", "Deny") | ("limitRule", _) => {}
            ("fwRule", "Allow") => {
                skip("Allow: NetLeash allows everything not blocked");
                continue;
            }
            ("fwRule", "Ask") => {
                skip("Ask: NetLeash has no ask-on-connect mode yet");
                continue;
            }
            ("IgnoreRule", _) => {
                skip("ignore rules exempt traffic from stats/limits; not applicable");
                continue;
            }
            _ => {
                skip("rule type NetLeash doesn't support");
                continue;
            }
        }
        let Some(filter) = filter else {
            skip("its filter is missing from the file");
            continue;
        };
        let (paths, internet) = match app_paths(filter, &filters) {
            Ok(p) => p,
            Err(reason) => {
                skip(&reason);
                continue;
            }
        };
        if internet && kind != "fwRule" {
            skip("limits on internet traffic only aren't supported yet");
            continue;
        }
        let dir = text(r, "Dir");
        let (inbound, outbound) = match dir.as_str() {
            "In" => (true, false),
            "Out" => (false, true),
            "Both" => (true, true),
            _ => {
                skip(&format!("unknown direction \"{dir}\""));
                continue;
            }
        };
        for path in paths {
            if path == "null-path" {
                skipped.push(Skipped {
                    what: what.clone(),
                    reason: "Windows Store app, identified by package rather than path".into(),
                });
                continue;
            }
            let e = rules.entry(app_key(&path)).or_insert_with(|| Rule {
                path: path.clone(),
                ..Default::default()
            });
            if kind == "fwRule" {
                // One program, several Deny rules: a full block wins over an
                // internet-only one (the stricter of the two).
                e.internet_only = internet && (e.internet_only || !e.blocks_any());
                e.block_in |= inbound;
                e.block_out |= outbound;
            } else {
                let Ok(bytes) = text(r, "limitSize").parse::<u64>() else {
                    skipped.push(Skipped {
                        what: what.clone(),
                        reason: "limit without a readable size".into(),
                    });
                    continue;
                };
                if bytes == 0 {
                    // NetLimiter's 0 B/s limit is effectively a block.
                    e.internet_only &= !e.blocks_any();
                    e.block_in |= inbound;
                    e.block_out |= outbound;
                    continue;
                }
                if inbound {
                    e.down_limit = Some(bytes);
                }
                if outbound {
                    e.up_limit = Some(bytes);
                }
            }
        }
    }
    let rules = rules.into_values().filter(|r| !r.is_noop()).collect();
    Ok((rules, skipped))
}

/// NetLimiter stores paths lowercased. If the file exists, use the real
/// spelling so the UI shows "C:\Program Files\..." rather than "c:\program files\...".
fn real_case(path: &str) -> Option<String> {
    let p = std::fs::canonicalize(path).ok()?;
    let s = p.to_string_lossy();
    let s = s.strip_prefix(r"\\?\")?; // only plain drive paths; leave UNC alone
    (s.to_lowercase() == path.to_lowercase()).then(|| s.to_string())
}

/// Read and parse a NetLimiter settings file, without changing anything.
pub fn plan(path: &Path) -> Result<Plan, String> {
    let meta = std::fs::metadata(path).map_err(|e| format!("{}: {e}", path.display()))?;
    if meta.len() > MAX_FILE {
        return Err(format!("{} is unexpectedly large", path.display()));
    }
    let xml = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let (mut rules, skipped) = parse(&xml)?;
    let mut missing_files = Vec::new();
    for r in &mut rules {
        if crate::pathglob::has_wildcard(&r.path) {
            if crate::pathglob::expand(&r.path).is_empty() {
                missing_files.push(r.path.clone());
            }
            continue;
        }
        match real_case(&r.path) {
            Some(p) => r.path = p,
            None if !Path::new(&r.path).exists() => missing_files.push(r.path.clone()),
            None => {}
        }
    }
    Ok(Plan {
        source: path.display().to_string(),
        rules,
        skipped,
        missing_files,
    })
}

/// Combine an imported rule with an existing one: blocks add up, and limits
/// already set in NetLeash win over imported ones.
pub fn merge(existing: Option<Rule>, imported: Rule) -> Rule {
    let Some(mut e) = existing else {
        return imported;
    };
    e.internet_only = match (e.blocks_any(), imported.blocks_any()) {
        (false, _) => imported.internet_only,
        (true, false) => e.internet_only,
        (true, true) => e.internet_only && imported.internet_only,
    };
    e.block_in |= imported.block_in;
    e.block_out |= imported.block_out;
    e.up_limit = e.up_limit.or(imported.up_limit);
    e.down_limit = e.down_limit.or(imported.down_limit);
    e
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"<NLSvcSettings xmlns="nlsettings" xmlns:i="http://www.w3.org/2001/XMLSchema-instance">
<Filters>
  <filter><Id>{c053e57e-d554-49cb-ac70-e0ce95302faa}</Id><FunctionList /><Name>Any</Name></filter>
  <filter><Id>{2bc7c021-b058-45dc-b22f-73d8e10e3fef}</Id><FunctionList><function i:type="FFIsInternetTraffic"><match>true</match></function></FunctionList><Name>Internet</Name></filter>
  <filter><Id>aaaa0001-0000-0000-0000-000000000000</Id><FunctionList><function i:type="FFAppIdEqual"><match>true</match><Values><value><Path>t:\programs\premiere\gpusniffer.exe</Path><Sid i:nil="true" /></value></Values></function></FunctionList><Name>gpusniffer.exe</Name></filter>
  <filter><Id>aaaa0002-0000-0000-0000-000000000000</Id><FunctionList><function i:type="FFAppIdEqual"><match>true</match><Values><value><Path>c:\lic\lmgrd.exe</Path></value><value><Path>c:\lic\ugslmd.exe</Path></value></Values></function></FunctionList><Name>License servers</Name></filter>
  <filter><Id>aaaa0003-0000-0000-0000-000000000000</Id><FunctionList><function i:type="FFAppIdEqual"><match>true</match><Values><value><Path>c:\x\app.exe</Path></value></Values></function><function i:type="FFRemotePortInRange"><match>true</match></function></FunctionList><Name>app on port</Name></filter>
  <filter i:type="StorePackageFilter"><Id>aaaa0004-0000-0000-0000-000000000000</Id><FunctionList><function i:type="FFAppIdEqual"><match>true</match><Values><value><Path>null-path</Path></value></Values></function></FunctionList><Name>5319275A.WhatsAppDesktop</Name><DisplayName>WhatsApp</DisplayName></filter>
  <filter><Id>aaaa0005-0000-0000-0000-000000000000</Id><FunctionList><function i:type="FFAppIdEqual"><match>true</match><Values><value><Path>d:\games\launcher.exe</Path></value></Values></function></FunctionList><Name>launcher</Name></filter>
  <filter><Id>aaaa0006-0000-0000-0000-000000000000</Id><BaseFilters xmlns:d4p1="http://schemas.microsoft.com/2003/10/Serialization/Arrays"><d4p1:string>aaaa0005-0000-0000-0000-000000000000</d4p1:string><d4p1:string>{2bc7c021-b058-45dc-b22f-73d8e10e3fef}</d4p1:string></BaseFilters><FilterType>Composite</FilterType><FunctionList /><Name>0b2bb683-74db-4b0a-83a5-1ac14ba8e214</Name></filter>
</Filters>
<Rules>
  <rule i:type="fwRule"><Dir>In</Dir><FilterId>aaaa0001-0000-0000-0000-000000000000</FilterId><IsEnabled>true</IsEnabled><Dir>In</Dir><action>Deny</action></rule>
  <rule i:type="fwRule"><Dir>Out</Dir><FilterId>{AAAA0001-0000-0000-0000-000000000000}</FilterId><IsEnabled>true</IsEnabled><Dir>Out</Dir><action>Deny</action></rule>
  <rule i:type="fwRule"><Dir>Out</Dir><FilterId>aaaa0002-0000-0000-0000-000000000000</FilterId><IsEnabled>true</IsEnabled><Dir>Out</Dir><action>Deny</action></rule>
  <rule i:type="fwRule"><Dir>Out</Dir><FilterId>aaaa0003-0000-0000-0000-000000000000</FilterId><IsEnabled>true</IsEnabled><action>Deny</action></rule>
  <rule i:type="fwRule"><Dir>Out</Dir><FilterId>aaaa0004-0000-0000-0000-000000000000</FilterId><IsEnabled>true</IsEnabled><action>Deny</action></rule>
  <rule i:type="fwRule"><Dir>Out</Dir><FilterId>aaaa0005-0000-0000-0000-000000000000</FilterId><IsEnabled>true</IsEnabled><action>Ask</action></rule>
  <rule i:type="fwRule"><Dir>In</Dir><FilterId>aaaa0005-0000-0000-0000-000000000000</FilterId><IsEnabled>true</IsEnabled><action>Allow</action></rule>
  <rule i:type="limitRule"><Dir>In</Dir><FilterId>aaaa0005-0000-0000-0000-000000000000</FilterId><IsEnabled>true</IsEnabled><limitSize>10485760</limitSize></rule>
  <rule i:type="limitRule"><Dir>In</Dir><FilterId>{c053e57e-d554-49cb-ac70-e0ce95302faa}</FilterId><IsEnabled>false</IsEnabled><limitSize>15728640</limitSize></rule>
  <rule i:type="fwRule"><Dir>Out</Dir><FilterId>{2bc7c021-b058-45dc-b22f-73d8e10e3fef}</FilterId><IsEnabled>true</IsEnabled><action>Deny</action></rule>
  <rule i:type="fwRule"><Dir>Out</Dir><FilterId>aaaa0006-0000-0000-0000-000000000000</FilterId><IsEnabled>true</IsEnabled><action>Deny</action></rule>
  <rule i:type="IgnoreRule"><Dir>Both</Dir><FilterId>aaaa0001-0000-0000-0000-000000000000</FilterId><IsEnabled>true</IsEnabled></rule>
</Rules>
</NLSvcSettings>"#;

    fn find<'a>(rules: &'a [Rule], path: &str) -> &'a Rule {
        rules.iter().find(|r| r.path == path).unwrap()
    }

    #[test]
    fn imports_per_direction_denies_and_limits() {
        let (rules, skipped) = parse(SAMPLE).unwrap();
        // Two one-way Deny rules on one program combine; filter ids match despite braces/case.
        let g = find(&rules, r"t:\programs\premiere\gpusniffer.exe");
        assert!(g.block_in && g.block_out);
        // A filter listing two programs yields two rules.
        assert!(find(&rules, r"c:\lic\lmgrd.exe").block_out);
        assert!(!find(&rules, r"c:\lic\ugslmd.exe").block_in);
        // Enabled app limit: In = download, bytes per second.
        assert_eq!(
            find(&rules, r"d:\games\launcher.exe").down_limit,
            Some(10_485_760)
        );
        assert_eq!(rules.len(), 4);
        // launcher + "Internet" Deny Out: an internet-only outbound block.
        let l = find(&rules, r"d:\games\launcher.exe");
        assert!(l.block_out && !l.block_in && l.internet_only);
        assert!(!g.internet_only);

        let reasons: Vec<&str> = skipped.iter().map(|s| s.reason.as_str()).collect();
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("can't express (RemotePortInRange)"))
        );
        assert!(reasons.iter().any(|r| r.contains("Store app")));
        assert!(reasons.iter().any(|r| r.starts_with("Ask")));
        assert!(reasons.iter().any(|r| r.starts_with("Allow")));
        assert!(reasons.contains(&"disabled in NetLimiter"));
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("\"Internet\", not to specific programs"))
        );
        assert!(reasons.iter().any(|r| r.starts_with("ignore rules")));
        assert_eq!(skipped.len(), 7);
        assert!(
            skipped
                .iter()
                .any(|s| s.what.starts_with("Deny Out — WhatsApp"))
        );
    }

    #[test]
    fn rejects_other_xml() {
        assert!(parse("<foo/>").unwrap_err().contains("not a NetLimiter"));
        assert!(parse("not xml").is_err());
    }

    #[test]
    fn merge_keeps_existing_limits_and_adds_blocks() {
        let existing = Rule {
            path: "c:\\a.exe".into(),
            up_limit: Some(1),
            ..Default::default()
        };
        let imported = Rule {
            path: "c:\\a.exe".into(),
            block_in: true,
            up_limit: Some(2),
            down_limit: Some(3),
            ..Default::default()
        };
        let m = merge(Some(existing), imported);
        assert_eq!(
            (m.block_in, m.block_out, m.up_limit, m.down_limit),
            (true, false, Some(1), Some(3))
        );
    }
}
