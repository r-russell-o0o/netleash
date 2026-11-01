//! Local web UI and JSON API, bound to 127.0.0.1 only.
//!
//! Because the server runs elevated, it guards against web pages in your
//! browser driving it: the Host header must name this server (defeats DNS
//! rebinding) and every write needs a custom `X-NetLeash` header, which a
//! cross-origin page cannot send without a CORS preflight we never approve.

use crate::catalog;
use crate::conns;
use crate::enforce::Enforcer;
use crate::nlimport;
use crate::state::{Rule, State, app_key};
use crate::sys::ProcessNames;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;
use tiny_http::{Header, Method, Request, Response, Server};

const INDEX: &str = include_str!("../ui/index.html");
const MAX_BODY: usize = 64 * 1024;

type Reply = Response<std::io::Cursor<Vec<u8>>>;

fn reply(status: u16, content_type: &str, body: impl Into<Vec<u8>>) -> Reply {
    Response::from_data(body.into())
        .with_status_code(status)
        .with_header(Header::from_bytes("Content-Type", content_type).unwrap())
        .with_header(Header::from_bytes("Cache-Control", "no-store").unwrap())
        .with_header(Header::from_bytes("X-Content-Type-Options", "nosniff").unwrap())
        .with_header(Header::from_bytes("X-Frame-Options", "DENY").unwrap())
}

fn json(body: String) -> Reply {
    reply(200, "application/json", body)
}

fn error(status: u16, msg: &str) -> Reply {
    reply(
        status,
        "application/json",
        serde_json::json!({ "error": msg }).to_string(),
    )
}

fn header<'a>(req: &'a Request, name: &'static str) -> Option<&'a str> {
    req.headers()
        .iter()
        .find(|h| h.field.equiv(name))
        .map(|h| h.value.as_str())
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 2 < b.len() => {
                let hex = std::str::from_utf8(&b[i + 1..i + 3]).ok();
                match hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                    Some(v) => {
                        out.push(v);
                        i += 3;
                        continue;
                    }
                    None => out.push(b'%'),
                }
            }
            b'+' => out.push(b' '),
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn query_param(url: &str, key: &str) -> Option<String> {
    let q = url.split_once('?')?.1;
    q.split('&')
        .filter_map(|kv| kv.split_once('='))
        .find(|(k, _)| *k == key)
        .map(|(_, v)| percent_decode(v))
}

pub fn serve(
    port: u16,
    state: Arc<State>,
    enforcer: Arc<Enforcer>,
    names: Arc<ProcessNames>,
) -> Result<(), String> {
    let server = Server::http(("127.0.0.1", port))
        .map_err(|e| format!("cannot listen on port {port}: {e}"))?;
    let allowed_hosts = [format!("127.0.0.1:{port}"), format!("localhost:{port}")];
    for mut req in server.incoming_requests() {
        let host_ok = header(&req, "Host").is_some_and(|h| allowed_hosts.iter().any(|a| a == h));
        // Building the program catalog can take seconds the first time (it
        // reads version info from every program's file); answer it on its own
        // thread so the rest of the UI keeps updating meanwhile.
        if host_ok && *req.method() == Method::Get && req.url() == "/api/programs" {
            let (st, nm) = (state.clone(), names.clone());
            std::thread::spawn(move || {
                let body = serde_json::to_string(&catalog::build(&st, &nm)).unwrap();
                let _ = req.respond(json(body));
            });
            continue;
        }
        let resp = if !host_ok {
            error(403, "bad Host header")
        } else {
            handle(&mut req, &state, &enforcer)
        };
        let _ = req.respond(resp);
    }
    Ok(())
}

fn handle(req: &mut Request, state: &State, enforcer: &Enforcer) -> Reply {
    let url = req.url().to_string();
    let path = url.split('?').next().unwrap_or("");
    match (req.method(), path) {
        (Method::Get, "/") => reply(200, "text/html; charset=utf-8", INDEX),
        (Method::Get, "/api/state") => {
            let mut snap = state.snapshot();
            for a in &mut snap.apps {
                a.description = catalog::ver_info(&a.path).description;
            }
            json(serde_json::to_string(&snap).unwrap())
        }
        (Method::Get, "/api/usage") => json(state.usage_json()),
        (Method::Get, "/api/connections") => {
            let Some(key) = query_param(&url, "app") else {
                return error(400, "missing app");
            };
            let pids = state.pids_of(&app_key(&key));
            json(serde_json::to_string(&conns::for_pids(&pids)).unwrap())
        }
        (Method::Post, "/api/rule") => {
            let rule: Rule = match read_json_body(req) {
                Ok(r) => r,
                Err(resp) => return resp,
            };
            let rule = rule.normalize();
            if let Err(e) = validate(&rule) {
                return error(400, &e);
            }
            if let Err(e) = state.set_rule(rule) {
                return error(500, &format!("could not save rules: {e}"));
            }
            enforcer.apply();
            json(r#"{"ok":true}"#.into())
        }
        (Method::Post, "/api/import/netlimiter") => {
            let opts: ImportOpts = match read_json_body(req) {
                Ok(o) => o,
                Err(resp) => return resp,
            };
            let source = opts.path.unwrap_or_else(|| nlimport::DEFAULT_PATH.into());
            // Only NetLimiter-style XML files; this endpoint must not become a file reader.
            if !source.to_lowercase().ends_with(".xml") || !Path::new(&source).is_absolute() {
                return error(400, "give the full path of NetLimiter's nl_settings.xml");
            }
            let plan = match nlimport::plan(Path::new(&source)) {
                Ok(p) => p,
                Err(e) => return error(400, &e),
            };
            if opts.apply {
                let merged: Vec<Rule> = plan
                    .rules
                    .iter()
                    .filter(|r| validate(r).is_ok())
                    .map(|r| nlimport::merge(state.rule_for(&app_key(&r.path)), r.clone()))
                    .collect();
                let n = merged.len();
                if let Err(e) = state.set_rules(merged) {
                    return error(500, &format!("could not save rules: {e}"));
                }
                state.log(format!("imported {n} rules from {}", plan.source));
                enforcer.apply();
            }
            json(serde_json::to_string(&plan).unwrap())
        }
        _ => error(404, "not found"),
    }
}

#[derive(serde::Deserialize)]
struct ImportOpts {
    #[serde(default)]
    path: Option<String>,
    /// false: only report what would be imported.
    #[serde(default)]
    apply: bool,
}

/// Parse a JSON request body, enforcing the CSRF header and size limit.
fn read_json_body<T: serde::de::DeserializeOwned>(req: &mut Request) -> Result<T, Reply> {
    if header(req, "X-NetLeash") != Some("1") {
        return Err(error(403, "missing X-NetLeash header"));
    }
    let mut body = Vec::new();
    if req
        .as_reader()
        .take(MAX_BODY as u64 + 1)
        .read_to_end(&mut body)
        .is_err()
        || body.len() > MAX_BODY
    {
        return Err(error(413, "body too large"));
    }
    serde_json::from_slice(&body).map_err(|e| error(400, &format!("bad request: {e}")))
}

fn validate(r: &Rule) -> Result<(), String> {
    if r.path.trim().is_empty() || r.path.len() > 1024 || r.path.chars().any(|c| c.is_control()) {
        return Err("invalid path".into());
    }
    if r.blocks_any() && !r.path.contains(['\\', '/']) {
        return Err(format!(
            "cannot block \"{}\": blocking needs a full executable path",
            r.path
        ));
    }
    for v in [r.up_limit, r.down_limit].into_iter().flatten() {
        if v == 0 {
            return Err("a limit of 0 is a block; use block instead".into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_query() {
        assert_eq!(
            query_param(
                "/api/connections?app=c%3A%5Cprogram%20files%5Cx.exe&y=1",
                "app"
            )
            .as_deref(),
            Some(r"c:\program files\x.exe")
        );
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("%zz"), "%zz");
    }
}
