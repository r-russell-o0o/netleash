//! NetLeash — a small, auditable per-application network monitor, blocker and
//! upload/download limiter for Windows. Monitoring and blocking use only
//! mechanisms Windows ships with; limits use the WinDivert driver if present.

mod catalog;
mod conns;
mod demo;
mod enforce;
mod etw;
mod lan;
mod nlimport;
mod pathglob;
mod qos;
mod shaper;
mod state;
mod sys;
mod watch;
mod web;
mod wfp;
mod windivert;

use state::State;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

const DEFAULT_PORT: u16 = 5199;

struct Args {
    demo: bool,
    port: u16,
    data_dir: Option<PathBuf>,
    open: bool,
    windivert: Option<PathBuf>,
}

fn usage() -> ! {
    eprintln!(
        "usage: netleash [--demo] [--port N] [--data-dir DIR] [--windivert DIR] [--open]\n\n  \
         --demo       synthetic traffic, no Administrator needed, OS untouched\n  \
         --port N     web UI port on 127.0.0.1 (default {DEFAULT_PORT})\n  \
         --data-dir   where rules.json and usage.json live\n               \
         (default %ProgramData%\\NetLeash, or .\\demo-data with --demo)\n  \
         --windivert  folder holding WinDivert.dll and WinDivert64.sys\n               \
         (default: <exe dir>\\windivert, or the project's vendor folder)\n  \
         --open       open the UI in the default browser\n  \
         --check-windivert  test that WinDivert loads and its driver starts, then exit"
    );
    std::process::exit(2)
}

/// Diagnostic: can WinDivert be loaded, and can its driver start?
fn check_windivert(dir: Option<&std::path::Path>) -> ! {
    let api = match windivert::load(dir) {
        Ok(api) => api,
        Err(e) => {
            eprintln!("WinDivert: {e}\nsearched:");
            for c in windivert::candidates(dir) {
                eprintln!("  {}", c.display());
            }
            std::process::exit(1)
        }
    };
    println!("WinDivert.dll loaded, all functions found");
    match windivert::Handle::open(
        api,
        "true",
        windivert::LAYER_FLOW,
        0,
        windivert::FLAG_SNIFF | windivert::FLAG_RECV_ONLY,
    ) {
        Ok(_) => {
            println!("driver started OK (flow handle opened and closed)");
            std::process::exit(0)
        }
        Err(e) => {
            println!("driver: {e}");
            std::process::exit(1)
        }
    }
}

fn parse_args() -> Args {
    let mut a = Args {
        demo: false,
        port: DEFAULT_PORT,
        data_dir: None,
        open: false,
        windivert: None,
    };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--demo" => a.demo = true,
            "--open" => a.open = true,
            "--port" => {
                a.port = it
                    .next()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or_else(|| usage())
            }
            "--check-windivert" => check_windivert(a.windivert.as_deref()),
            "--windivert" => {
                a.windivert = Some(it.next().map(PathBuf::from).unwrap_or_else(|| usage()))
            }
            "--data-dir" => {
                a.data_dir = Some(it.next().map(PathBuf::from).unwrap_or_else(|| usage()))
            }
            _ => usage(),
        }
    }
    a
}

fn main() {
    let args = parse_args();
    if !args.demo && !sys::is_elevated() {
        eprintln!(
            "NetLeash needs Administrator rights to watch and control traffic.\n\
             Run it from an elevated terminal, or try `netleash --demo` to explore the UI."
        );
        std::process::exit(1);
    }
    let data_dir = args.data_dir.clone().unwrap_or_else(|| {
        if args.demo {
            PathBuf::from("demo-data")
        } else {
            PathBuf::from(std::env::var("ProgramData").unwrap_or_else(|_| r"C:\ProgramData".into()))
                .join("NetLeash")
        }
    });
    let state = Arc::new(State::new(data_dir.clone(), args.demo));
    {
        // Record panics in the log file. Deliberately not via State::log: the
        // panic may have happened while its lock was held.
        let log = data_dir.join("netleash.log");
        let default = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            state::append_log(
                &log,
                &format!(
                    "{} {} PANIC: {info}",
                    sys::local_date(),
                    sys::local_time_hms()
                ),
            );
            default(info);
        }));
    }
    let names = Arc::new(sys::ProcessNames::new());
    // New-program alerts. On the very first run, programs already in use are
    // learned silently for a while (NETLEASH_LEARN_SECS overrides, for tests).
    let learn = std::env::var("NETLEASH_LEARN_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(600);
    let watch = Arc::new(watch::Watch::new(
        state.data_dir(),
        Duration::from_secs(learn),
    ));
    // Monitor
    if args.demo {
        state.set_status(|s| s.monitor = "demo (synthetic traffic on real processes)".into());
        demo::spawn(state.clone(), names.clone(), watch.clone());
    } else {
        etw::stop(); // a session left behind by a previous crash
        let (st, nm, wt) = (state.clone(), names.clone(), watch.clone());
        let started = etw::start(move |ev| {
            if ev.remote.is_loopback() {
                return; // local IPC is not network traffic
            }
            let path = nm.resolve(ev.pid);
            st.record(&path, ev.pid, ev.dir, ev.bytes as u64);
            wt.observe(&path);
        });
        match started {
            Ok(()) => state.set_status(|s| s.monitor = "ok (ETW Kernel-Network)".into()),
            Err(e) => {
                state.log(format!("monitor unavailable: {e}"));
                state.set_status(|s| s.monitor = format!("error: {e}"));
            }
        }
    }

    // Enforcement: re-apply saved rules at startup.
    let enforcer = Arc::new(enforce::Enforcer::new(
        state.clone(),
        names.clone(),
        args.windivert.as_deref(),
    ));
    enforcer.apply();

    {
        let (st, en, demo) = (state.clone(), enforcer.clone(), args.demo);
        sys::on_exit(move || {
            eprintln!("shutting down, removing limits and filters...");
            if !demo {
                etw::stop();
            }
            en.shutdown();
            st.flush_usage();
        });
    }

    // One-second clock for rates; every minute, save usage and re-expand
    // wildcard rules.
    {
        let (st, en, wt) = (state.clone(), enforcer.clone(), watch.clone());
        std::thread::spawn(move || {
            let mut next = Instant::now() + Duration::from_secs(1);
            let mut n = 0u64;
            loop {
                std::thread::sleep(next.saturating_duration_since(Instant::now()));
                next += Duration::from_secs(1);
                st.tick(&sys::local_date());
                watch::process(&wt, &st, &en);
                n += 1;
                if n.is_multiple_of(60) {
                    st.flush_usage();
                    en.refresh();
                }
            }
        });
    }

    // Warm the program catalog's version-info cache in the background, so the
    // "Find programs" list opens quickly the first time.
    {
        let (st, nm, wt) = (state.clone(), names.clone(), watch.clone());
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_secs(10));
            let programs = catalog::build(&st, &nm);
            if wt.first_run {
                // Programs that already use the network are not "new".
                wt.seed(programs.iter().map(|p| p.path.as_str()));
                wt.flush();
            }
            let n = programs.len();
            st.log(format!(
                "program list ready ({n} programs that use the network)"
            ));
        });
    }

    let url = format!("http://127.0.0.1:{}/", args.port);
    state.log(format!(
        "NetLeash {} — UI at {url} (data in {})",
        if args.demo { "demo" } else { "running" },
        state.data_dir().display()
    ));
    if args.open {
        let _ = std::process::Command::new("explorer.exe").arg(&url).spawn();
    }
    if let Err(e) = web::serve(
        args.port,
        state.clone(),
        enforcer.clone(),
        names.clone(),
        watch.clone(),
    ) {
        state.log(format!(
            "exiting: {e} (is another NetLeash already running?)"
        ));
        if !args.demo {
            etw::stop();
        }
        enforcer.shutdown();
        std::process::exit(1);
    }
}
