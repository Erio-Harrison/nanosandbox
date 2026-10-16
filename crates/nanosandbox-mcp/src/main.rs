mod audit;
mod config;
mod protocol;

use protocol::{Action, Server};
use serde_json::Value;
use std::io::{BufRead, Write};
use std::sync::Arc;

fn main() {
    let cfg = match config::parse_args(std::env::args().skip(1)) {
        Ok(config::Parsed::Run(cfg)) => cfg,
        Ok(config::Parsed::Help) => {
            print!("{}", config::USAGE);
            return;
        }
        Ok(config::Parsed::Version) => {
            println!("nanosandbox-mcp {}", env!("CARGO_PKG_VERSION"));
            return;
        }
        Ok(config::Parsed::CleanTmp) => {
            #[cfg(unix)]
            println!(
                "removed {} leftover temp directories",
                nanosandbox::clean_stale_tmp()
            );
            return;
        }
        Ok(config::Parsed::AuditVerify(path)) => {
            let report = audit::verify(&path);
            for e in &report.errors {
                eprintln!("nanosandbox-mcp: {e}");
            }
            if !report.errors.is_empty() {
                std::process::exit(1);
            }
            println!(
                "ok: {} sessions ({} sealed), {} commands",
                report.sessions, report.sealed, report.runs
            );
            for n in report.notes.iter().take(10) {
                println!("note: {n}");
            }
            if report.notes.len() > 10 {
                println!("note: ... and {} more", report.notes.len() - 10);
            }
            return;
        }
        Ok(config::Parsed::AuditCleanup(dir, plan)) => {
            match audit::prune(&dir, &plan) {
                Ok(p) => {
                    let verb = if plan.dry_run {
                        "would remove"
                    } else {
                        "removed"
                    };
                    for r in &p.removed {
                        println!("{verb} {} ({} bytes)", r.session, r.bytes);
                    }
                    for u in &p.unverified {
                        println!("kept {u}: it does not verify (see --audit-verify)");
                    }
                    println!("{verb} {} sessions", p.removed.len());
                }
                Err(e) => die(&e),
            }
            return;
        }
        Err(e) => die(&e),
    };
    if cfg!(windows) {
        die(
            "Windows is not supported yet: the sandbox there is a resource limiter, not a security boundary",
        );
    }
    // Refuse here, not on the first call, what this platform can't enforce.
    let (sandbox, audit) = cfg.build().unwrap_or_else(|e| die(&e));

    if let Some(dir) = &cfg.audit_dir {
        eprintln!(
            "nanosandbox-mcp: audit: recording to {} ({})",
            dir.display(),
            cfg.audit_retention.describe()
        );
    }
    eprintln!(
        "nanosandbox-mcp {} ready on {}: {}",
        env!("CARGO_PKG_VERSION"),
        sandbox.platform(),
        cfg.summary()
    );

    let server = Arc::new(Server::new(
        sandbox,
        cfg.summary(),
        cfg.max_concurrent,
        cfg.log_io,
    ));
    for line in std::io::stdin().lock().lines() {
        let line = match line {
            Ok(line) => line,
            Err(e) => {
                eprintln!("nanosandbox-mcp: could not read stdin: {e}; exiting");
                break;
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        match server.handle_line(&line) {
            Action::Nothing => {}
            Action::Respond(v) => send(&v),
            Action::Call(call) => {
                let server = Arc::clone(&server);
                std::thread::spawn(move || {
                    if let Some(v) = server.execute_call(call) {
                        send(&v);
                    }
                });
            }
        }
    }
    // Stdin closed: exit now rather than wait on commands; running ones show in the audit record as started, never ended.
    if let Some(audit) = &audit {
        audit.close();
    }
    std::process::exit(0);
}

/// One message per line; the lock keeps concurrent replies from interleaving.
fn send(message: &Value) {
    let mut out = std::io::stdout().lock();
    if writeln!(out, "{message}")
        .and_then(|()| out.flush())
        .is_err()
    {
        std::process::exit(1);
    }
}

fn die(message: &str) -> ! {
    eprintln!("nanosandbox-mcp: {message}");
    std::process::exit(2);
}
