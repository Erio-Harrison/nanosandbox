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
        Err(e) => die(&e),
    };
    if cfg!(windows) {
        die(
            "Windows is not supported yet: the sandbox there is a resource limiter, not a security boundary",
        );
    }
    // Refuses here, not on the first call, anything this platform can't
    // enforce (see nanosandbox's `build()`).
    let sandbox = cfg.build().unwrap_or_else(|e| die(&e));

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
        let Ok(line) = line else { break };
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
    // Stdin closed: the client is shutting us down. Exit now rather than
    // wait on running commands; a sandbox dies with its host process.
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
