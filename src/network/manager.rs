//! Proxy lifecycle and network configuration.

use super::proxy::{Policy, Refusals, Rule};
use crate::error::{Result, SandboxError};
use crate::network::HttpProxy;
use crate::result::NetworkRefusal;
use std::sync::{Arc, mpsc};
use std::thread::JoinHandle;

/// The port the proxy listens on inside a Linux sandbox's own network
/// namespace, where nothing else is: any port is free there.
#[cfg(target_os = "linux")]
pub(crate) const SANDBOX_PROXY_PORT: u16 = 3128;

/// The proxy for a sandbox's `allow_network`: a runtime on its own thread, serving each run
/// on a per-run listener (see `attach`). Nothing listens between runs.
pub struct ProxiedNetwork {
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<JoinHandle<()>>,
    runtime: tokio::runtime::Handle,
    policy: Arc<Policy>,
}

/// Serves one run's listener; dropping it (or `finish`) closes the listener
/// and cuts the run's connections that are still open.
pub(crate) struct Attachment {
    _stop: tokio::sync::oneshot::Sender<()>,
    refusals: Arc<Refusals>,
}

impl Attachment {
    /// Stops serving the run, and returns what the proxy didn't connect it to.
    pub(crate) fn finish(self) -> Vec<NetworkRefusal> {
        self.refusals.list()
    }
}

/// What `allow_network` and its companions asked for.
#[derive(Clone, Debug, Default)]
pub struct ProxyRules {
    /// `allow_network` entries.
    pub allowed: Vec<String>,
    /// `deny_network` entries, each with its reason if one was given.
    pub denied: Vec<(String, Option<String>)>,
    pub allow_private_destinations: bool,
    pub require_host_match: bool,
}

impl ProxyRules {
    /// The first entry that can't work, if any: which list, the entry and why.
    pub(crate) fn invalid_entry(&self) -> Option<(&'static str, &str, &'static str)> {
        let allowed = self.allowed.iter().map(|e| ("allow_network", e.as_str()));
        let denied = self
            .denied
            .iter()
            .map(|(e, _)| ("deny_network", e.as_str()));
        allowed
            .chain(denied)
            .find_map(|(list, entry)| Rule::parse(entry).err().map(|why| (list, entry, why)))
    }
}

impl ProxiedNetwork {
    /// Start the proxy for `rules`.
    pub fn setup(rules: ProxyRules) -> Result<Self> {
        if let Some((list, entry, why)) = rules.invalid_entry() {
            return Err(crate::error::SandboxError::Config {
                context: format!("{list} entry {entry:?}: {why}"),
                source: None,
            });
        }
        let policy = HttpProxy::new(rules.allowed, 0)
            .deny(rules.denied)
            .allow_private_destinations(rules.allow_private_destinations)
            .require_host_match(rules.require_host_match)
            .policy();
        let (runtime_tx, runtime_rx) = mpsc::channel::<std::io::Result<tokio::runtime::Handle>>();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        // // Built and dropped on this dedicated thread: dropping a `Runtime` inside another async
        // // context panics.
        let thread = std::thread::Builder::new()
            .name("nanosandbox-proxy".into())
            .spawn(move || {
                let rt = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        let _ = runtime_tx.send(Err(e));
                        return;
                    }
                };
                let _ = runtime_tx.send(Ok(rt.handle().clone()));
                rt.block_on(async move {
                    let _ = shutdown_rx.await;
                });
            })
            .map_err(|e| SandboxError::Internal {
                context: "Failed to spawn proxy thread".into(),
                source: Box::new(e),
            })?;

        let runtime = runtime_rx
            .recv()
            .map_err(|e| SandboxError::Internal {
                context: "proxy thread went away".into(),
                source: Box::new(e),
            })?
            .map_err(|e| SandboxError::Internal {
                context: "Failed to create proxy runtime".into(),
                source: Box::new(e),
            })?;

        Ok(Self {
            shutdown_tx: Some(shutdown_tx),
            thread: Some(thread),
            runtime,
            policy,
        })
    }

    /// Serves the proxy on one run's `listener` until the `Attachment` is dropped or finished.
    /// Linux: bound in the sandbox's own netns; macOS: loopback, the only place the profile
    /// allows. Connections go out from this process's network either way.
    pub(crate) fn attach(&self, listener: std::net::TcpListener) -> std::io::Result<Attachment> {
        listener.set_nonblocking(true)?;
        let listener = {
            let _runtime = self.runtime.enter();
            tokio::net::TcpListener::from_std(listener)?
        };
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let stop = async move {
            let _ = stop_rx.await;
        };
        let refusals = Arc::new(Refusals::default());
        self.runtime.spawn(HttpProxy::serve(
            listener,
            Arc::clone(&self.policy),
            Arc::clone(&refusals),
            stop,
        ));
        Ok(Attachment {
            _stop: stop_tx,
            refusals,
        })
    }

    /// The environment variables pointing a run's programs to its proxy listener on `port`:
    /// HTTP for `HTTP_PROXY`/`HTTPS_PROXY`, SOCKS5 (names resolved by the proxy) for
    /// `ALL_PROXY`, which libcurl, Go's `x/net/proxy` and others use for everything else.
    pub fn env_vars(port: u16) -> Vec<(String, String)> {
        let http = format!("http://127.0.0.1:{port}");
        let socks = format!("socks5h://127.0.0.1:{port}");
        ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"]
            .into_iter()
            .map(|key| (key.to_string(), http.clone()))
            .chain(
                ["ALL_PROXY", "all_proxy"]
                    .into_iter()
                    .map(|key| (key.to_string(), socks.clone())),
            )
            .collect()
    }

    /// [`env_vars`](Self::env_vars), plus `NO_PROXY` for loopback unless
    /// `allow_private_destinations` is on (the proxy would 403 a program's own `127.0.0.1`
    /// server). With it on, loopback must go through the proxy to reach the host's services.
    pub fn env_vars_for(port: u16, allow_private_destinations: bool) -> Vec<(String, String)> {
        let mut vars = Self::env_vars(port);
        if !allow_private_destinations {
            vars.extend(
                ["NO_PROXY", "no_proxy"]
                    .into_iter()
                    .map(|key| (key.to_string(), "localhost,127.0.0.1,::1".to_string())),
            );
        }
        vars
    }

    /// Shutdown the proxy
    pub fn shutdown(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

impl Drop for ProxiedNetwork {
    fn drop(&mut self) {
        self.shutdown();
        // // Blocks until the runtime thread exits.
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_env_vars() {
        let vars = ProxiedNetwork::env_vars(3128);
        assert_eq!(vars.len(), 6);
        for key in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
            assert!(
                vars.iter()
                    .any(|(k, v)| k == key && v == "http://127.0.0.1:3128")
            );
        }
        for key in ["ALL_PROXY", "all_proxy"] {
            assert!(
                vars.iter()
                    .any(|(k, v)| k == key && v == "socks5h://127.0.0.1:3128")
            );
        }
    }

    #[test]
    fn test_loopback_bypasses_the_proxy_unless_private_destinations_are_allowed() {
        let vars = ProxiedNetwork::env_vars_for(3128, false);
        assert_eq!(vars.len(), 8);
        for key in ["NO_PROXY", "no_proxy"] {
            let (_, v) = vars.iter().find(|(k, _)| k == key).unwrap();
            for host in ["localhost", "127.0.0.1", "::1"] {
                assert!(v.split(',').any(|h| h == host), "{key}={v}");
            }
        }

        // // Allowed on purpose: loopback reaches the host's services via the proxy.
        let vars = ProxiedNetwork::env_vars_for(3128, true);
        assert_eq!(vars.len(), 6);
        assert!(!vars.iter().any(|(k, _)| k.eq_ignore_ascii_case("no_proxy")));
    }

    /// A run's listener is served until its attachment finishes, and only
    /// that run's refusals come back.
    #[test]
    fn test_attach_serves_one_run() {
        use std::io::{Read, Write};
        let network = ProxiedNetwork::setup(ProxyRules {
            allowed: vec!["example.com".into()],
            ..Default::default()
        })
        .unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let attachment = network.attach(listener).unwrap();

        let mut client = std::net::TcpStream::connect(addr).unwrap();
        client
            .write_all(b"CONNECT evil.example:443 HTTP/1.1\r\n\r\n")
            .unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        assert!(response.starts_with("HTTP/1.1 403"), "{response}");

        let refusals = attachment.finish();
        assert_eq!(refusals.len(), 1);
        assert_eq!(
            (
                refusals[0].host.as_str(),
                refusals[0].port,
                refusals[0].reason.code()
            ),
            ("evil.example", 443, "not-allowed")
        );
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert!(std::net::TcpStream::connect(addr).is_err());
    }
}
