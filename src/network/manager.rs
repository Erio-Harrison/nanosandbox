//! ProxiedNetwork manager
//!
//! Manages the lifecycle of the HTTP proxy and network configuration.

use super::proxy::{Blocked, Policy};
use crate::error::{Result, SandboxError};
use crate::network::HttpProxy;
use std::sync::{Arc, mpsc};
use std::thread::JoinHandle;

/// The port the proxy listens on inside a Linux sandbox's own network
/// namespace, where nothing else is: any port is free there.
#[cfg(target_os = "linux")]
pub(crate) const SANDBOX_PROXY_PORT: u16 = 3128;

/// The proxy for a sandbox's `allow_network`: a runtime on a thread of its
/// own, which serves each run on a listener of that run's (see `attach`).
/// Nothing listens between runs.
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
    blocked: Arc<Blocked>,
}

impl Attachment {
    /// Stops serving the run, and returns the hosts the proxy refused it.
    pub(crate) fn finish(self) -> Vec<String> {
        self.blocked.hosts()
    }
}

impl ProxiedNetwork {
    /// Setup proxied network for a sandbox
    ///
    /// # Arguments
    ///
    /// * `allowed_domains` - List of domains to allow access to
    /// * `allow_private_destinations` - Whether those may resolve to
    ///   loopback, private, link-local and other non-public addresses
    pub fn setup(allowed_domains: Vec<String>, allow_private_destinations: bool) -> Result<Self> {
        let policy = HttpProxy::new(allowed_domains, 0)
            .allow_private_destinations(allow_private_destinations)
            .policy();
        let (runtime_tx, runtime_rx) = mpsc::channel::<std::io::Result<tokio::runtime::Handle>>();
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        // The runtime is built and dropped entirely on this dedicated OS thread,
        // so it never nests inside whatever runtime the caller happens to be on.
        // Dropping a `Runtime` from within another async context panics:
        // https://docs.rs/tokio/latest/tokio/runtime/struct.Runtime.html#shutdown
        // The "spawn a runtime, talk to it over a channel" pattern is documented at
        // https://tokio.rs/tokio/topics/bridging
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
                // Runs the runs' connections until shutdown.
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

    /// Serves the proxy on `listener`, one run's, until the returned
    /// `Attachment` is dropped or finished. On Linux the listener is bound
    /// inside the sandbox's own network namespace, where the sandbox can
    /// reach it but nothing else; on macOS it's on loopback, the only place
    /// the sandbox profile lets the run connect to. Connections made on the
    /// sandbox's behalf go out from this process's network either way.
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
        let blocked = Arc::new(Blocked::default());
        self.runtime.spawn(HttpProxy::serve(
            listener,
            Arc::clone(&self.policy),
            Arc::clone(&blocked),
            stop,
        ));
        Ok(Attachment {
            _stop: stop_tx,
            blocked,
        })
    }

    /// The environment variables pointing a run's programs to its proxy
    /// listener on `port`.
    pub fn env_vars(port: u16) -> Vec<(String, String)> {
        let url = format!("http://127.0.0.1:{port}");
        ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"]
            .into_iter()
            .map(|key| (key.to_string(), url.clone()))
            .collect()
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
        // Blocks briefly until the runtime's thread exits -- consistent with
        // the rest of the crate, which is blocking end-to-end.
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
        assert_eq!(vars.len(), 4);
        for key in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
            assert!(
                vars.iter()
                    .any(|(k, v)| k == key && v == "http://127.0.0.1:3128")
            );
        }
    }

    /// A run's listener is served until its attachment finishes, and only
    /// that run's refusals come back.
    #[test]
    fn test_attach_serves_one_run() {
        use std::io::{Read, Write};
        let network = ProxiedNetwork::setup(vec!["example.com".into()], false).unwrap();
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

        assert_eq!(attachment.finish(), vec!["evil.example"]);
        // Closed with the run: nothing listens there any more.
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert!(std::net::TcpStream::connect(addr).is_err());
    }
}
