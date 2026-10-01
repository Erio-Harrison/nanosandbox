//! ProxiedNetwork manager
//!
//! Manages the lifecycle of the HTTP proxy and network configuration.

use crate::error::{Result, SandboxError};
use crate::network::HttpProxy;
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::Duration;
use tokio::sync::watch;

/// Manages proxied network access for a sandbox
pub struct ProxiedNetwork {
    proxy_port: u16,
    proxy_url: String,
    shutdown_tx: watch::Sender<bool>,
    thread: Option<JoinHandle<()>>,
    /// The proxy thread's runtime and whitelist, for `attach`.
    #[cfg(target_os = "linux")]
    runtime: tokio::runtime::Handle,
    #[cfg(target_os = "linux")]
    allowed: std::sync::Arc<std::collections::HashSet<String>>,
}

/// Keeps serving an attached listener; dropping it stops that and closes
/// the listener.
#[cfg(target_os = "linux")]
pub(crate) struct Attachment {
    _stop: tokio::sync::oneshot::Sender<()>,
}

impl ProxiedNetwork {
    /// Setup proxied network for a sandbox
    ///
    /// # Arguments
    ///
    /// * `allowed_domains` - List of domains to allow access to
    ///
    /// # Returns
    ///
    /// A `ProxiedNetwork` instance that manages the proxy lifecycle
    pub fn setup(allowed_domains: Vec<String>) -> Result<Self> {
        // Create shutdown channel
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        // Carries the real bind result (address or error) from inside proxy.run(),
        // which binds exactly once — see HttpProxy::run's `bound` parameter. There
        // is no separate "reserve a port, then bind it again" step, so there is no
        // window for another process to grab the port in between.
        let (bound_tx, bound_rx) = mpsc::channel::<std::io::Result<std::net::SocketAddr>>();
        let proxy = HttpProxy::new(allowed_domains, 0);
        #[cfg(target_os = "linux")]
        let allowed = proxy.allowed_domains();
        #[cfg(target_os = "linux")]
        let (runtime_tx, runtime_rx) = mpsc::channel::<tokio::runtime::Handle>();

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
                        tracing::error!("Failed to create proxy runtime: {e}");
                        let _ = bound_tx.send(Err(std::io::Error::other(e)));
                        return;
                    }
                };
                #[cfg(target_os = "linux")]
                let _ = runtime_tx.send(rt.handle().clone());
                rt.block_on(async move {
                    // Port 0 (see `proxy` above): ask the OS for any free
                    // ephemeral port, reported back once run() has bound it.
                    if let Err(e) = proxy.run(shutdown_rx, Some(bound_tx)).await {
                        tracing::error!("Proxy error: {e}");
                    }
                });
            })
            .map_err(|e| SandboxError::Internal(format!("Failed to spawn proxy thread: {e}")))?;

        let proxy_port = match bound_rx.recv_timeout(Duration::from_secs(3)) {
            Ok(Ok(addr)) => addr.port(),
            Ok(Err(e)) => {
                let _ = thread.join();
                return Err(SandboxError::Internal(format!("proxy failed to bind: {e}")));
            }
            Err(_) => {
                let _ = shutdown_tx.send(true);
                let _ = thread.join();
                return Err(SandboxError::Internal(
                    "proxy did not start within 3s".into(),
                ));
            }
        };

        Ok(Self {
            proxy_port,
            proxy_url: format!("http://127.0.0.1:{proxy_port}"),
            shutdown_tx,
            thread: Some(thread),
            // Sent before run() binds, so it's here once bound_rx said so.
            #[cfg(target_os = "linux")]
            runtime: runtime_rx
                .recv()
                .map_err(|_| SandboxError::Internal("proxy runtime went away".into()))?,
            #[cfg(target_os = "linux")]
            allowed,
        })
    }

    /// Also serves the proxy on `listener` -- one bound inside a sandbox's
    /// own network namespace, where the sandbox can reach it but nothing
    /// else -- until the returned `Attachment` is dropped. Connections made
    /// on the sandbox's behalf still go out from this process's network.
    #[cfg(target_os = "linux")]
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
        self.runtime
            .spawn(HttpProxy::serve(listener, self.allowed.clone(), stop));
        Ok(Attachment { _stop: stop_tx })
    }

    /// Get the proxy port
    pub fn port(&self) -> u16 {
        self.proxy_port
    }

    /// Get the proxy URL
    pub fn url(&self) -> &str {
        &self.proxy_url
    }

    /// Get environment variables for the proxy
    ///
    /// Returns a list of (key, value) pairs to set in the sandbox environment
    pub fn env_vars(&self) -> Vec<(String, String)> {
        vec![
            ("HTTP_PROXY".into(), self.proxy_url.clone()),
            ("HTTPS_PROXY".into(), self.proxy_url.clone()),
            ("http_proxy".into(), self.proxy_url.clone()),
            ("https_proxy".into(), self.proxy_url.clone()),
        ]
    }

    /// Shutdown the proxy
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }
}

impl Drop for ProxiedNetwork {
    fn drop(&mut self) {
        self.shutdown();
        // Blocks briefly until the proxy's accept loop observes the shutdown
        // signal and the thread exits — consistent with the rest of the crate,
        // which is blocking end-to-end.
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
        let network = ProxiedNetwork::setup(vec!["example.com".into()]).unwrap();
        let vars = network.env_vars();

        assert_eq!(vars.len(), 4);
        assert!(vars.iter().any(|(k, _)| k == "HTTP_PROXY"));
        assert!(vars.iter().any(|(k, _)| k == "HTTPS_PROXY"));
        assert!(vars.iter().any(|(k, _)| k == "http_proxy"));
        assert!(vars.iter().any(|(k, _)| k == "https_proxy"));

        // Cleanup
        network.shutdown();
    }
}
