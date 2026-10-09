//! Node.js bindings for nanosandbox, built with napi-rs.
//!
//! Mirrors `nanosandbox::SandboxBuilder`/`Sandbox`/`ExecutionResult` method
//! for method; see the Rust crate's docs for behavior. Builder setters
//! consume `self` in Rust, so each one here takes the wrapped builder out of
//! `Option` and hands back a new wrapper -- that's what makes
//! `Sandbox.builder().readOnly(...).memoryLimit(...)` chain in JS too.

#![deny(clippy::all)]

use napi::Error;
use napi_derive::napi;
use std::time::Duration;

fn to_napi_err(e: nanosandbox::SandboxError) -> Error {
    Error::from_reason(e.to_string())
}

fn builder_consumed() -> Error {
    Error::from_reason(
        "this builder was already consumed by build() (or another chained call that didn't keep its return value)",
    )
}

/// Read-only or read-write, for [`SandboxBuilder.bind`]. Linux only.
#[cfg(target_os = "linux")]
#[napi(string_enum)]
pub enum Permission {
    ReadOnly,
    ReadWrite,
}

#[cfg(target_os = "linux")]
impl From<Permission> for nanosandbox::Permission {
    fn from(p: Permission) -> Self {
        match p {
            Permission::ReadOnly => nanosandbox::Permission::ReadOnly,
            Permission::ReadWrite => nanosandbox::Permission::ReadWrite,
        }
    }
}

/// Sandbox builder with a fluent API; see `nanosandbox::SandboxBuilder`.
#[napi]
pub struct SandboxBuilder {
    inner: Option<nanosandbox::SandboxBuilder>,
}

impl SandboxBuilder {
    fn wrap(inner: nanosandbox::SandboxBuilder) -> Self {
        Self { inner: Some(inner) }
    }

    fn take(&mut self) -> napi::Result<nanosandbox::SandboxBuilder> {
        self.inner.take().ok_or_else(builder_consumed)
    }
}

#[napi]
impl SandboxBuilder {
    #[napi(constructor)]
    pub fn new() -> Self {
        Self::wrap(nanosandbox::Sandbox::builder())
    }

    // ===== Filesystem =====

    #[napi]
    pub fn read_only(&mut self, path: String) -> napi::Result<SandboxBuilder> {
        Ok(Self::wrap(self.take()?.read_only(path)))
    }

    #[napi]
    pub fn writable(&mut self, path: String) -> napi::Result<SandboxBuilder> {
        Ok(Self::wrap(self.take()?.writable(path)))
    }

    #[napi]
    pub fn private_tmp(&mut self, size_bytes: f64) -> napi::Result<SandboxBuilder> {
        Ok(Self::wrap(self.take()?.private_tmp(size_bytes as u64)))
    }

    #[napi]
    pub fn no_private_tmp(&mut self) -> napi::Result<SandboxBuilder> {
        Ok(Self::wrap(self.take()?.no_private_tmp()))
    }

    #[napi]
    pub fn deny_read(&mut self, path: String) -> napi::Result<SandboxBuilder> {
        Ok(Self::wrap(self.take()?.deny_read(path)))
    }

    #[napi]
    pub fn hide_home(&mut self) -> napi::Result<SandboxBuilder> {
        Ok(Self::wrap(self.take()?.hide_home()))
    }

    #[napi]
    pub fn working_dir(&mut self, path: String) -> napi::Result<SandboxBuilder> {
        Ok(Self::wrap(self.take()?.working_dir(path)))
    }

    // ===== Resource limits =====

    #[napi]
    pub fn memory_limit(&mut self, bytes: f64) -> napi::Result<SandboxBuilder> {
        Ok(Self::wrap(self.take()?.memory_limit(bytes as u64)))
    }

    #[napi]
    pub fn cpu_limit(&mut self, cpus: f64) -> napi::Result<SandboxBuilder> {
        Ok(Self::wrap(self.take()?.cpu_limit(cpus)))
    }

    #[napi]
    pub fn wall_time_limit(&mut self, seconds: f64) -> napi::Result<SandboxBuilder> {
        Ok(Self::wrap(self.take()?.wall_time_limit(Duration::from_secs_f64(seconds))))
    }

    #[napi]
    pub fn cpu_time_limit(&mut self, seconds: f64) -> napi::Result<SandboxBuilder> {
        Ok(Self::wrap(self.take()?.cpu_time_limit(Duration::from_secs_f64(seconds))))
    }

    #[napi]
    pub fn max_pids(&mut self, n: u32) -> napi::Result<SandboxBuilder> {
        Ok(Self::wrap(self.take()?.max_pids(n)))
    }

    #[napi]
    pub fn max_file_size(&mut self, bytes: f64) -> napi::Result<SandboxBuilder> {
        Ok(Self::wrap(self.take()?.max_file_size(bytes as u64)))
    }

    #[napi]
    pub fn max_open_files(&mut self, n: u32) -> napi::Result<SandboxBuilder> {
        Ok(Self::wrap(self.take()?.max_open_files(n)))
    }

    #[napi]
    pub fn max_output(&mut self, bytes: f64) -> napi::Result<SandboxBuilder> {
        Ok(Self::wrap(self.take()?.max_output(bytes as u64)))
    }

    // ===== Network =====

    #[napi]
    pub fn no_network(&mut self) -> napi::Result<SandboxBuilder> {
        Ok(Self::wrap(self.take()?.no_network()))
    }

    #[napi]
    pub fn host_network(&mut self) -> napi::Result<SandboxBuilder> {
        Ok(Self::wrap(self.take()?.host_network()))
    }

    #[napi]
    pub fn allow_network(&mut self, domains: Vec<String>) -> napi::Result<SandboxBuilder> {
        let refs: Vec<&str> = domains.iter().map(String::as_str).collect();
        Ok(Self::wrap(self.take()?.allow_network(&refs)))
    }

    #[napi]
    pub fn allow_private_destinations(&mut self) -> napi::Result<SandboxBuilder> {
        Ok(Self::wrap(self.take()?.allow_private_destinations()))
    }

    // ===== Environment =====

    #[napi]
    pub fn env(&mut self, key: String, value: String) -> napi::Result<SandboxBuilder> {
        Ok(Self::wrap(self.take()?.env(key, value)))
    }

    #[napi]
    pub fn clear_env(&mut self, clear: bool) -> napi::Result<SandboxBuilder> {
        Ok(Self::wrap(self.take()?.clear_env(clear)))
    }

    // ===== Build =====

    #[napi]
    pub fn build(&mut self) -> napi::Result<Sandbox> {
        let inner = self.take()?.build().map_err(to_napi_err)?;
        Ok(Sandbox { inner })
    }
}

/// Linux-only `SandboxBuilder` methods. In a separate `impl` block (rather
/// than `#[cfg(target_os = "linux")]` on individual methods inside the main
/// one) because `#[napi]` on the surrounding block expands before per-method
/// `cfg` stripping happens, and ends up referencing the stripped methods'
/// generated callbacks anyway -- a block-level `cfg` avoids that.
#[cfg(target_os = "linux")]
#[napi]
impl SandboxBuilder {
    #[napi]
    pub fn bind(
        &mut self,
        source: String,
        target: String,
        permission: Permission,
    ) -> napi::Result<SandboxBuilder> {
        Ok(Self::wrap(self.take()?.bind(source, target, permission.into())))
    }

    #[napi]
    pub fn tmpfs(&mut self, path: String, size_bytes: f64) -> napi::Result<SandboxBuilder> {
        Ok(Self::wrap(self.take()?.tmpfs(path, size_bytes as u64)))
    }

    #[napi]
    pub fn rootfs(&mut self, path: String) -> napi::Result<SandboxBuilder> {
        Ok(Self::wrap(self.take()?.rootfs(path)))
    }

    #[napi]
    pub fn seccomp(&mut self, enabled: bool) -> napi::Result<SandboxBuilder> {
        Ok(Self::wrap(self.take()?.seccomp(enabled)))
    }

    #[napi]
    pub fn uid(&mut self, uid: u32) -> napi::Result<SandboxBuilder> {
        Ok(Self::wrap(self.take()?.uid(uid)))
    }

    #[napi]
    pub fn gid(&mut self, gid: u32) -> napi::Result<SandboxBuilder> {
        Ok(Self::wrap(self.take()?.gid(gid)))
    }

    #[napi]
    pub fn host_uid(&mut self, uid: u32) -> napi::Result<SandboxBuilder> {
        Ok(Self::wrap(self.take()?.host_uid(uid)))
    }

    #[napi]
    pub fn host_gid(&mut self, gid: u32) -> napi::Result<SandboxBuilder> {
        Ok(Self::wrap(self.take()?.host_gid(gid)))
    }

    #[napi]
    pub fn hostname(&mut self, name: String) -> napi::Result<SandboxBuilder> {
        Ok(Self::wrap(self.take()?.hostname(name)))
    }
}

/// See `nanosandbox::Sandbox`.
#[napi]
pub struct Sandbox {
    inner: nanosandbox::Sandbox,
}

#[napi]
impl Sandbox {
    #[napi]
    pub fn builder() -> SandboxBuilder {
        SandboxBuilder::new()
    }

    #[napi]
    pub fn data_analysis(input_dir: String, output_dir: String) -> SandboxBuilder {
        SandboxBuilder::wrap(nanosandbox::Sandbox::data_analysis(input_dir, output_dir))
    }

    #[napi]
    pub fn code_judge(code_dir: String) -> SandboxBuilder {
        SandboxBuilder::wrap(nanosandbox::Sandbox::code_judge(code_dir))
    }

    #[napi]
    pub fn agent_executor(workspace: String) -> SandboxBuilder {
        SandboxBuilder::wrap(nanosandbox::Sandbox::agent_executor(workspace))
    }

    #[napi]
    pub fn interactive(workspace: String) -> SandboxBuilder {
        SandboxBuilder::wrap(nanosandbox::Sandbox::interactive(workspace))
    }

    #[napi]
    pub fn run(&self, cmd: String, args: Vec<String>) -> napi::Result<ExecutionResult> {
        self.run_with_input(cmd, args, None)
    }

    #[napi]
    pub fn run_with_input(
        &self,
        cmd: String,
        args: Vec<String>,
        stdin: Option<napi::bindgen_prelude::Buffer>,
    ) -> napi::Result<ExecutionResult> {
        let args_ref: Vec<&str> = args.iter().map(String::as_str).collect();
        let stdin: Option<Vec<u8>> = stdin.map(|b| b.to_vec());
        let inner = self
            .inner
            .run_with_input(&cmd, &args_ref, stdin.as_deref())
            .map_err(to_napi_err)?;
        Ok(ExecutionResult { inner })
    }

    #[napi(getter)]
    pub fn id(&self) -> &str {
        self.inner.id()
    }

    #[napi]
    pub fn platform(&self) -> &'static str {
        self.inner.platform()
    }
}

/// See `nanosandbox::ExecutionResult`. Getters read straight from the real
/// Rust value, and `success`/`failureReason` call its own methods, so this
/// can't drift from the core crate's definition of either.
#[napi]
pub struct ExecutionResult {
    inner: nanosandbox::ExecutionResult,
}

#[napi]
impl ExecutionResult {
    #[napi(getter)]
    pub fn stdout(&self) -> &str {
        &self.inner.stdout
    }

    #[napi(getter)]
    pub fn stderr(&self) -> &str {
        &self.inner.stderr
    }

    #[napi(getter)]
    pub fn exit_code(&self) -> i32 {
        self.inner.exit_code
    }

    #[napi(getter)]
    pub fn wall_time_seconds(&self) -> f64 {
        self.inner.duration.as_secs_f64()
    }

    #[napi(getter)]
    pub fn cpu_time_seconds(&self) -> Option<f64> {
        self.inner.cpu_time.map(|d| d.as_secs_f64())
    }

    #[napi(getter)]
    pub fn peak_memory_bytes(&self) -> Option<f64> {
        self.inner.peak_memory.map(|b| b as f64)
    }

    #[napi(getter)]
    pub fn killed_by_timeout(&self) -> bool {
        self.inner.killed_by_timeout
    }

    #[napi(getter)]
    pub fn killed_by_oom(&self) -> bool {
        self.inner.killed_by_oom
    }

    #[napi(getter)]
    pub fn killed_by_tmp_limit(&self) -> bool {
        self.inner.killed_by_tmp_limit
    }

    #[napi(getter)]
    pub fn killed_by_cpu_limit(&self) -> bool {
        self.inner.killed_by_cpu_limit
    }

    #[napi(getter)]
    pub fn output_truncated(&self) -> bool {
        self.inner.output_truncated
    }

    #[napi(getter)]
    pub fn proc_isolated(&self) -> bool {
        self.inner.proc_isolated
    }

    #[napi(getter)]
    pub fn signal(&self) -> Option<i32> {
        self.inner.signal
    }

    #[napi(getter)]
    pub fn blocked_hosts(&self) -> Vec<String> {
        self.inner.blocked_hosts.clone()
    }

    #[napi]
    pub fn success(&self) -> bool {
        self.inner.success()
    }

    #[napi]
    pub fn failure_reason(&self) -> Option<String> {
        self.inner.failure_reason()
    }
}

#[napi]
pub fn is_platform_supported() -> bool {
    nanosandbox::is_platform_supported()
}

#[napi]
pub fn platform_name() -> &'static str {
    nanosandbox::platform_name()
}

#[napi]
pub const KB: f64 = 1024.0;
#[napi]
pub const MB: f64 = 1024.0 * 1024.0;
#[napi]
pub const GB: f64 = 1024.0 * 1024.0 * 1024.0;
