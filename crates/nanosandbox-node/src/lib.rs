//! Node.js bindings for nanosandbox, built with napi-rs.
//!
//! Mirrors `nanosandbox::SandboxBuilder`/`Sandbox`/`ExecutionResult`; see the Rust docs.
//! Setters take the wrapped builder out of its `Option` and return a new wrapper so JS chains.

#![deny(clippy::all)]

use napi::Error;
use napi::bindgen_prelude::AsyncTask;
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

fn invalid_arg(message: String) -> Error {
    Error::new(napi::Status::InvalidArg, message)
}

/// Longest accepted time limit: a year. Keeps `Instant + Duration` far from overflow.
const MAX_LIMIT_SECS: f64 = 365.0 * 86_400.0;

/// JS gives every number as f64; `Duration::from_secs_f64` panics (and aborts Node) on
/// negative, NaN, infinite or huge input.
fn time_limit(name: &str, value: f64) -> napi::Result<Duration> {
    if !(value.is_finite() && value > 0.0) {
        return Err(invalid_arg(format!(
            "{name} must be a positive number of seconds, got {value}"
        )));
    }
    if value > MAX_LIMIT_SECS {
        return Err(invalid_arg(format!(
            "{name} must be at most {MAX_LIMIT_SECS} seconds (a year), got {value}"
        )));
    }
    Duration::try_from_secs_f64(value).map_err(|e| invalid_arg(format!("{name}: {e}")))
}

/// `f64 as u64` saturates: -1 or NaN would silently become 0. Reject anything that is
/// not a non-negative integer JS can represent exactly.
fn whole(name: &str, value: f64) -> napi::Result<u64> {
    const MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0; // 2^53 - 1
    if !value.is_finite() || value < 0.0 || value.fract() != 0.0 || value > MAX_SAFE_INTEGER {
        return Err(invalid_arg(format!(
            "{name} must be a non-negative integer up to 2^53 - 1, got {value}"
        )));
    }
    Ok(value as u64)
}

fn whole_u32(name: &str, value: f64) -> napi::Result<u32> {
    // napi's own u32 conversion wraps: -1 would read as 4294967295.
    u32::try_from(whole(name, value)?)
        .map_err(|_| invalid_arg(format!("{name} must be at most {}, got {value}", u32::MAX)))
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

impl Default for SandboxBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[napi]
impl SandboxBuilder {
    #[napi(constructor)]
    pub fn new() -> Self {
        Self::wrap(nanosandbox::Sandbox::builder())
    }

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
        let size_bytes = whole("privateTmp size", size_bytes)?;
        Ok(Self::wrap(self.take()?.private_tmp(size_bytes)))
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

    #[napi]
    pub fn memory_limit(&mut self, bytes: f64) -> napi::Result<SandboxBuilder> {
        let bytes = whole("memoryLimit", bytes)?;
        Ok(Self::wrap(self.take()?.memory_limit(bytes)))
    }

    #[napi]
    pub fn cpu_limit(&mut self, cpus: f64) -> napi::Result<SandboxBuilder> {
        Ok(Self::wrap(self.take()?.cpu_limit(cpus)))
    }

    #[napi]
    pub fn wall_time_limit(&mut self, seconds: f64) -> napi::Result<SandboxBuilder> {
        let limit = time_limit("wallTimeLimit", seconds)?;
        Ok(Self::wrap(self.take()?.wall_time_limit(limit)))
    }

    #[napi]
    pub fn cpu_time_limit(&mut self, seconds: f64) -> napi::Result<SandboxBuilder> {
        let limit = time_limit("cpuTimeLimit", seconds)?;
        Ok(Self::wrap(self.take()?.cpu_time_limit(limit)))
    }

    #[napi]
    pub fn max_pids(&mut self, n: f64) -> napi::Result<SandboxBuilder> {
        let n = whole_u32("maxPids", n)?;
        Ok(Self::wrap(self.take()?.max_pids(n)))
    }

    #[napi]
    pub fn max_file_size(&mut self, bytes: f64) -> napi::Result<SandboxBuilder> {
        let bytes = whole("maxFileSize", bytes)?;
        Ok(Self::wrap(self.take()?.max_file_size(bytes)))
    }

    #[napi]
    pub fn max_open_files(&mut self, n: f64) -> napi::Result<SandboxBuilder> {
        let n = whole_u32("maxOpenFiles", n)?;
        Ok(Self::wrap(self.take()?.max_open_files(n)))
    }

    #[napi]
    pub fn max_output(&mut self, bytes: f64) -> napi::Result<SandboxBuilder> {
        let bytes = whole("maxOutput", bytes)?;
        Ok(Self::wrap(self.take()?.max_output(bytes)))
    }

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

    #[napi]
    pub fn deny_network(&mut self, entries: Vec<String>) -> napi::Result<SandboxBuilder> {
        let refs: Vec<&str> = entries.iter().map(String::as_str).collect();
        Ok(Self::wrap(self.take()?.deny_network(&refs)))
    }

    #[napi]
    pub fn deny_network_with_reason(
        &mut self,
        entry: String,
        reason: String,
    ) -> napi::Result<SandboxBuilder> {
        Ok(Self::wrap(
            self.take()?.deny_network_with_reason(&entry, &reason),
        ))
    }

    #[napi]
    pub fn require_host_match(&mut self) -> napi::Result<SandboxBuilder> {
        Ok(Self::wrap(self.take()?.require_host_match()))
    }

    #[napi]
    pub fn allow_trustd(&mut self) -> napi::Result<SandboxBuilder> {
        Ok(Self::wrap(self.take()?.allow_trustd()))
    }

    #[napi]
    pub fn report_denials(&mut self) -> napi::Result<SandboxBuilder> {
        Ok(Self::wrap(self.take()?.report_denials()))
    }

    #[napi]
    pub fn env(&mut self, key: String, value: String) -> napi::Result<SandboxBuilder> {
        Ok(Self::wrap(self.take()?.env(key, value)))
    }

    #[napi]
    pub fn clear_env(&mut self, clear: bool) -> napi::Result<SandboxBuilder> {
        Ok(Self::wrap(self.take()?.clear_env(clear)))
    }

    #[napi]
    pub fn build(&mut self) -> napi::Result<Sandbox> {
        let inner = self.take()?.build().map_err(to_napi_err)?;
        Ok(Sandbox {
            inner: std::sync::Arc::new(inner),
        })
    }
}

/// Linux-only methods, in a separate `impl`: `#[napi]` expands before per-method `cfg` stripping.
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
        Ok(Self::wrap(self.take()?.bind(
            source,
            target,
            permission.into(),
        )))
    }

    #[napi]
    pub fn tmpfs(&mut self, path: String, size_bytes: f64) -> napi::Result<SandboxBuilder> {
        let size_bytes = whole("tmpfs size", size_bytes)?;
        Ok(Self::wrap(self.take()?.tmpfs(path, size_bytes)))
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
    pub fn uid(&mut self, uid: f64) -> napi::Result<SandboxBuilder> {
        let uid = whole_u32("uid", uid)?;
        Ok(Self::wrap(self.take()?.uid(uid)))
    }

    #[napi]
    pub fn gid(&mut self, gid: f64) -> napi::Result<SandboxBuilder> {
        let gid = whole_u32("gid", gid)?;
        Ok(Self::wrap(self.take()?.gid(gid)))
    }

    #[napi]
    pub fn host_uid(&mut self, uid: f64) -> napi::Result<SandboxBuilder> {
        let uid = whole_u32("hostUid", uid)?;
        Ok(Self::wrap(self.take()?.host_uid(uid)))
    }

    #[napi]
    pub fn host_gid(&mut self, gid: f64) -> napi::Result<SandboxBuilder> {
        let gid = whole_u32("hostGid", gid)?;
        Ok(Self::wrap(self.take()?.host_gid(gid)))
    }

    #[napi]
    pub fn hostname(&mut self, name: String) -> napi::Result<SandboxBuilder> {
        Ok(Self::wrap(self.take()?.hostname(name)))
    }
}

/// macOS-only methods; separate block for the same reason.
#[cfg(target_os = "macos")]
#[napi]
impl SandboxBuilder {
    /// Whether the host's /tmp and other system temp dirs stay writable; `false` leaves only private `$TMPDIR`.
    #[napi]
    pub fn shared_tmp(&mut self, shared: bool) -> napi::Result<SandboxBuilder> {
        Ok(Self::wrap(self.take()?.shared_tmp(shared)))
    }
}

/// See `nanosandbox::Sandbox`.
#[napi]
pub struct Sandbox {
    inner: std::sync::Arc<nanosandbox::Sandbox>,
}

/// A run on libuv's thread pool; sync `run` would freeze the event loop.
pub struct RunTask {
    sandbox: std::sync::Arc<nanosandbox::Sandbox>,
    cmd: String,
    args: Vec<String>,
    stdin: Option<Vec<u8>>,
}

impl napi::Task for RunTask {
    type Output = nanosandbox::ExecutionResult;
    type JsValue = ExecutionResult;

    fn compute(&mut self) -> napi::Result<Self::Output> {
        let args: Vec<&str> = self.args.iter().map(String::as_str).collect();
        self.sandbox
            .run_with_input(&self.cmd, &args, self.stdin.as_deref())
            .map_err(to_napi_err)
    }

    fn resolve(&mut self, _env: napi::Env, output: Self::Output) -> napi::Result<Self::JsValue> {
        Ok(ExecutionResult { inner: output })
    }
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

    /// Like `run`, but returns a Promise. Uses libuv's pool (4 threads, `UV_THREADPOOL_SIZE`); extra runs queue.
    #[napi(ts_return_type = "Promise<ExecutionResult>")]
    pub fn run_async(&self, cmd: String, args: Vec<String>) -> AsyncTask<RunTask> {
        self.run_with_input_async(cmd, args, None)
    }

    /// Like `runWithInput`, but returns a Promise; see `runAsync`.
    #[napi(ts_return_type = "Promise<ExecutionResult>")]
    pub fn run_with_input_async(
        &self,
        cmd: String,
        args: Vec<String>,
        stdin: Option<napi::bindgen_prelude::Buffer>,
    ) -> AsyncTask<RunTask> {
        AsyncTask::new(RunTask {
            sandbox: self.inner.clone(),
            cmd,
            args,
            stdin: stdin.map(|b| b.to_vec()),
        })
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

/// One `ExecutionResult.networkRefusals` entry: `reason` is the code the program saw in
/// `X-Proxy-Error`; `detail` is a deny entry's reason.
#[napi(object)]
pub struct NetworkRefusal {
    pub host: String,
    pub port: u16,
    pub reason: String,
    pub detail: Option<String>,
    pub attempts: u32,
}

/// One `ExecutionResult.deniedPaths` entry (with `reportDenials`).
#[napi(object)]
pub struct DeniedPath {
    pub path: String,
    pub operation: String,
    pub count: u32,
}

/// See `nanosandbox::ExecutionResult`; `success`/`failureReason` call the core methods.
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

    #[napi(getter)]
    pub fn denied_paths(&self) -> Vec<DeniedPath> {
        self.inner
            .denied_paths
            .iter()
            .map(|d| DeniedPath {
                path: d.path.to_string_lossy().into_owned(),
                operation: d.operation.clone(),
                count: d.count,
            })
            .collect()
    }

    #[napi(getter)]
    pub fn network_refusals(&self) -> Vec<NetworkRefusal> {
        self.inner
            .network_refusals
            .iter()
            .map(|r| NetworkRefusal {
                host: r.host.clone(),
                port: r.port,
                reason: r.reason.code().to_string(),
                detail: match &r.reason {
                    nanosandbox::RefusalReason::Denied(why) => why.clone(),
                    _ => None,
                },
                attempts: r.attempts,
            })
            .collect()
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
