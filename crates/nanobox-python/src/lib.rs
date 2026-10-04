//! Python bindings for nanosandbox, built with PyO3.
//!
//! Mirrors `nanosandbox::SandboxBuilder`/`Sandbox`/`ExecutionResult` method
//! for method; see the Rust crate's docs for behavior. Builder setters
//! consume `self` in Rust, so each one here takes the wrapped builder out of
//! `Option` and hands back a new wrapper -- that's what makes
//! `Sandbox.builder().read_only(...).memory_limit(...)` chain in Python too.

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use std::time::Duration;

fn to_py_err(e: nanosandbox::SandboxError) -> PyErr {
    PyRuntimeError::new_err(e.to_string())
}

fn builder_consumed() -> PyErr {
    PyValueError::new_err("this builder was already consumed by build() (or another chained call that didn't keep its return value)")
}

/// Read-only or read-write, for [`SandboxBuilder.bind`]. Linux only.
#[cfg(target_os = "linux")]
#[pyclass(eq, eq_int, name = "Permission")]
#[derive(Clone, PartialEq)]
pub enum Permission {
    #[pyo3(name = "READ_ONLY")]
    ReadOnly,
    #[pyo3(name = "READ_WRITE")]
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
#[pyclass(name = "SandboxBuilder")]
pub struct SandboxBuilder {
    inner: Option<nanosandbox::SandboxBuilder>,
}

impl SandboxBuilder {
    fn wrap(inner: nanosandbox::SandboxBuilder) -> Self {
        Self { inner: Some(inner) }
    }

    fn take(&mut self) -> PyResult<nanosandbox::SandboxBuilder> {
        self.inner.take().ok_or_else(builder_consumed)
    }
}

#[pymethods]
impl SandboxBuilder {
    #[new]
    fn new() -> Self {
        Self::wrap(nanosandbox::Sandbox::builder())
    }

    // ===== Filesystem =====

    fn read_only(&mut self, path: String) -> PyResult<Self> {
        Ok(Self::wrap(self.take()?.read_only(path)))
    }

    fn writable(&mut self, path: String) -> PyResult<Self> {
        Ok(Self::wrap(self.take()?.writable(path)))
    }

    #[pyo3(signature = (size_bytes=nanosandbox::DEFAULT_PRIVATE_TMP_SIZE))]
    fn private_tmp(&mut self, size_bytes: u64) -> PyResult<Self> {
        Ok(Self::wrap(self.take()?.private_tmp(size_bytes)))
    }

    fn no_private_tmp(&mut self) -> PyResult<Self> {
        Ok(Self::wrap(self.take()?.no_private_tmp()))
    }

    fn deny_read(&mut self, path: String) -> PyResult<Self> {
        Ok(Self::wrap(self.take()?.deny_read(path)))
    }

    fn hide_home(&mut self) -> PyResult<Self> {
        Ok(Self::wrap(self.take()?.hide_home()))
    }

    fn working_dir(&mut self, path: String) -> PyResult<Self> {
        Ok(Self::wrap(self.take()?.working_dir(path)))
    }

    #[cfg(target_os = "linux")]
    fn bind(&mut self, source: String, target: String, permission: Permission) -> PyResult<Self> {
        Ok(Self::wrap(self.take()?.bind(source, target, permission.into())))
    }

    #[cfg(target_os = "linux")]
    fn tmpfs(&mut self, path: String, size_bytes: u64) -> PyResult<Self> {
        Ok(Self::wrap(self.take()?.tmpfs(path, size_bytes)))
    }

    #[cfg(target_os = "linux")]
    fn rootfs(&mut self, path: String) -> PyResult<Self> {
        Ok(Self::wrap(self.take()?.rootfs(path)))
    }

    // ===== Resource limits =====

    fn memory_limit(&mut self, bytes: u64) -> PyResult<Self> {
        Ok(Self::wrap(self.take()?.memory_limit(bytes)))
    }

    fn cpu_limit(&mut self, cpus: f64) -> PyResult<Self> {
        Ok(Self::wrap(self.take()?.cpu_limit(cpus)))
    }

    fn wall_time_limit(&mut self, seconds: f64) -> PyResult<Self> {
        Ok(Self::wrap(self.take()?.wall_time_limit(Duration::from_secs_f64(seconds))))
    }

    fn cpu_time_limit(&mut self, seconds: f64) -> PyResult<Self> {
        Ok(Self::wrap(self.take()?.cpu_time_limit(Duration::from_secs_f64(seconds))))
    }

    fn max_pids(&mut self, n: u32) -> PyResult<Self> {
        Ok(Self::wrap(self.take()?.max_pids(n)))
    }

    fn max_file_size(&mut self, bytes: u64) -> PyResult<Self> {
        Ok(Self::wrap(self.take()?.max_file_size(bytes)))
    }

    fn max_open_files(&mut self, n: u32) -> PyResult<Self> {
        Ok(Self::wrap(self.take()?.max_open_files(n)))
    }

    fn max_output(&mut self, bytes: u64) -> PyResult<Self> {
        Ok(Self::wrap(self.take()?.max_output(bytes)))
    }

    // ===== Network =====

    fn no_network(&mut self) -> PyResult<Self> {
        Ok(Self::wrap(self.take()?.no_network()))
    }

    fn host_network(&mut self) -> PyResult<Self> {
        Ok(Self::wrap(self.take()?.host_network()))
    }

    fn allow_network(&mut self, domains: Vec<String>) -> PyResult<Self> {
        let refs: Vec<&str> = domains.iter().map(String::as_str).collect();
        Ok(Self::wrap(self.take()?.allow_network(&refs)))
    }

    fn allow_private_destinations(&mut self) -> PyResult<Self> {
        Ok(Self::wrap(self.take()?.allow_private_destinations()))
    }

    // ===== Security =====

    #[cfg(target_os = "linux")]
    fn seccomp(&mut self, enabled: bool) -> PyResult<Self> {
        Ok(Self::wrap(self.take()?.seccomp(enabled)))
    }

    #[cfg(target_os = "linux")]
    fn uid(&mut self, uid: u32) -> PyResult<Self> {
        Ok(Self::wrap(self.take()?.uid(uid)))
    }

    #[cfg(target_os = "linux")]
    fn gid(&mut self, gid: u32) -> PyResult<Self> {
        Ok(Self::wrap(self.take()?.gid(gid)))
    }

    // ===== Environment =====

    fn env(&mut self, key: String, value: String) -> PyResult<Self> {
        Ok(Self::wrap(self.take()?.env(key, value)))
    }

    fn clear_env(&mut self, clear: bool) -> PyResult<Self> {
        Ok(Self::wrap(self.take()?.clear_env(clear)))
    }

    #[cfg(target_os = "linux")]
    fn hostname(&mut self, name: String) -> PyResult<Self> {
        Ok(Self::wrap(self.take()?.hostname(name)))
    }

    // ===== Build =====

    fn build(&mut self) -> PyResult<Sandbox> {
        let inner = self.take()?.build().map_err(to_py_err)?;
        Ok(Sandbox { inner })
    }
}

/// See `nanosandbox::Sandbox`.
#[pyclass(name = "Sandbox")]
pub struct Sandbox {
    inner: nanosandbox::Sandbox,
}

#[pymethods]
impl Sandbox {
    #[staticmethod]
    fn builder() -> SandboxBuilder {
        SandboxBuilder::new()
    }

    #[staticmethod]
    fn data_analysis(input_dir: String, output_dir: String) -> SandboxBuilder {
        SandboxBuilder::wrap(nanosandbox::Sandbox::data_analysis(input_dir, output_dir))
    }

    #[staticmethod]
    fn code_judge(code_dir: String) -> SandboxBuilder {
        SandboxBuilder::wrap(nanosandbox::Sandbox::code_judge(code_dir))
    }

    #[staticmethod]
    fn agent_executor(workspace: String) -> SandboxBuilder {
        SandboxBuilder::wrap(nanosandbox::Sandbox::agent_executor(workspace))
    }

    #[staticmethod]
    fn interactive(workspace: String) -> SandboxBuilder {
        SandboxBuilder::wrap(nanosandbox::Sandbox::interactive(workspace))
    }

    #[pyo3(signature = (cmd, args))]
    fn run(&self, cmd: String, args: Vec<String>) -> PyResult<ExecutionResult> {
        self.run_with_input(cmd, args, None)
    }

    #[pyo3(signature = (cmd, args, stdin=None))]
    fn run_with_input(
        &self,
        cmd: String,
        args: Vec<String>,
        stdin: Option<Vec<u8>>,
    ) -> PyResult<ExecutionResult> {
        let args_ref: Vec<&str> = args.iter().map(String::as_str).collect();
        let inner = self
            .inner
            .run_with_input(&cmd, &args_ref, stdin.as_deref())
            .map_err(to_py_err)?;
        Ok(ExecutionResult { inner })
    }

    fn id(&self) -> &str {
        self.inner.id()
    }

    fn platform(&self) -> &'static str {
        self.inner.platform()
    }
}

/// See `nanosandbox::ExecutionResult`. Getters read straight from the real
/// Rust value, and `success`/`failure_reason` call its own methods, so this
/// can't drift from the core crate's definition of either.
#[pyclass(name = "ExecutionResult")]
pub struct ExecutionResult {
    inner: nanosandbox::ExecutionResult,
}

#[pymethods]
impl ExecutionResult {
    #[getter]
    fn stdout(&self) -> &str {
        &self.inner.stdout
    }

    #[getter]
    fn stderr(&self) -> &str {
        &self.inner.stderr
    }

    #[getter]
    fn exit_code(&self) -> i32 {
        self.inner.exit_code
    }

    #[getter]
    fn wall_time_seconds(&self) -> f64 {
        self.inner.duration.as_secs_f64()
    }

    #[getter]
    fn cpu_time_seconds(&self) -> Option<f64> {
        self.inner.cpu_time.map(|d| d.as_secs_f64())
    }

    #[getter]
    fn peak_memory_bytes(&self) -> Option<u64> {
        self.inner.peak_memory
    }

    #[getter]
    fn killed_by_timeout(&self) -> bool {
        self.inner.killed_by_timeout
    }

    #[getter]
    fn killed_by_oom(&self) -> bool {
        self.inner.killed_by_oom
    }

    #[getter]
    fn killed_by_tmp_limit(&self) -> bool {
        self.inner.killed_by_tmp_limit
    }

    #[getter]
    fn killed_by_cpu_limit(&self) -> bool {
        self.inner.killed_by_cpu_limit
    }

    #[getter]
    fn output_truncated(&self) -> bool {
        self.inner.output_truncated
    }

    #[getter]
    fn proc_isolated(&self) -> bool {
        self.inner.proc_isolated
    }

    #[getter]
    fn signal(&self) -> Option<i32> {
        self.inner.signal
    }

    #[getter]
    fn blocked_hosts(&self) -> Vec<String> {
        self.inner.blocked_hosts.clone()
    }

    fn success(&self) -> bool {
        self.inner.success()
    }

    fn failure_reason(&self) -> Option<String> {
        self.inner.failure_reason()
    }

    fn __repr__(&self) -> String {
        if self.inner.success() {
            format!("ExecutionResult(success, {:.2}s)", self.wall_time_seconds())
        } else {
            format!(
                "ExecutionResult(failed: {})",
                self.inner.failure_reason().unwrap_or_default()
            )
        }
    }
}

#[pyfunction]
fn is_platform_supported() -> bool {
    nanosandbox::is_platform_supported()
}

#[pyfunction]
fn platform_name() -> &'static str {
    nanosandbox::platform_name()
}

#[pymodule]
fn _nanosandbox(m: &Bound<'_, PyModule>) -> PyResult<()> {
    #[cfg(target_os = "linux")]
    m.add_class::<Permission>()?;
    m.add_class::<SandboxBuilder>()?;
    m.add_class::<Sandbox>()?;
    m.add_class::<ExecutionResult>()?;
    m.add_function(wrap_pyfunction!(is_platform_supported, m)?)?;
    m.add_function(wrap_pyfunction!(platform_name, m)?)?;

    m.add("KB", nanosandbox::KB)?;
    m.add("MB", nanosandbox::MB)?;
    m.add("GB", nanosandbox::GB)?;

    Ok(())
}
