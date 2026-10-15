//! The Job Object a run's processes live in: its limits, what it reports
//! back (memory limit hit, CPU time used), and killing every process of it
//! at once.
//!
//! Nothing can leave it: breakaway isn't allowed, so every descendant is in
//! it too. Closing the handle kills whatever is still running in it, which
//! is what keeps a run from outliving this process, even if it dies.

use std::io;
use std::ptr::{null, null_mut};
use std::time::Duration;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::IO::{
    CreateIoCompletionPort, GetQueuedCompletionStatus, OVERLAPPED,
};
use windows_sys::Win32::System::JobObjects::*;
use windows_sys::Win32::System::Threading::{ALL_PROCESSOR_GROUPS, GetActiveProcessorCount};

/// Job notifications, as delivered on its completion port.
pub(super) const MSG_END_OF_JOB_TIME: u32 = 1;
pub(super) const MSG_ACTIVE_PROCESS_ZERO: u32 = 4;
pub(super) const MSG_JOB_MEMORY_LIMIT: u32 = 10;

/// What a run's Job enforces.
pub(super) struct Limits {
    pub(super) memory: Option<u64>,
    pub(super) max_pids: Option<u32>,
    /// Cores' worth of CPU, as `cpu_limit` takes it.
    pub(super) cpus: Option<f64>,
    pub(super) cpu_time: Option<Duration>,
}

pub(super) struct Job {
    handle: HANDLE,
    port: HANDLE,
}

// Both handles are only ever used through `&self` calls the kernel
// serializes; nothing here is thread-affine.
unsafe impl Send for Job {}
unsafe impl Sync for Job {}

impl Job {
    pub(super) fn create(limits: &Limits) -> io::Result<Self> {
        let handle = unsafe { CreateJobObjectW(null(), null()) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }
        let port = unsafe { CreateIoCompletionPort(INVALID_HANDLE_VALUE, null_mut(), 0, 1) };
        if port.is_null() {
            let e = io::Error::last_os_error();
            unsafe { CloseHandle(handle) };
            return Err(e);
        }
        let job = Self { handle, port };

        let assoc = JOBOBJECT_ASSOCIATE_COMPLETION_PORT {
            CompletionKey: null_mut(),
            CompletionPort: port,
        };
        job.set(JobObjectAssociateCompletionPortInformation, &assoc)?;

        let mut ext: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { std::mem::zeroed() };
        let basic = &mut ext.BasicLimitInformation;
        // A crash ends the process instead of waiting on an error dialog
        // until the run times out.
        basic.LimitFlags =
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
        if let Some(n) = limits.max_pids {
            basic.LimitFlags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
            basic.ActiveProcessLimit = n;
        }
        if let Some(t) = limits.cpu_time {
            // User time only; `wait` also polls user + kernel time.
            basic.LimitFlags |= JOB_OBJECT_LIMIT_JOB_TIME;
            basic.PerJobUserTimeLimit =
                i64::try_from(t.as_nanos() / 100).unwrap_or(i64::MAX).max(1);
        }
        if let Some(bytes) = limits.memory {
            ext.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_JOB_MEMORY;
            ext.JobMemoryLimit = usize::try_from(bytes).unwrap_or(usize::MAX);
        }
        job.set(JobObjectExtendedLimitInformation, &ext)?;

        if let Some(rate) = limits.cpus.and_then(cpu_rate) {
            let info = JOBOBJECT_CPU_RATE_CONTROL_INFORMATION {
                ControlFlags: JOB_OBJECT_CPU_RATE_CONTROL_ENABLE
                    | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP,
                Anonymous: JOBOBJECT_CPU_RATE_CONTROL_INFORMATION_0 { CpuRate: rate },
            };
            job.set(JobObjectCpuRateControlInformation, &info)?;
        }
        Ok(job)
    }

    fn set<T>(&self, class: JOBOBJECTINFOCLASS, info: &T) -> io::Result<()> {
        let ok = unsafe {
            SetInformationJobObject(
                self.handle,
                class,
                (info as *const T).cast(),
                size_of::<T>() as u32,
            )
        };
        if ok == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn query<T>(&self, class: JOBOBJECTINFOCLASS) -> Option<T> {
        let mut info: T = unsafe { std::mem::zeroed() };
        let ok = unsafe {
            QueryInformationJobObject(
                self.handle,
                class,
                (&mut info as *mut T).cast(),
                size_of::<T>() as u32,
                null_mut(),
            )
        };
        (ok != 0).then_some(info)
    }

    pub(super) fn assign(&self, process: HANDLE) -> io::Result<()> {
        if unsafe { AssignProcessToJobObject(self.handle, process) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Kills every process in the job.
    pub(super) fn terminate(&self, exit_code: u32) {
        unsafe { TerminateJobObject(self.handle, exit_code) };
    }

    /// The next notification, if one comes within `timeout`. Notifications
    /// can be lost, so the caller doesn't rely on them alone.
    pub(super) fn next_message(&self, timeout: Duration) -> Option<u32> {
        let (mut msg, mut key, mut overlapped) = (0u32, 0usize, null_mut::<OVERLAPPED>());
        let ms = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX);
        let ok = unsafe {
            GetQueuedCompletionStatus(self.port, &mut msg, &mut key, &mut overlapped, ms)
        };
        (ok != 0).then_some(msg)
    }

    /// User + kernel time of every process the job has had.
    pub(super) fn cpu_time(&self) -> Option<Duration> {
        let a: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION =
            self.query(JobObjectBasicAccountingInformation)?;
        let ticks = u64::try_from(a.TotalUserTime).ok()? + u64::try_from(a.TotalKernelTime).ok()?;
        Some(Duration::from_nanos(ticks.saturating_mul(100)))
    }

    /// The memory the job's processes have committed right now.
    pub(super) fn memory(&self) -> Option<u64> {
        let v: JOBOBJECT_LIMIT_VIOLATION_INFORMATION =
            self.query(JobObjectLimitViolationInformation)?;
        Some(v.JobMemory)
    }

    /// The most committed memory the job's processes have had at once, as
    /// Windows counts it: an allocation the memory limit refused counts in
    /// it too, at its full size, so past the limit it overstates.
    pub(super) fn peak_memory(&self) -> Option<u64> {
        let e: JOBOBJECT_EXTENDED_LIMIT_INFORMATION =
            self.query(JobObjectExtendedLimitInformation)?;
        Some(e.PeakJobMemoryUsed as u64)
    }
}

impl Drop for Job {
    fn drop(&mut self) {
        // KILL_ON_JOB_CLOSE: anything still running in it dies here.
        unsafe {
            CloseHandle(self.handle);
            CloseHandle(self.port);
        }
    }
}

/// `cpu_limit` as a hard cap in a Job's units: hundredths of a percent of
/// every processor on the machine. None when it would cap nothing.
fn cpu_rate(cpus: f64) -> Option<u32> {
    let total = unsafe { GetActiveProcessorCount(ALL_PROCESSOR_GROUPS) }.max(1);
    rate_of(cpus, total)
}

fn rate_of(cpus: f64, processors: u32) -> Option<u32> {
    let rate = (cpus / f64::from(processors) * 10_000.0).round();
    (rate < 10_000.0).then(|| (rate as u32).max(1))
}

#[cfg(test)]
mod tests {
    use super::rate_of;

    #[test]
    fn cpu_limit_is_a_share_of_the_whole_machine() {
        assert_eq!(rate_of(1.0, 16), Some(625));
        assert_eq!(rate_of(0.5, 4), Some(1250));
        assert_eq!(rate_of(0.01, 64), Some(2));
        assert_eq!(rate_of(0.0001, 64), Some(1));
        // As many cores as there are, or more, caps nothing.
        assert_eq!(rate_of(16.0, 16), None);
        assert_eq!(rate_of(32.0, 16), None);
    }
}
