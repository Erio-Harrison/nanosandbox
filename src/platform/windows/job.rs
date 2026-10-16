//! The Job Object a run lives in: its limits, notifications, and killing the run at once.
//! No breakaway, so every descendant is in it; closing the handle kills the rest, so a run
//! can't outlive this process.

use std::io;
use std::ptr::{null, null_mut};
use std::time::Duration;
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::IO::{
    CreateIoCompletionPort, GetQueuedCompletionStatus, OVERLAPPED,
};
use windows_sys::Win32::System::JobObjects::*;

/// Job completion-port notifications.
pub(super) const MSG_END_OF_JOB_TIME: u32 = 1;
pub(super) const MSG_ACTIVE_PROCESS_ZERO: u32 = 4;
pub(super) const MSG_JOB_MEMORY_LIMIT: u32 = 10;

/// What a run's Job enforces.
pub(super) struct Limits {
    pub(super) memory: Option<u64>,
    pub(super) max_pids: Option<u32>,
    pub(super) cpu_time: Option<Duration>,
}

pub(super) struct Job {
    handle: HANDLE,
    port: HANDLE,
}

// Only used through `&self` kernel calls; not thread-affine.
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
        // A crash ends the process rather than waiting on an error dialog.
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

    /// Next notification within `timeout`; they can be lost, so don't rely on them alone.
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

    /// Peak committed memory; a refused allocation counts at full size, so it overstates past the limit.
    pub(super) fn peak_memory(&self) -> Option<u64> {
        let e: JOBOBJECT_EXTENDED_LIMIT_INFORMATION =
            self.query(JobObjectExtendedLimitInformation)?;
        Some(e.PeakJobMemoryUsed as u64)
    }
}

impl Drop for Job {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.handle);
            CloseHandle(self.port);
        }
    }
}
