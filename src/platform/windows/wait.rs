//! Waiting for a run to finish: feeding stdin and collecting output on
//! their own threads, enforcing the wall-clock and CPU time limits, noticing
//! the memory limit, and killing whatever is left of the run at the end.

use super::job::{Job, MSG_ACTIVE_PROCESS_ZERO, MSG_END_OF_JOB_TIME, MSG_JOB_MEMORY_LIMIT};
use crate::builder::SandboxConfig;
use crate::error::{Result, SandboxError};
use crate::platform::output::Captured;
use crate::result::ExecutionResult;
use std::io::{Read, Write};
use std::process::Child;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// The exit code a run's processes get when this kills them (timeout,
/// memory or CPU time limit): `ExecutionResult` says which.
pub(super) const KILLED_EXIT_CODE: u32 = 1;

/// How often CPU time is checked against `cpu_time_limit`, and the root
/// process for exit when a notification was missed.
const POLL: Duration = Duration::from_millis(20);

pub(super) fn wait(
    child: &mut Child,
    job: &Job,
    stdin: Option<&[u8]>,
    config: &SandboxConfig,
    start: Instant,
) -> Result<ExecutionResult> {
    // stdin is fed and output drained on their own threads, so neither
    // side can fill a pipe and stall the other.
    let feeder = child.stdin.take().map(|mut pipe| {
        let data = stdin.unwrap_or(&[]).to_vec();
        std::thread::spawn(move || {
            // A program that exits without reading it all is fine.
            let _ = pipe.write_all(&data);
        })
    });
    let stdout = child.stdout.take().map(|p| drain(p, config.max_output));
    let stderr = child.stderr.take().map(|p| drain(p, config.max_output));

    let deadline = start + config.wall_time_limit.unwrap_or(Duration::from_secs(3600));
    let (mut killed_by_timeout, mut killed_by_oom, mut killed_by_cpu_limit) = (false, false, false);
    loop {
        if child.try_wait()?.is_some() {
            break;
        }
        let now = Instant::now();
        if now >= deadline {
            killed_by_timeout = true;
            break;
        }
        match job.next_message(POLL.min(deadline - now)) {
            Some(MSG_JOB_MEMORY_LIMIT) => {
                // The allocation past the limit failed; the run is killed,
                // as it is on Linux, rather than left to cope with that.
                killed_by_oom = true;
                break;
            }
            Some(MSG_END_OF_JOB_TIME) => {
                killed_by_cpu_limit = true;
                break;
            }
            Some(MSG_ACTIVE_PROCESS_ZERO) => break,
            _ => {}
        }
        if let Some(limit) = config.cpu_time_limit
            && job.cpu_time().is_some_and(|used| used > limit)
        {
            killed_by_cpu_limit = true;
            break;
        }
    }

    // Whatever is left of the run (the root, if a limit stopped it, or what
    // it left running in the background) goes now, so nothing outlives the
    // run, and the output pipes close.
    job.terminate(KILLED_EXIT_CODE);
    let status = child.wait()?;

    if let Some(f) = feeder {
        let _ = f.join();
    }
    let stdout = join(stdout)?;
    let stderr = join(stderr)?;

    Ok(ExecutionResult {
        output_truncated: stdout.truncated() || stderr.truncated(),
        stdout: stdout.into_string(),
        stderr: stderr.into_string(),
        exit_code: status.code().unwrap_or(-1),
        duration: start.elapsed(),
        killed_by_timeout,
        killed_by_oom,
        killed_by_tmp_limit: false,
        killed_by_cpu_limit,
        signal: None,
        peak_memory: job.peak_memory(),
        cpu_time: job.cpu_time(),
        blocked_hosts: Vec::new(),
        proc_isolated: true,
    })
}

fn drain(mut pipe: impl Read + Send + 'static, limit: u64) -> JoinHandle<Captured> {
    std::thread::spawn(move || {
        let mut out = Captured::new(limit);
        let mut buf = [0u8; 8192];
        loop {
            match pipe.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => out.push(&buf[..n]),
            }
        }
        out
    })
}

fn join(reader: Option<JoinHandle<Captured>>) -> Result<Captured> {
    match reader {
        None => Ok(Captured::new(0)),
        Some(r) => r.join().map_err(|_| SandboxError::ExecutionFailed {
            context: "collect output".into(),
            source: Box::new(std::io::Error::other("output reader panicked")),
        }),
    }
}
