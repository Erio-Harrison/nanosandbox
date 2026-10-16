//! Wait for a run: feed stdin, collect output, enforce wall and CPU limits, watch memory, kill leftovers.

use super::job::{Job, MSG_ACTIVE_PROCESS_ZERO, MSG_END_OF_JOB_TIME, MSG_JOB_MEMORY_LIMIT};
use crate::builder::SandboxConfig;
use crate::error::{Result, SandboxError};
use crate::platform::output::Captured;
use crate::result::ExecutionResult;
use std::io::{Read, Write};
use std::process::Child;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// Exit code of processes this kills; `ExecutionResult` says why.
pub(super) const KILLED_EXIT_CODE: u32 = 1;

/// CPU time check interval, and root-exit check when a notification was missed.
const POLL: Duration = Duration::from_millis(20);

pub(super) fn wait(
    child: &mut Child,
    job: &Job,
    stdin: Option<&[u8]>,
    config: &SandboxConfig,
    start: Instant,
) -> Result<ExecutionResult> {
    // Own threads, so neither side's full pipe stalls the other.
    let feeder = child.stdin.take().map(|mut pipe| {
        let data = stdin.unwrap_or(&[]).to_vec();
        std::thread::spawn(move || {
            let _ = pipe.write_all(&data);
        })
    });
    let stdout = child.stdout.take().map(|p| drain(p, config.max_output));
    let stderr = child.stderr.take().map(|p| drain(p, config.max_output));

    let deadline = start + config.wall_time_limit.unwrap_or(Duration::from_secs(3600));
    let (mut killed_by_timeout, mut killed_by_oom, mut killed_by_cpu_limit) = (false, false, false);
    // Max memory seen, for when the Job's peak can't be trusted (see `peak_memory`).
    let mut seen_memory = 0;
    loop {
        if child.try_wait()?.is_some() {
            break;
        }
        let now = Instant::now();
        if now >= deadline {
            killed_by_timeout = true;
            break;
        }
        let message = job.next_message(POLL.min(deadline - now));
        seen_memory = seen_memory.max(job.memory().unwrap_or(0));
        match message {
            Some(MSG_JOB_MEMORY_LIMIT) => {
                // Allocation past the limit failed; kill the run, as on Linux.
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

    // Kill whatever is left so nothing outlives the run and the pipes close.
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
        peak_memory: peak_memory(job, config.memory_limit, seen_memory),
        cpu_time: job.cpu_time(),
        blocked_hosts: Vec::new(),
        proc_isolated: true,
    })
}

/// The Job's peak, unless it exceeded the memory limit: that's a refused allocation counted at
/// full size, so use the max seen while polling instead.
fn peak_memory(job: &Job, limit: Option<u64>, seen: u64) -> Option<u64> {
    let peak = job.peak_memory()?;
    Some(match limit {
        Some(limit) if peak > limit => seen.min(limit),
        _ => peak,
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
