//! When each polled limit is next due. The wait loops sleep until the earliest of these (or an
//! I/O or exit event), so a run with nothing to poll never wakes on a timer.

use std::time::{Duration, Instant};

/// Margin over `cpu_time_limit` for the cgroup-wide check, so a single process's own
/// `RLIMIT_CPU` is what ends it; without one this check raced ahead under load.
#[cfg(any(target_os = "linux", test))]
pub(crate) const CPU_LIMIT_GRACE: Duration = Duration::from_millis(200);
#[cfg(any(target_os = "linux", test))]
const CPU_CHECK_FLOOR: Duration = Duration::from_millis(10);

/// Next read of the cgroup-wide CPU total: the soonest the budget left could be used up with
/// `parallelism` CPUs, at least `CPU_CHECK_FLOOR`. Checks get closer as the limit nears.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn cpu_check_due(
    now: Instant,
    used: Duration,
    limit: Duration,
    parallelism: u32,
) -> Instant {
    let budget = (limit + CPU_LIMIT_GRACE).saturating_sub(used);
    now + (budget / parallelism.max(1)).max(CPU_CHECK_FLOOR)
}

/// Next memory footprint read (macOS, no kernel limit): 10 ms, 2 ms once past 60% of the limit.
#[cfg(any(target_os = "macos", test))]
pub(crate) fn memory_check_due(now: Instant, used: u64, limit: u64) -> Instant {
    now + if used > limit / 10 * 6 {
        Duration::from_millis(2)
    } else {
        Duration::from_millis(10)
    }
}

/// Whole milliseconds until `due`, rounded up (so the loop never wakes just before it), as
/// `poll(2)` takes it; `None` is forever.
#[cfg(any(target_os = "linux", test))]
pub(crate) fn poll_timeout_ms(due: Option<Instant>, now: Instant) -> libc::c_int {
    match due {
        None => -1,
        Some(due) => {
            let left = due.saturating_duration_since(now);
            left.as_millis()
                .saturating_add(u128::from(left.subsec_nanos() % 1_000_000 != 0))
                .min(libc::c_int::MAX as u128) as libc::c_int
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cpu_checks_close_in_on_the_limit() {
        let now = Instant::now();
        let limit = Duration::from_secs(6);
        let far = cpu_check_due(now, Duration::ZERO, limit, 6) - now;
        assert!(far >= Duration::from_secs(1) && far < Duration::from_millis(1100));
        let near = cpu_check_due(now, Duration::from_millis(6150), limit, 6) - now;
        assert_eq!(near, CPU_CHECK_FLOOR);
        let over = cpu_check_due(now, Duration::from_secs(10), limit, 0) - now;
        assert_eq!(over, CPU_CHECK_FLOOR);
    }

    #[test]
    fn test_memory_checks_speed_up_near_the_limit() {
        let now = Instant::now();
        assert_eq!(memory_check_due(now, 10, 100) - now, Duration::from_millis(10));
        assert_eq!(memory_check_due(now, 61, 100) - now, Duration::from_millis(2));
    }

    #[test]
    fn test_poll_timeout_rounds_up() {
        let now = Instant::now();
        assert_eq!(poll_timeout_ms(None, now), -1);
        assert_eq!(poll_timeout_ms(Some(now), now), 0);
        assert_eq!(
            poll_timeout_ms(Some(now + Duration::from_micros(1500)), now),
            2
        );
        assert_eq!(poll_timeout_ms(Some(now + Duration::from_millis(3)), now), 3);
    }
}
