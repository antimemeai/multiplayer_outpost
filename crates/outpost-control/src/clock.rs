//! Sleep-aware monotonic clock and wall-clock utilities.
//!
//! Laptop/host sleep MUST count against 45s/60s control-plane liveness and lease timers,
//! so `sleep_aware_now_ms()` uses:
//! - `CLOCK_BOOTTIME` on Linux
//! - `mach_continuous_time` scaled via `mach_timebase_info` on macOS

use std::time::{SystemTime, UNIX_EPOCH};

/// Returns a monotonic timestamp in milliseconds that continues advancing while the system sleeps.
#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
pub fn sleep_aware_now_ms() -> u64 {
    use std::sync::OnceLock;

    #[repr(C)]
    struct MachTimebaseInfo {
        numer: u32,
        denom: u32,
    }

    unsafe extern "C" {
        fn mach_continuous_time() -> u64;
        fn mach_timebase_info(info: *mut MachTimebaseInfo) -> i32;
    }

    static TIMEBASE: OnceLock<(u32, u32)> = OnceLock::new();
    let &(numer, denom) = TIMEBASE.get_or_init(|| {
        let mut info = MachTimebaseInfo { numer: 1, denom: 1 };
        // SAFETY: `info` is a valid, aligned out-pointer for Apple's `mach_timebase_info`.
        let rc = unsafe { mach_timebase_info(&raw mut info) };
        if rc == 0 && info.denom != 0 {
            (info.numer, info.denom)
        } else {
            (1, 1)
        }
    });

    // SAFETY: `mach_continuous_time` takes no arguments and is thread-safe on macOS >= 10.12.
    let ticks = unsafe { mach_continuous_time() };
    let nanos = u128::from(ticks)
        .saturating_mul(u128::from(numer))
        / u128::from(denom.max(1));
    u64::try_from(nanos / 1_000_000).unwrap_or(u64::MAX)
}

/// Returns a monotonic timestamp in milliseconds that continues advancing while the system sleeps.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
pub fn sleep_aware_now_ms() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `ts` is a valid out-pointer for POSIX `clock_gettime(CLOCK_BOOTTIME)`.
    let rc = unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &raw mut ts) };
    if rc != 0 || ts.tv_sec < 0 || ts.tv_nsec < 0 {
        return wall_now_ms();
    }
    let secs = u64::try_from(ts.tv_sec).unwrap_or(0);
    let nanos = u64::try_from(ts.tv_nsec).unwrap_or(0);
    secs.saturating_mul(1_000).saturating_add(nanos / 1_000_000)
}

/// Fallback monotonic sleep-aware clock for non-Linux/non-macOS platforms.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn sleep_aware_now_ms() -> u64 {
    wall_now_ms()
}

/// Returns current Unix wall-clock time in whole seconds.
pub fn wall_now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// Returns current Unix wall-clock time in milliseconds.
pub fn wall_now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sleep_aware_clock_is_monotonic_and_advances() {
        let t0 = sleep_aware_now_ms();
        std::thread::sleep(std::time::Duration::from_millis(15));
        let t1 = sleep_aware_now_ms();
        assert!(t1 >= t0, "monotonic clock went backwards: t0={t0}, t1={t1}");
        assert!(
            t1.saturating_sub(t0) >= 5,
            "monotonic clock did not advance after 15ms sleep: t0={t0}, t1={t1}"
        );
    }

    #[test]
    fn wall_clock_is_sane() {
        let s = wall_now_secs();
        let ms = wall_now_ms();
        assert!(s > 1_700_000_000, "unexpected wall_now_secs: {s}");
        assert!(ms >= (s as u64).saturating_mul(1_000).saturating_sub(2_000));
    }
}
