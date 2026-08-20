//! Minimal POSIX signal handling for graceful Ctrl-C shutdown.
//!
//! The crate has zero dependencies, so instead of pulling in `ctrlc` or
//! `signal-hook` we declare the classic libc `signal` entry point directly and
//! have the handler only flip an atomic flag. The engine polls the flag.

use std::sync::atomic::{AtomicBool, Ordering};

static SHUTDOWN: AtomicBool = AtomicBool::new(false);

/// True once SIGINT/SIGTERM has been observed.
pub fn shutdown_requested() -> bool {
    SHUTDOWN.load(Ordering::Relaxed)
}

#[cfg(unix)]
mod imp {
    use super::SHUTDOWN;
    use std::sync::atomic::Ordering;

    unsafe extern "C" fn handle(_signum: i32) {
        SHUTDOWN.store(true, Ordering::SeqCst);
    }

    extern "C" {
        fn signal(signum: i32, handler: usize) -> usize;
    }

    pub fn install() {
        let handler: unsafe extern "C" fn(i32) = handle;
        unsafe {
            // SIGINT = 2, SIGTERM = 15 (POSIX).
            let _ = signal(2, handler as usize);
            let _ = signal(15, handler as usize);
        }
    }
}

#[cfg(not(unix))]
mod imp {
    pub fn install() {}
}

/// Install the shutdown handlers (no-op on non-Unix platforms).
pub fn install() {
    imp::install();
}