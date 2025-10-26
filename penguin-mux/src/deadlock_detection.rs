//! Deadlock detection facility using `parking_lot`'s deadlock detection
//! implementation.
//!
//! <div class="warning">
//! This is not a part of the stable public API. It may change or be removed
//! within any minor version.
//! </div>
//
// SPDX-License-Identifier:  Apache-2.0 OR GPL-3.0-or-later
use std::{sync::OnceLock, thread};
use tracing::{error, info};

/// Global deadlock detection thread handle
static DETECTION_THREAD: OnceLock<thread::JoinHandle<()>> = OnceLock::new();

/// Spawn the deadlock detection thread if one is not already running
pub fn try_spawn_deadlock_detection() {
    DETECTION_THREAD.get_or_init(|| {
        // Create a background thread which checks for deadlocks every 10s
        thread::spawn(move || {
            info!("Deadlock detection thread started");
            loop {
                thread::sleep(std::time::Duration::from_secs(10));
                let deadlocks = parking_lot::deadlock::check_deadlock();
                if deadlocks.is_empty() {
                    continue;
                }

                error!("{} deadlocks detected", deadlocks.len());
                for (i, threads) in deadlocks.iter().enumerate() {
                    error!("Deadlock #{i}");
                    for t in threads {
                        error!("Thread Id {:#?}", t.thread_id());
                        error!("{:#?}", t.backtrace());
                    }
                }
            }
        })
    });
}
