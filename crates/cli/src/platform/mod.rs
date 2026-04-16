//! Platform-specific broker process spawning.
//!
//! On Unix, the broker is a plain child process; it inherits no special
//! lifetime handling (it self-manages via the port file and Ctrl-C / SIGTERM).
//!
//! On Windows, the CLI creates a Job Object with
//! `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` and assigns the broker child to it.
//! When the CLI process exits (normal, crash, killed), Windows terminates
//! every process in the job — so the broker cannot be orphaned. The job
//! handle is intentionally leaked: it must outlive the CLI child for the
//! kill-on-close behaviour to fire.

use std::process::{Child, Command};

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

/// Spawn the broker daemon, attaching it to a lifetime-binding primitive
/// on platforms that support one (Windows Job Object). On Unix this is a
/// plain [`Command::spawn`].
pub fn spawn_broker(cmd: &mut Command) -> std::io::Result<Child> {
    #[cfg(unix)]
    {
        unix::spawn_broker(cmd)
    }
    #[cfg(windows)]
    {
        windows::spawn_broker(cmd)
    }
    #[cfg(not(any(unix, windows)))]
    {
        cmd.spawn()
    }
}
