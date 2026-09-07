//! One process-wide lock for environment variables in tests.
//!
//! `HOME`, `AGTCRDN_BROKER_URL`, `AGTCRDN_SERVER_URL` and
//! `AGTCRDN_WORKSPACE_DIR` are process-global, and several test modules need
//! to set them. Two modules each holding *their own* mutex serialises neither
//! against the other, which is how a test that parks `HOME` on an empty
//! tempdir can be raced by one that points it at a fixture. There is one lock,
//! here, and every test that touches the environment takes it.

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::sync::{Mutex, MutexGuard};

static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Holds the environment lock for the life of a test and restores every
/// variable it changed on drop.
pub(crate) struct EnvGuard {
    _lock: MutexGuard<'static, ()>,
    saved: BTreeMap<String, Option<String>>,
}

impl EnvGuard {
    pub(crate) fn new() -> Self {
        Self {
            _lock: ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner()),
            saved: BTreeMap::new(),
        }
    }

    /// Set a variable, remembering its prior value.
    pub(crate) fn set(&mut self, key: &str, value: impl AsRef<OsStr>) {
        self.remember(key);
        // SAFETY: the process-wide lock above serialises every test that
        // touches the environment.
        unsafe { std::env::set_var(key, value) };
    }

    /// Remove a variable, remembering its prior value. Used to clear one the
    /// host happens to export, so a test cannot pass or fail because of the
    /// developer's shell.
    pub(crate) fn unset(&mut self, key: &str) {
        self.remember(key);
        // SAFETY: as above.
        unsafe { std::env::remove_var(key) };
    }

    fn remember(&mut self, key: &str) {
        self.saved
            .entry(key.to_string())
            .or_insert_with(|| std::env::var(key).ok());
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for (key, prior) in &self.saved {
            // SAFETY: the lock is still held; it is released after this.
            unsafe {
                match prior {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }
    }
}
