//! Unix-only broker spawn: plain `Command::spawn`.

use std::process::{Child, Command};

pub fn spawn_broker(cmd: &mut Command) -> std::io::Result<Child> {
    cmd.spawn()
}
