//! Windows broker spawn with a Job Object so the broker dies when the
//! CLI process exits. Uses `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`.

use std::os::windows::io::AsRawHandle;
use std::process::{Child, Command};

use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};

pub fn spawn_broker(cmd: &mut Command) -> std::io::Result<Child> {
    // Create an unnamed Job Object.
    let job = unsafe { CreateJobObjectW(None, None) }
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

    // Configure kill-on-close.
    let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    unsafe {
        SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            &info as *const _ as *const _,
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    }
    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

    // Spawn the child.
    let child = cmd.spawn()?;

    // Assign the child's process handle to the job.
    let handle = HANDLE(child.as_raw_handle() as *mut core::ffi::c_void);
    unsafe { AssignProcessToJobObject(job, handle) }
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

    // Discard the job handle without closing it: the kernel's
    // kill-on-close trigger must fire on process exit, not when this
    // function returns. `HANDLE` is `Copy` and has no `Drop` impl, so
    // simply letting the local go out of scope is fine — the kernel-side
    // handle persists for the life of the process.
    let _ = job;

    Ok(child)
}
