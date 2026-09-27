#[cfg(target_os = "linux")]
use crate::{ExecOptions, RuntimeError};
use std::env;
#[cfg(target_os = "linux")]
use std::{
    fs,
    os::unix::ffi::OsStrExt,
    process::{Command, ExitStatus},
};

pub const DANGEROUS_ENV_VARS: &[&str] = &[
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "DYLD_INSERT_LIBRARIES",
    "DYLD_LIBRARY_PATH",
    "PYTHONPATH",
    "NODE_OPTIONS",
    "BASH_ENV",
    "ENV",
];

pub fn sanitize_environment() {
    for key in DANGEROUS_ENV_VARS {
        env::remove_var(key);
    }
}

#[cfg(target_os = "linux")]
pub fn set_no_new_privs() -> Result<(), RuntimeError> {
    let result = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
    if result != 0 {
        return Err(RuntimeError::Io(std::io::Error::last_os_error()));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn spawn_and_wait(options: &ExecOptions) -> Result<ExitStatus, RuntimeError> {
    let mut command = Command::new(&options.command[0]);
    command.args(&options.command[1..]);
    if let Some(workdir) = &options.workdir {
        command.current_dir(workdir);
    }
    Ok(command.status()?)
}

#[cfg(target_os = "linux")]
pub fn close_inherited_file_descriptors() -> Result<(), RuntimeError> {
    let mut fds = Vec::new();
    for entry in fs::read_dir("/proc/self/fd")? {
        let entry = entry?;
        let Some(fd) = parse_fd(entry.file_name().as_bytes()) else {
            continue;
        };
        if fd > 2 {
            fds.push(fd);
        }
    }

    fds.sort_unstable();
    fds.dedup();
    for fd in fds {
        unsafe {
            libc::close(fd);
        }
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn parse_fd(bytes: &[u8]) -> Option<i32> {
    let text = std::str::from_utf8(bytes).ok()?;
    text.parse().ok()
}
