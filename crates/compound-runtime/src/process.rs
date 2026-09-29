use crate::ExecOptions;
#[cfg(target_os = "linux")]
use crate::RuntimeError;
use std::{env, ffi::OsString};
#[cfg(target_os = "linux")]
use std::{
    fs::{self, File},
    os::fd::AsRawFd,
    os::unix::ffi::OsStrExt,
    os::unix::process::CommandExt,
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

pub fn prepare_environment(options: &ExecOptions) {
    if options.clear_environment {
        let retained = retained_environment(&options.keep_environment);
        env::vars_os().for_each(|(key, _)| env::remove_var(key));
        for (key, value) in retained {
            env::set_var(key, value);
        }
    }
    sanitize_environment();
}

fn retained_environment(keys: &[OsString]) -> Vec<(OsString, OsString)> {
    keys.iter()
        .filter_map(|key| env::var_os(key).map(|value| (key.clone(), value)))
        .collect()
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
pub fn spawn_and_wait(
    options: &ExecOptions,
    network_namespace: Option<File>,
) -> Result<ExitStatus, RuntimeError> {
    let mut command = Command::new(&options.command[0]);
    command.args(&options.command[1..]);
    if let Some(workdir) = &options.workdir {
        command.current_dir(workdir);
    }
    configure_child(&mut command, options, network_namespace);
    Ok(command.status()?)
}

#[cfg(target_os = "linux")]
fn configure_child(command: &mut Command, options: &ExecOptions, network_namespace: Option<File>) {
    let uid = options.uid;
    let gid = options.gid;
    if uid.is_none() && gid.is_none() && network_namespace.is_none() {
        return;
    }

    unsafe {
        command.pre_exec(move || {
            if let Some(namespace) = &network_namespace {
                let result = libc::setns(namespace.as_raw_fd(), libc::CLONE_NEWNET);
                if result != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }

            if uid.is_some() || gid.is_some() {
                let result = libc::setgroups(0, std::ptr::null());
                if result != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }

            if let Some(gid) = gid {
                let result = libc::setgid(gid);
                if result != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }

            if let Some(uid) = uid {
                let result = libc::setuid(uid);
                if result != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }

            Ok(())
        });
    }
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
