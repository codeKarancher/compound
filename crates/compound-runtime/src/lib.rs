mod process;

#[cfg(target_os = "linux")]
use compound_fs::apply_landlock_plan;
#[cfg(target_os = "linux")]
use compound_fs::InheritedFileDescriptors;
use compound_fs::{compile_landlock_plan, FsLockDocument};
use std::{ffi::OsString, fs, path::PathBuf, process::ExitStatus};
use thiserror::Error;

pub use process::{sanitize_environment, DANGEROUS_ENV_VARS};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecOptions {
    pub fs_lock: PathBuf,
    pub workdir: Option<PathBuf>,
    pub command: Vec<OsString>,
}

impl ExecOptions {
    pub fn new(command: impl IntoIterator<Item = OsString>) -> Self {
        Self {
            fs_lock: PathBuf::from("fs-lock.compound.yaml"),
            workdir: None,
            command: command.into_iter().collect(),
        }
    }
}

pub fn exec(options: &ExecOptions) -> Result<ExitStatus, RuntimeError> {
    if options.command.is_empty() {
        return Err(RuntimeError::MissingCommand);
    }

    let lock = read_fs_lock(&options.fs_lock)?;
    lock.validate_lock().map_err(RuntimeError::InvalidFsLock)?;
    let plan = compile_landlock_plan(&lock)?;

    #[cfg(not(target_os = "linux"))]
    {
        let _ = plan;
        return Err(RuntimeError::UnsupportedPlatform);
    }

    #[cfg(target_os = "linux")]
    {
        process::set_no_new_privs()?;
        sanitize_environment();
        if lock.policy.inherited_file_descriptors != Some(InheritedFileDescriptors::Allow) {
            process::close_inherited_file_descriptors()?;
        }
        apply_landlock_plan(&plan)?;
        process::spawn_and_wait(options)
    }
}

fn read_fs_lock(path: &PathBuf) -> Result<FsLockDocument, RuntimeError> {
    let bytes = fs::read(path).map_err(|source| RuntimeError::ReadFsLock {
        path: path.clone(),
        source,
    })?;
    serde_yaml::from_reader(bytes.as_slice()).map_err(|source| RuntimeError::ParseFsLock {
        path: path.clone(),
        source,
    })
}

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("compound exec requires a command after --")]
    MissingCommand,
    #[error("compound exec with filesystem enforcement requires Linux Landlock")]
    UnsupportedPlatform,
    #[error("failed to read fs lock {}: {source}", path.display())]
    ReadFsLock {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to parse fs lock {}: {source}", path.display())]
    ParseFsLock {
        path: PathBuf,
        source: serde_yaml::Error,
    },
    #[error("invalid fs lock: {0:?}")]
    InvalidFsLock(Vec<compound_fs::FsValidationError>),
    #[error(transparent)]
    Landlock(#[from] compound_fs::LandlockError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
