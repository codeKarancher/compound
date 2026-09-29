mod process;

#[cfg(target_os = "linux")]
use compound_fs::apply_landlock_plan;
#[cfg(target_os = "linux")]
use compound_fs::compile_landlock_plan;
use compound_fs::FsLockDocument;
#[cfg(target_os = "linux")]
use compound_fs::InheritedFileDescriptors;
use std::{ffi::OsString, fs, path::PathBuf, process::ExitStatus};
#[cfg(target_os = "linux")]
use std::{
    fs::File,
    path::Path,
    process::{Child, Command},
    time::Duration,
};
use thiserror::Error;

pub use process::{prepare_environment, sanitize_environment, DANGEROUS_ENV_VARS};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecOptions {
    pub fs_lock: PathBuf,
    pub tcp_lock: Option<PathBuf>,
    pub jail_id: String,
    pub workdir: Option<PathBuf>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub clear_environment: bool,
    pub keep_environment: Vec<OsString>,
    pub command: Vec<OsString>,
}

impl ExecOptions {
    pub fn new(command: impl IntoIterator<Item = OsString>) -> Self {
        Self {
            fs_lock: PathBuf::from("fs-lock.compound.yaml"),
            tcp_lock: None,
            jail_id: "default".to_owned(),
            workdir: None,
            uid: None,
            gid: None,
            clear_environment: false,
            keep_environment: Vec::new(),
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

    #[cfg(not(target_os = "linux"))]
    {
        let _ = &options.tcp_lock;
        return Err(RuntimeError::UnsupportedPlatform);
    }

    #[cfg(target_os = "linux")]
    {
        let tcp_enforcement = if options.tcp_lock.is_some() {
            Some(TcpEnforcement::start(options)?)
        } else {
            None
        };
        let plan = compile_landlock_plan(&lock)?;
        process::set_no_new_privs()?;
        process::prepare_environment(options);
        if lock.policy.inherited_file_descriptors != Some(InheritedFileDescriptors::Allow) {
            process::close_inherited_file_descriptors()?;
        }
        let network_namespace = tcp_enforcement
            .as_ref()
            .map(TcpEnforcement::open_namespace)
            .transpose()?;
        apply_landlock_plan(&plan)?;
        let status = process::spawn_and_wait(options, network_namespace)?;
        drop(tcp_enforcement);
        Ok(status)
    }
}

#[cfg(target_os = "linux")]
struct TcpEnforcement {
    jail_id: String,
    namespace: String,
    gateway: Child,
}

#[cfg(target_os = "linux")]
impl TcpEnforcement {
    fn start(options: &ExecOptions) -> Result<Self, RuntimeError> {
        let tcp_lock = options.tcp_lock.as_ref().expect("checked by caller");
        let network_options = compoundd::NetworkPlanOptions::new(&options.jail_id);
        let namespace = compoundd::build_cleanup_plan(&network_options)?.namespace;

        let _ = run_compoundd([
            OsString::from("cleanup"),
            OsString::from("--jail-id"),
            OsString::from(&options.jail_id),
        ]);
        run_compoundd([
            OsString::from("apply"),
            OsString::from("--tcp-lock"),
            tcp_lock.as_os_str().to_owned(),
            OsString::from("--jail-id"),
            OsString::from(&options.jail_id),
        ])?;

        let mut gateway = Command::new("compoundd")
            .arg("gateway")
            .arg("--tcp-lock")
            .arg(tcp_lock)
            .arg("--jail-id")
            .arg(&options.jail_id)
            .spawn()
            .map_err(|source| RuntimeError::SpawnCompoundd {
                program: "compoundd gateway".to_owned(),
                source,
            })?;

        std::thread::sleep(Duration::from_millis(100));
        if let Some(status) = gateway.try_wait()? {
            let _ = run_compoundd([
                OsString::from("cleanup"),
                OsString::from("--jail-id"),
                OsString::from(&options.jail_id),
            ]);
            return Err(RuntimeError::CompounddFailed {
                program: "compoundd gateway".to_owned(),
                code: status.code(),
            });
        }

        Ok(Self {
            jail_id: options.jail_id.clone(),
            namespace,
            gateway,
        })
    }

    fn open_namespace(&self) -> Result<File, RuntimeError> {
        let path = Path::new("/var/run/netns").join(&self.namespace);
        File::open(&path).map_err(|source| RuntimeError::OpenNetworkNamespace { path, source })
    }
}

#[cfg(target_os = "linux")]
impl Drop for TcpEnforcement {
    fn drop(&mut self) {
        let _ = self.gateway.kill();
        let _ = self.gateway.wait();
        let _ = run_compoundd([
            OsString::from("cleanup"),
            OsString::from("--jail-id"),
            OsString::from(&self.jail_id),
        ]);
    }
}

#[cfg(target_os = "linux")]
fn run_compoundd(args: impl IntoIterator<Item = OsString>) -> Result<(), RuntimeError> {
    let status = Command::new("compoundd")
        .args(args)
        .status()
        .map_err(|source| RuntimeError::SpawnCompoundd {
            program: "compoundd".to_owned(),
            source,
        })?;
    if !status.success() {
        return Err(RuntimeError::CompounddFailed {
            program: "compoundd".to_owned(),
            code: status.code(),
        });
    }
    Ok(())
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
    #[cfg(target_os = "linux")]
    #[error("failed to spawn {program}: {source}")]
    SpawnCompoundd {
        program: String,
        source: std::io::Error,
    },
    #[cfg(target_os = "linux")]
    #[error("{program} failed with exit code {code:?}")]
    CompounddFailed { program: String, code: Option<i32> },
    #[cfg(target_os = "linux")]
    #[error("failed to open network namespace {}: {source}", path.display())]
    OpenNetworkNamespace {
        path: PathBuf,
        source: std::io::Error,
    },
    #[cfg(target_os = "linux")]
    #[error(transparent)]
    Network(#[from] compoundd::NetworkError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
