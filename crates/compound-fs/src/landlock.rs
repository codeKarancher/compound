use crate::{FsAccess, FsDefault, FsLockDocument};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LandlockPlan {
    pub rules: Vec<LandlockPathRule>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LandlockPathRule {
    pub path: PathBuf,
    pub access: BTreeSet<FsAccess>,
}

pub fn compile_landlock_plan(lock: &FsLockDocument) -> Result<LandlockPlan, LandlockError> {
    if lock.policy.default != FsDefault::Deny {
        return Err(LandlockError::InvalidPolicy(
            "fs lock must set policy.default: deny".to_owned(),
        ));
    }

    if lock.policy.paths.is_empty() {
        return Err(LandlockError::InvalidPolicy(
            "fs lock must grant at least one path".to_owned(),
        ));
    }

    let mut rules = BTreeMap::<PathBuf, BTreeSet<FsAccess>>::new();
    for rule in &lock.policy.paths {
        if !rule.path.is_absolute() {
            return Err(LandlockError::InvalidPolicy(format!(
                "landlock path must be absolute: {}",
                rule.path.display()
            )));
        }

        if rule.access.is_empty() {
            return Err(LandlockError::InvalidPolicy(format!(
                "landlock path must grant at least one access right: {}",
                rule.path.display()
            )));
        }

        match rules.get(&rule.path) {
            Some(existing) if existing != &rule.access => {
                return Err(LandlockError::InvalidPolicy(format!(
                    "conflicting landlock grants for path: {}",
                    rule.path.display()
                )));
            }
            Some(_) => {}
            None => {
                rules.insert(rule.path.clone(), rule.access.clone());
            }
        }
    }

    Ok(LandlockPlan {
        rules: rules
            .into_iter()
            .map(|(path, access)| LandlockPathRule { path, access })
            .collect(),
    })
}

#[cfg(target_os = "linux")]
pub fn apply_landlock_plan(plan: &LandlockPlan) -> Result<(), LandlockError> {
    linux::apply_landlock_plan(plan)
}

#[cfg(not(target_os = "linux"))]
pub fn apply_landlock_plan(_plan: &LandlockPlan) -> Result<(), LandlockError> {
    Err(LandlockError::UnsupportedPlatform)
}

#[derive(Debug, Error)]
pub enum LandlockError {
    #[error("invalid filesystem policy for Landlock: {0}")]
    InvalidPolicy(String),
    #[error("Landlock enforcement requires Linux")]
    UnsupportedPlatform,
    #[error(
        "Landlock ABI {actual} is unsupported; Compound filesystem enforcement requires ABI {required} or newer ({reason})"
    )]
    UnsupportedAbi {
        actual: i64,
        required: i64,
        reason: &'static str,
    },
    #[error("Landlock syscall failed at {operation}: {source}")]
    Syscall {
        operation: &'static str,
        source: std::io::Error,
    },
    #[error("failed to open Landlock path {}: {source}", path.display())]
    OpenPath {
        path: PathBuf,
        source: std::io::Error,
    },
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::{
        ffi::CString,
        io,
        os::{
            fd::{AsRawFd, FromRawFd, OwnedFd},
            unix::ffi::OsStrExt,
        },
    };

    const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1;
    const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;
    const MINIMUM_SUPPORTED_ABI: i64 = 3;

    const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;
    const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
    const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;
    const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3;
    const LANDLOCK_ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
    const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
    const LANDLOCK_ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
    const LANDLOCK_ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
    const LANDLOCK_ACCESS_FS_MAKE_REG: u64 = 1 << 8;
    const LANDLOCK_ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
    const LANDLOCK_ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
    const LANDLOCK_ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
    const LANDLOCK_ACCESS_FS_MAKE_SYM: u64 = 1 << 12;
    const LANDLOCK_ACCESS_FS_REFER: u64 = 1 << 13;
    const LANDLOCK_ACCESS_FS_TRUNCATE: u64 = 1 << 14;

    #[repr(C)]
    struct LandlockRulesetAttr {
        handled_access_fs: u64,
    }

    #[repr(C)]
    struct LandlockPathBeneathAttr {
        allowed_access: u64,
        parent_fd: i32,
    }

    pub fn apply_landlock_plan(plan: &LandlockPlan) -> Result<(), LandlockError> {
        ensure_supported_abi()?;

        let handled_access_fs = handled_rights();
        let ruleset_attr = LandlockRulesetAttr { handled_access_fs };

        let ruleset_fd = syscall_create_ruleset(&ruleset_attr)?;
        for rule in &plan.rules {
            let file = open_landlock_path(&rule.path)?;
            let path_attr = LandlockPathBeneathAttr {
                allowed_access: rights_to_bits(&rule.access),
                parent_fd: file.as_raw_fd(),
            };
            syscall_add_rule(ruleset_fd.as_raw_fd(), &path_attr)?;
        }

        syscall_restrict_self(ruleset_fd.as_raw_fd())?;

        Ok(())
    }

    fn handled_rights() -> u64 {
        LANDLOCK_ACCESS_FS_EXECUTE
            | LANDLOCK_ACCESS_FS_WRITE_FILE
            | LANDLOCK_ACCESS_FS_READ_FILE
            | LANDLOCK_ACCESS_FS_READ_DIR
            | LANDLOCK_ACCESS_FS_REMOVE_DIR
            | LANDLOCK_ACCESS_FS_REMOVE_FILE
            | LANDLOCK_ACCESS_FS_MAKE_CHAR
            | LANDLOCK_ACCESS_FS_MAKE_DIR
            | LANDLOCK_ACCESS_FS_MAKE_REG
            | LANDLOCK_ACCESS_FS_MAKE_SOCK
            | LANDLOCK_ACCESS_FS_MAKE_FIFO
            | LANDLOCK_ACCESS_FS_MAKE_BLOCK
            | LANDLOCK_ACCESS_FS_MAKE_SYM
            | LANDLOCK_ACCESS_FS_REFER
            | LANDLOCK_ACCESS_FS_TRUNCATE
    }

    fn rights_to_bits(access: &BTreeSet<FsAccess>) -> u64 {
        access.iter().fold(0, |bits, access| {
            bits | match access {
                FsAccess::Read => LANDLOCK_ACCESS_FS_READ_FILE,
                FsAccess::List => LANDLOCK_ACCESS_FS_READ_DIR,
                FsAccess::Write => LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_TRUNCATE,
                FsAccess::Create => LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_MAKE_REG,
                FsAccess::Delete => LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE,
                FsAccess::Rename => LANDLOCK_ACCESS_FS_REFER,
                FsAccess::Execute => LANDLOCK_ACCESS_FS_EXECUTE,
            }
        })
    }

    fn ensure_supported_abi() -> Result<(), LandlockError> {
        let abi = kernel_landlock_abi()?;
        if abi < MINIMUM_SUPPORTED_ABI {
            return Err(LandlockError::UnsupportedAbi {
                actual: abi,
                required: MINIMUM_SUPPORTED_ABI,
                reason: "rename/reparent and truncate must be enforceable for Compound's fs access model",
            });
        }
        Ok(())
    }

    fn open_landlock_path(path: &PathBuf) -> Result<OwnedFd, LandlockError> {
        let c_path = CString::new(path.as_os_str().as_bytes()).map_err(|source| {
            LandlockError::OpenPath {
                path: path.clone(),
                source: io::Error::new(io::ErrorKind::InvalidInput, source),
            }
        })?;

        let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(LandlockError::OpenPath {
                path: path.clone(),
                source: io::Error::last_os_error(),
            });
        }

        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    fn syscall_create_ruleset(attr: &LandlockRulesetAttr) -> Result<OwnedFd, LandlockError> {
        let fd = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                attr as *const LandlockRulesetAttr,
                std::mem::size_of::<LandlockRulesetAttr>(),
                0,
            )
        };
        if fd < 0 {
            return Err(last_error("landlock_create_ruleset"));
        }
        Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
    }

    fn syscall_add_rule(
        ruleset_fd: i32,
        attr: &LandlockPathBeneathAttr,
    ) -> Result<(), LandlockError> {
        let result = unsafe {
            libc::syscall(
                libc::SYS_landlock_add_rule,
                ruleset_fd,
                LANDLOCK_RULE_PATH_BENEATH,
                attr as *const LandlockPathBeneathAttr,
                0,
            )
        };
        if result < 0 {
            return Err(last_error("landlock_add_rule"));
        }
        Ok(())
    }

    fn syscall_restrict_self(ruleset_fd: i32) -> Result<(), LandlockError> {
        let result = unsafe { libc::syscall(libc::SYS_landlock_restrict_self, ruleset_fd, 0) };
        if result < 0 {
            return Err(last_error("landlock_restrict_self"));
        }
        Ok(())
    }

    fn last_error(operation: &'static str) -> LandlockError {
        LandlockError::Syscall {
            operation,
            source: io::Error::last_os_error(),
        }
    }

    fn kernel_landlock_abi() -> Result<i64, LandlockError> {
        let version = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                std::ptr::null::<libc::c_void>(),
                0,
                LANDLOCK_CREATE_RULESET_VERSION,
            )
        };
        if version < 0 {
            return Err(last_error("landlock_create_ruleset(version)"));
        }
        Ok(version)
    }
}
