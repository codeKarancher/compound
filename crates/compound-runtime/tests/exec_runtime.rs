use compound_runtime::{exec, sanitize_environment, ExecOptions, RuntimeError};
use std::{
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

static TEMP_ID: AtomicU64 = AtomicU64::new(0);

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn temp_dir() -> PathBuf {
    let id = TEMP_ID.fetch_add(1, Ordering::Relaxed);
    let dir =
        std::env::temp_dir().join(format!("compound-runtime-test-{}-{id}", std::process::id()));
    fs::create_dir_all(&dir).unwrap_or_else(|err| panic!("create {}: {err}", dir.display()));
    dir
}

#[test]
fn exec_rejects_missing_command() {
    let options = ExecOptions {
        fs_lock: repo_root().join("fs-lock.compound.yaml"),
        workdir: None,
        command: Vec::new(),
    };

    let error = exec(&options).expect_err("missing command should fail");

    assert!(matches!(error, RuntimeError::MissingCommand));
}

#[test]
fn sanitizer_removes_dangerous_environment_variables() {
    std::env::set_var("LD_PRELOAD", "/tmp/inject.so");
    std::env::set_var("PYTHONPATH", "/tmp/python");
    std::env::set_var("NODE_OPTIONS", "--require /tmp/inject.js");

    sanitize_environment();

    assert!(std::env::var_os("LD_PRELOAD").is_none());
    assert!(std::env::var_os("PYTHONPATH").is_none());
    assert!(std::env::var_os("NODE_OPTIONS").is_none());
}

#[test]
fn invalid_fs_lock_fails_before_target_can_run() {
    let dir = temp_dir();
    let lock = dir.join("invalid-fs-lock.compound.yaml");
    let marker = dir.join("marker");
    fs::write(
        &lock,
        r#"
version: 1
metadata:
  name: invalid
source:
  root: fs.compound.yaml
policy:
  default: inherit
  paths:
    - path: /tmp
      access: [read]
"#,
    )
    .expect("write invalid lock");

    let options = ExecOptions {
        fs_lock: lock,
        workdir: None,
        command: vec![
            OsString::from("sh"),
            OsString::from("-c"),
            OsString::from(format!("touch {}", marker.display())),
        ],
    };

    let error = exec(&options).expect_err("invalid fs lock should fail");

    assert!(matches!(error, RuntimeError::InvalidFsLock(_)));
    assert!(!marker.exists(), "target command must not run");
}

#[cfg(not(target_os = "linux"))]
#[test]
fn non_linux_exec_fails_closed_before_target_can_run() {
    let dir = temp_dir();
    let marker = dir.join("marker");
    let options = ExecOptions {
        fs_lock: repo_root().join("fs-lock.compound.yaml"),
        workdir: None,
        command: vec![
            OsString::from("sh"),
            OsString::from("-c"),
            OsString::from(format!("touch {}", marker.display())),
        ],
    };

    let error = exec(&options).expect_err("non-Linux runtime should fail closed");

    assert!(matches!(error, RuntimeError::UnsupportedPlatform));
    assert!(!marker.exists(), "target command must not run");
}
