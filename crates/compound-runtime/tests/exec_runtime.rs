use compound_runtime::{
    exec, prepare_environment, sanitize_environment, ExecOptions, RuntimeError,
};
use std::{
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Mutex,
    },
};

static TEMP_ID: AtomicU64 = AtomicU64::new(0);
static ENV_LOCK: Mutex<()> = Mutex::new(());

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
        tcp_lock: None,
        jail_id: "default".to_owned(),
        workdir: None,
        uid: None,
        gid: None,
        clear_environment: false,
        keep_environment: Vec::new(),
        command: Vec::new(),
    };

    let error = exec(&options).expect_err("missing command should fail");

    assert!(matches!(error, RuntimeError::MissingCommand));
}

#[test]
fn sanitizer_removes_dangerous_environment_variables() {
    let _guard = ENV_LOCK.lock().expect("lock environment test");
    std::env::set_var("LD_PRELOAD", "/tmp/inject.so");
    std::env::set_var("PYTHONPATH", "/tmp/python");
    std::env::set_var("NODE_OPTIONS", "--require /tmp/inject.js");

    sanitize_environment();

    assert!(std::env::var_os("LD_PRELOAD").is_none());
    assert!(std::env::var_os("PYTHONPATH").is_none());
    assert!(std::env::var_os("NODE_OPTIONS").is_none());
}

#[test]
fn clear_environment_retains_only_requested_safe_variables() {
    let _guard = ENV_LOCK.lock().expect("lock environment test");
    let snapshot: Vec<_> = std::env::vars_os().collect();
    std::env::set_var("COMPOUND_TEST_KEEP", "keep");
    std::env::set_var("COMPOUND_TEST_DROP", "drop");
    std::env::set_var("LD_PRELOAD", "/tmp/inject.so");

    let options = ExecOptions {
        fs_lock: repo_root().join("fs-lock.compound.yaml"),
        tcp_lock: None,
        jail_id: "default".to_owned(),
        workdir: None,
        uid: None,
        gid: None,
        clear_environment: true,
        keep_environment: vec![
            OsString::from("COMPOUND_TEST_KEEP"),
            OsString::from("LD_PRELOAD"),
        ],
        command: vec![OsString::from("true")],
    };

    prepare_environment(&options);

    assert_eq!(std::env::var("COMPOUND_TEST_KEEP").as_deref(), Ok("keep"));
    assert!(std::env::var_os("COMPOUND_TEST_DROP").is_none());
    assert!(std::env::var_os("LD_PRELOAD").is_none());

    std::env::vars_os().for_each(|(key, _)| std::env::remove_var(key));
    for (key, value) in snapshot {
        std::env::set_var(key, value);
    }
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
        tcp_lock: None,
        jail_id: "default".to_owned(),
        workdir: None,
        uid: None,
        gid: None,
        clear_environment: false,
        keep_environment: Vec::new(),
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
        tcp_lock: None,
        jail_id: "default".to_owned(),
        workdir: None,
        uid: None,
        gid: None,
        clear_environment: false,
        keep_environment: Vec::new(),
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
