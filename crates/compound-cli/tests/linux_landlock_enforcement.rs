#![cfg(target_os = "linux")]

use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
};

static TEMP_ID: AtomicU64 = AtomicU64::new(0);

fn compound_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_compound"))
}

fn temp_dir() -> PathBuf {
    let id = TEMP_ID.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "compound-linux-landlock-test-{}-{id}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).unwrap_or_else(|err| panic!("create {}: {err}", dir.display()));
    dir
}

fn write_lock(dir: &Path, paths: &str) -> PathBuf {
    let lock = dir.join("fs-lock.compound.yaml");
    fs::write(
        &lock,
        format!(
            r#"
version: 1
kind: fs-lock
metadata:
  name: linux-landlock-test
source:
  root: fs.compound.yaml
policy:
  default: deny
  paths:
{runtime_paths}
{paths}
  inherited_file_descriptors: deny
"#,
            runtime_paths = runtime_paths(),
            paths = paths
        ),
    )
    .expect("write fs lock");
    lock
}

fn runtime_paths() -> &'static str {
    r#"    - path: /bin
      access: [read, list, execute]
    - path: /usr
      access: [read, list, execute]
    - path: /lib
      access: [read, list, execute]
    - path: /lib64
      access: [read, list, execute]
    - path: /etc
      access: [read, list]
    - path: /proc/self
      access: [read, list]
"#
}

fn path_rule(path: &Path, access: &str) -> String {
    format!(
        "    - path: {}\n      access: [{}]\n",
        path.display(),
        access
    )
}

fn run_compound(lock: &Path, command: &str) -> Output {
    Command::new(compound_bin())
        .arg("exec")
        .arg("--fs-lock")
        .arg(lock)
        .arg("--")
        .arg("/bin/sh")
        .arg("-c")
        .arg(command)
        .output()
        .expect("run compound")
}

#[test]
fn landlock_allows_write_inside_granted_directory() {
    let dir = temp_dir();
    let allowed = dir.join("allowed");
    fs::create_dir_all(&allowed).expect("create allowed");
    let lock = write_lock(
        &dir,
        &path_rule(&allowed, "read, list, write, create, delete, rename"),
    );

    let output = run_compound(
        &lock,
        &format!("printf hello > {}", allowed.join("out").display()),
    );

    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(fs::read_to_string(allowed.join("out")).unwrap(), "hello");
}

#[test]
fn landlock_denies_read_outside_grants() {
    let dir = temp_dir();
    let allowed = dir.join("allowed");
    let denied = dir.join("denied");
    fs::create_dir_all(&allowed).expect("create allowed");
    fs::create_dir_all(&denied).expect("create denied");
    fs::write(denied.join("secret"), "secret").expect("write secret");
    let lock = write_lock(&dir, &path_rule(&allowed, "read, list, write, create"));

    let output = run_compound(&lock, &format!("cat {}", denied.join("secret").display()));

    assert!(
        !output.status.success(),
        "denied read unexpectedly succeeded"
    );
}

#[test]
fn landlock_denies_write_outside_grants() {
    let dir = temp_dir();
    let allowed = dir.join("allowed");
    let denied = dir.join("denied");
    fs::create_dir_all(&allowed).expect("create allowed");
    fs::create_dir_all(&denied).expect("create denied");
    let lock = write_lock(&dir, &path_rule(&allowed, "read, list, write, create"));

    let output = run_compound(
        &lock,
        &format!("printf nope > {}", denied.join("out").display()),
    );

    assert!(
        !output.status.success(),
        "denied write unexpectedly succeeded"
    );
    assert!(!denied.join("out").exists());
}

#[test]
fn landlock_denies_execute_without_execute_grant() {
    let dir = temp_dir();
    let allowed = dir.join("allowed");
    fs::create_dir_all(&allowed).expect("create allowed");
    let script = allowed.join("script.sh");
    fs::write(&script, "#!/bin/sh\nexit 0\n").expect("write script");
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).expect("chmod script");
    let lock = write_lock(&dir, &path_rule(&allowed, "read, list"));

    let output = run_compound(&lock, &script.display().to_string());

    assert!(
        !output.status.success(),
        "script executed without execute grant"
    );
}

#[test]
fn landlock_denies_symlink_escape() {
    let dir = temp_dir();
    let allowed = dir.join("allowed");
    let denied = dir.join("denied");
    fs::create_dir_all(&allowed).expect("create allowed");
    fs::create_dir_all(&denied).expect("create denied");
    fs::write(denied.join("secret"), "secret").expect("write secret");
    std::os::unix::fs::symlink(denied.join("secret"), allowed.join("link"))
        .expect("create symlink");
    let lock = write_lock(&dir, &path_rule(&allowed, "read, list"));

    let output = run_compound(&lock, &format!("cat {}", allowed.join("link").display()));

    assert!(!output.status.success(), "symlink escape read succeeded");
}

#[test]
fn landlock_restrictions_apply_to_descendants() {
    let dir = temp_dir();
    let allowed = dir.join("allowed");
    let denied = dir.join("denied");
    fs::create_dir_all(&allowed).expect("create allowed");
    fs::create_dir_all(&denied).expect("create denied");
    fs::write(denied.join("secret"), "secret").expect("write secret");
    let lock = write_lock(&dir, &path_rule(&allowed, "read, list"));

    let output = run_compound(
        &lock,
        &format!("/bin/sh -c 'cat {}'", denied.join("secret").display()),
    );

    assert!(
        !output.status.success(),
        "descendant escaped Landlock restriction"
    );
}
