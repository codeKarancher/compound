#![cfg(target_os = "linux")]

use std::{
    ffi::OsString,
    fs,
    fs::File,
    os::fd::AsRawFd,
    os::unix::{ffi::OsStringExt, fs::PermissionsExt},
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

fn write_raw_lock(dir: &Path, contents: &str) -> PathBuf {
    let lock = dir.join("fs-lock.compound.yaml");
    fs::write(&lock, contents).expect("write raw fs lock");
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

fn two_path_rules(first: (&Path, &str), second: (&Path, &str)) -> String {
    format!(
        "{}{}",
        path_rule(first.0, first.1),
        path_rule(second.0, second.1)
    )
}

fn shell_quote(path: &Path) -> String {
    format!("'{}'", path.display().to_string().replace('\'', "'\\''"))
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

fn assert_target_never_runs(lock: &Path) {
    let output = run_compound(lock, "exit 42");

    assert!(
        !output.status.success(),
        "invalid lock unexpectedly allowed target to run"
    );
    assert!(
        output.status.code() != Some(42),
        "target command ran before lock validation failed"
    );
}

fn run_compound_with_workdir(lock: &Path, workdir: &Path, command: &str) -> Output {
    Command::new(compound_bin())
        .arg("exec")
        .arg("--fs-lock")
        .arg(lock)
        .arg("--workdir")
        .arg(workdir)
        .arg("--")
        .arg("/bin/sh")
        .arg("-c")
        .arg(command)
        .output()
        .expect("run compound")
}

fn run_compound_inheriting_fd(lock: &Path, command: &str, file: &File) -> Output {
    let fd = file.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    assert!(flags >= 0, "F_GETFD failed");
    let result = unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) };
    assert_eq!(result, 0, "F_SETFD failed");

    let fd_env = OsString::from_vec(fd.to_string().into_bytes());
    let output = Command::new(compound_bin())
        .arg("exec")
        .arg("--fs-lock")
        .arg(lock)
        .arg("--")
        .arg("/bin/sh")
        .arg("-c")
        .arg(command)
        .env("COMPOUND_TEST_FD", fd_env)
        .output()
        .expect("run compound");

    let result = unsafe { libc::fcntl(fd, libc::F_SETFD, flags) };
    assert_eq!(result, 0, "restore F_SETFD failed");

    output
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
fn landlock_denies_create_outside_grants() {
    let dir = temp_dir();
    let allowed = dir.join("allowed");
    let denied = dir.join("denied");
    fs::create_dir_all(&allowed).expect("create allowed");
    fs::create_dir_all(&denied).expect("create denied");
    let lock = write_lock(&dir, &path_rule(&allowed, "read, list, write, create"));

    let output = run_compound(&lock, &format!("mkdir {}", denied.join("newdir").display()));

    assert!(
        !output.status.success(),
        "denied directory create unexpectedly succeeded"
    );
    assert!(!denied.join("newdir").exists());
}

#[test]
fn landlock_denies_delete_outside_grants() {
    let dir = temp_dir();
    let allowed = dir.join("allowed");
    let denied = dir.join("denied");
    fs::create_dir_all(&allowed).expect("create allowed");
    fs::create_dir_all(&denied).expect("create denied");
    fs::write(denied.join("secret"), "secret").expect("write secret");
    let lock = write_lock(
        &dir,
        &path_rule(&allowed, "read, list, write, create, delete"),
    );

    let output = run_compound(&lock, &format!("rm {}", denied.join("secret").display()));

    assert!(
        !output.status.success(),
        "denied delete unexpectedly succeeded"
    );
    assert!(denied.join("secret").exists());
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
fn landlock_denies_parent_traversal_escape() {
    let dir = temp_dir();
    let allowed = dir.join("allowed");
    let denied = dir.join("denied");
    fs::create_dir_all(&allowed).expect("create allowed");
    fs::create_dir_all(&denied).expect("create denied");
    fs::write(denied.join("secret"), "secret").expect("write secret");
    let lock = write_lock(&dir, &path_rule(&allowed, "read, list"));

    let output = run_compound(
        &lock,
        &format!("cat {}/../denied/secret", allowed.display()),
    );

    assert!(
        !output.status.success(),
        "parent traversal escape read succeeded"
    );
}

#[test]
fn landlock_denies_workdir_outside_grants() {
    let dir = temp_dir();
    let allowed = dir.join("allowed");
    let denied = dir.join("denied");
    fs::create_dir_all(&allowed).expect("create allowed");
    fs::create_dir_all(&denied).expect("create denied");
    fs::write(denied.join("secret"), "secret").expect("write secret");
    let lock = write_lock(&dir, &path_rule(&allowed, "read, list"));

    let output = run_compound_with_workdir(&lock, &denied, "cat secret");

    assert!(
        !output.status.success(),
        "workdir outside grants allowed a read escape"
    );
}

#[test]
fn landlock_denies_realistic_secret_fixture_reads() {
    let dir = temp_dir();
    let allowed = dir.join("workspace");
    let home = dir.join("home");
    let browser = home.join(".config/browser/Default");
    fs::create_dir_all(&allowed).expect("create workspace");
    fs::create_dir_all(home.join(".ssh")).expect("create ssh dir");
    fs::create_dir_all(home.join(".aws")).expect("create aws dir");
    fs::create_dir_all(home.join(".kube")).expect("create kube dir");
    fs::create_dir_all(home.join(".docker")).expect("create docker dir");
    fs::create_dir_all(&browser).expect("create browser profile dir");
    fs::write(home.join(".ssh/id_rsa"), "fake ssh private key").expect("write ssh secret");
    fs::write(home.join(".aws/credentials"), "fake aws credentials").expect("write aws secret");
    fs::write(home.join(".kube/config"), "fake kube config").expect("write kube secret");
    fs::write(home.join(".docker/config.json"), "fake docker auth").expect("write docker secret");
    fs::write(browser.join("Cookies"), "fake browser token").expect("write browser secret");
    let lock = write_lock(&dir, &path_rule(&allowed, "read, list, write, create"));
    let command = format!(
        r#"for file in {} {} {} {} {}; do if cat "$file" >/dev/null 2>&1; then exit 42; fi; done"#,
        shell_quote(&home.join(".ssh/id_rsa")),
        shell_quote(&home.join(".aws/credentials")),
        shell_quote(&home.join(".kube/config")),
        shell_quote(&home.join(".docker/config.json")),
        shell_quote(&browser.join("Cookies"))
    );

    let output = run_compound(&lock, &command);

    assert!(
        output.status.success(),
        "one or more realistic secret fixtures were readable: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn landlock_denies_inherited_fd_escape() {
    let dir = temp_dir();
    let allowed = dir.join("allowed");
    let denied = dir.join("denied");
    fs::create_dir_all(&allowed).expect("create allowed");
    fs::create_dir_all(&denied).expect("create denied");
    fs::write(denied.join("secret"), "secret").expect("write secret");
    let secret = File::open(denied.join("secret")).expect("open denied secret before confinement");
    let lock = write_lock(&dir, &path_rule(&allowed, "read, list"));

    let output = run_compound_inheriting_fd(&lock, "cat /proc/self/fd/$COMPOUND_TEST_FD", &secret);

    assert!(
        !output.status.success(),
        "inherited file descriptor escaped Landlock restriction"
    );
}

#[test]
fn landlock_denies_dev_fd_escape() {
    let dir = temp_dir();
    let allowed = dir.join("allowed");
    let denied = dir.join("denied");
    fs::create_dir_all(&allowed).expect("create allowed");
    fs::create_dir_all(&denied).expect("create denied");
    fs::write(denied.join("secret"), "secret").expect("write secret");
    let secret = File::open(denied.join("secret")).expect("open denied secret before confinement");
    let lock = write_lock(&dir, &path_rule(&allowed, "read, list"));

    let output = run_compound_inheriting_fd(&lock, "cat /dev/fd/$COMPOUND_TEST_FD", &secret);

    assert!(
        !output.status.success(),
        "/dev/fd escaped Landlock restriction"
    );
}

#[test]
fn landlock_documents_existing_hard_link_reachability() {
    let dir = temp_dir();
    let allowed = dir.join("allowed");
    let denied = dir.join("denied");
    fs::create_dir_all(&allowed).expect("create allowed");
    fs::create_dir_all(&denied).expect("create denied");
    let denied_secret = denied.join("secret");
    let allowed_link = allowed.join("secret-hardlink");
    fs::write(&denied_secret, "shared inode secret").expect("write denied secret");
    fs::hard_link(&denied_secret, &allowed_link).expect("create hard link");
    let lock = write_lock(&dir, &path_rule(&allowed, "read, list"));

    let output = run_compound(&lock, &format!("cat {}", shell_quote(&allowed_link)));

    assert!(
        output.status.success(),
        "hard link inside granted tree was not readable: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "shared inode secret"
    );
}

#[test]
fn landlock_separates_list_from_read() {
    let dir = temp_dir();
    let allowed = dir.join("allowed");
    fs::create_dir_all(&allowed).expect("create allowed");
    fs::write(allowed.join("secret"), "secret").expect("write secret");
    let lock = write_lock(&dir, &path_rule(&allowed, "list"));

    let list_output = run_compound(&lock, &format!("ls {}", allowed.display()));
    let read_output = run_compound(&lock, &format!("cat {}", allowed.join("secret").display()));

    assert!(
        list_output.status.success(),
        "list grant did not allow directory enumeration"
    );
    assert!(
        !read_output.status.success(),
        "list grant allowed file content read"
    );
}

#[test]
fn landlock_separates_read_from_list() {
    let dir = temp_dir();
    let allowed = dir.join("allowed");
    let secret = allowed.join("secret");
    fs::create_dir_all(&allowed).expect("create allowed");
    fs::write(&secret, "secret").expect("write secret");
    let lock = write_lock(&dir, &path_rule(&secret, "read"));

    let read_output = run_compound(&lock, &format!("cat {}", secret.display()));
    let list_output = run_compound(&lock, &format!("ls {}", allowed.display()));

    assert!(
        read_output.status.success(),
        "read grant did not allow a known file read"
    );
    assert!(
        !list_output.status.success(),
        "read grant allowed parent directory listing"
    );
}

#[test]
fn landlock_denies_create_when_only_write_is_granted() {
    let dir = temp_dir();
    let allowed = dir.join("allowed");
    let existing = allowed.join("existing");
    fs::create_dir_all(&allowed).expect("create allowed");
    fs::write(&existing, "old").expect("write existing");
    let lock = write_lock(&dir, &path_rule(&allowed, "read, list, write"));

    let modify_output = run_compound(&lock, &format!("printf new > {}", existing.display()));
    let create_output = run_compound(&lock, &format!("touch {}", allowed.join("new").display()));

    assert!(
        modify_output.status.success(),
        "write grant did not allow modifying existing file"
    );
    assert!(
        !create_output.status.success(),
        "write grant allowed creating a new file"
    );
    assert!(!allowed.join("new").exists());
}

#[test]
fn landlock_denies_delete_when_only_write_is_granted() {
    let dir = temp_dir();
    let allowed = dir.join("allowed");
    let existing = allowed.join("existing");
    fs::create_dir_all(&allowed).expect("create allowed");
    fs::write(&existing, "old").expect("write existing");
    let lock = write_lock(&dir, &path_rule(&allowed, "read, list, write"));

    let output = run_compound(&lock, &format!("rm {}", existing.display()));

    assert!(
        !output.status.success(),
        "write grant allowed deleting an existing file"
    );
    assert!(existing.exists());
}

#[test]
fn landlock_denies_rename_across_policy_boundary() {
    let dir = temp_dir();
    let allowed = dir.join("allowed");
    let denied = dir.join("denied");
    fs::create_dir_all(&allowed).expect("create allowed");
    fs::create_dir_all(&denied).expect("create denied");
    fs::write(allowed.join("file"), "data").expect("write file");
    let lock = write_lock(
        &dir,
        &path_rule(&allowed, "read, list, write, create, delete, rename"),
    );

    let output = run_compound(
        &lock,
        &format!(
            "mv {} {}",
            allowed.join("file").display(),
            denied.join("file").display()
        ),
    );

    assert!(
        !output.status.success(),
        "rename across policy boundary succeeded"
    );
    assert!(allowed.join("file").exists());
    assert!(!denied.join("file").exists());
}

#[test]
fn landlock_denies_rename_from_denied_into_allowed() {
    let dir = temp_dir();
    let allowed = dir.join("allowed");
    let denied = dir.join("denied");
    fs::create_dir_all(&allowed).expect("create allowed");
    fs::create_dir_all(&denied).expect("create denied");
    fs::write(denied.join("file"), "data").expect("write denied file");
    let lock = write_lock(
        &dir,
        &path_rule(&allowed, "read, list, write, create, delete, rename"),
    );

    let output = run_compound(
        &lock,
        &format!(
            "mv {} {}",
            shell_quote(&denied.join("file")),
            shell_quote(&allowed.join("file"))
        ),
    );

    assert!(
        !output.status.success(),
        "rename from denied tree into allowed tree succeeded"
    );
    assert!(denied.join("file").exists());
    assert!(!allowed.join("file").exists());
}

#[test]
fn landlock_documents_rename_target_create_semantics() {
    let dir = temp_dir();
    let source = dir.join("source");
    let target = dir.join("target");
    fs::create_dir_all(&source).expect("create source");
    fs::create_dir_all(&target).expect("create target");
    fs::write(source.join("file"), "data").expect("write source file");
    let lock = write_lock(
        &dir,
        &two_path_rules(
            (&source, "read, list, write, create, delete, rename"),
            (&target, "read, list, write, create, delete"),
        ),
    );

    let output = run_compound(
        &lock,
        &format!(
            "mv {} {}",
            shell_quote(&source.join("file")),
            shell_quote(&target.join("file"))
        ),
    );

    assert!(
        output.status.success(),
        "rename with source rename and target create/delete grants failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!source.join("file").exists());
    assert!(target.join("file").exists());
}

#[test]
fn landlock_denies_hard_link_creation_across_policy_boundary() {
    let dir = temp_dir();
    let allowed = dir.join("allowed");
    let denied = dir.join("denied");
    fs::create_dir_all(&allowed).expect("create allowed");
    fs::create_dir_all(&denied).expect("create denied");
    fs::write(denied.join("secret"), "secret").expect("write denied secret");
    let lock = write_lock(
        &dir,
        &path_rule(&allowed, "read, list, write, create, delete, rename"),
    );

    let output = run_compound(
        &lock,
        &format!(
            "ln {} {}",
            shell_quote(&denied.join("secret")),
            shell_quote(&allowed.join("linked-secret"))
        ),
    );

    assert!(
        !output.status.success(),
        "hard link creation from denied tree into allowed tree succeeded"
    );
    assert!(!allowed.join("linked-secret").exists());
}

#[test]
fn landlock_rejects_relative_lock_path_before_target_runs() {
    let dir = temp_dir();
    let lock = write_raw_lock(
        &dir,
        r#"
version: 1
kind: fs-lock
metadata:
  name: invalid-relative-path
source:
  root: fs.compound.yaml
policy:
  default: deny
  paths:
    - path: relative/path
      access: [read]
  inherited_file_descriptors: deny
"#,
    );

    assert_target_never_runs(&lock);
}

#[test]
fn landlock_rejects_inherit_default_before_target_runs() {
    let dir = temp_dir();
    let lock = write_raw_lock(
        &dir,
        &format!(
            r#"
version: 1
kind: fs-lock
metadata:
  name: invalid-inherit-default
source:
  root: fs.compound.yaml
policy:
  default: inherit
  paths:
{}  inherited_file_descriptors: deny
"#,
            path_rule(&dir, "read, list")
        ),
    );

    assert_target_never_runs(&lock);
}

#[test]
fn landlock_rejects_empty_paths_before_target_runs() {
    let dir = temp_dir();
    let lock = write_raw_lock(
        &dir,
        r#"
version: 1
kind: fs-lock
metadata:
  name: invalid-empty-paths
source:
  root: fs.compound.yaml
policy:
  default: deny
  paths: []
  inherited_file_descriptors: deny
"#,
    );

    assert_target_never_runs(&lock);
}

#[test]
fn landlock_rejects_unsupported_version_before_target_runs() {
    let dir = temp_dir();
    let lock = write_raw_lock(
        &dir,
        &format!(
            r#"
version: 999
kind: fs-lock
metadata:
  name: invalid-version
source:
  root: fs.compound.yaml
policy:
  default: deny
  paths:
{}  inherited_file_descriptors: deny
"#,
            path_rule(&dir, "read, list")
        ),
    );

    assert_target_never_runs(&lock);
}

#[test]
fn landlock_rejects_conflicting_duplicate_paths_before_target_runs() {
    let dir = temp_dir();
    let lock = write_raw_lock(
        &dir,
        &format!(
            r#"
version: 1
kind: fs-lock
metadata:
  name: invalid-duplicate-paths
source:
  root: fs.compound.yaml
policy:
  default: deny
  paths:
{}{}  inherited_file_descriptors: deny
"#,
            path_rule(&dir, "read"),
            path_rule(&dir, "read, write")
        ),
    );

    assert_target_never_runs(&lock);
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
