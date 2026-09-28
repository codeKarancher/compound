use std::{
    fs,
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
        "compound-cli-integration-test-{}-{id}",
        std::process::id()
    ));
    fs::create_dir_all(&dir).unwrap_or_else(|err| panic!("create {}: {err}", dir.display()));
    dir
}

fn run(args: &[&str], cwd: &Path) -> Output {
    Command::new(compound_bin())
        .args(args)
        .current_dir(cwd)
        .output()
        .expect("run compound")
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "expected success\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn assert_failure(output: &Output) {
    assert!(
        !output.status.success(),
        "expected failure\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn write_fs_policy(dir: &Path) -> PathBuf {
    let allowed = dir.join("allowed");
    fs::create_dir_all(&allowed).expect("create allowed dir");
    let policy = dir.join("fs.compound.yaml");
    fs::write(
        &policy,
        format!(
            r#"
version: 1
kind: fs-policy
metadata:
  name: cli-fs-test
policy:
  default: deny
  paths:
    - path: {}
      access: [read, list, write, create, delete, rename]
  inherited_file_descriptors: deny
"#,
            allowed.display()
        ),
    )
    .expect("write fs policy");
    policy
}

fn write_tcp_policy(dir: &Path) -> PathBuf {
    let policy = dir.join("tcp.compound.yaml");
    fs::write(
        &policy,
        r#"
version: 1
kind: tcp-policy
metadata:
  name: cli-tcp-test
tcp:
  default: deny
  direct:
    tcp: deny
    udp: deny
    dns: deny
    raw_sockets: deny
  encrypted_hostname_unverifiable: deny
  deny_cidrs:
    - 127.0.0.0/8
  allow:
    - host: Example.COM
      ports: [443, 443]
      protocol: tls
"#,
    )
    .expect("write tcp policy");
    policy
}

#[test]
fn fs_lock_writes_lock_file() {
    let dir = temp_dir();
    let policy = write_fs_policy(&dir);
    let output_path = dir.join("fs-lock.compound.yaml");

    let output = run(
        &[
            "fs",
            "lock",
            "--policy",
            policy.to_str().unwrap(),
            "--output",
            output_path.to_str().unwrap(),
        ],
        &dir,
    );

    assert_success(&output);
    let lock = fs::read_to_string(&output_path).expect("read fs lock");
    assert!(lock.contains("kind: fs-lock"));
    assert!(lock.contains("inherited_file_descriptors: deny"));
}

#[test]
fn fs_lock_check_validates_without_writing_output() {
    let dir = temp_dir();
    let policy = write_fs_policy(&dir);
    let output_path = dir.join("should-not-exist.yaml");

    let output = run(
        &[
            "fs",
            "lock",
            "--policy",
            policy.to_str().unwrap(),
            "--output",
            output_path.to_str().unwrap(),
            "--check",
        ],
        &dir,
    );

    assert_success(&output);
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("filesystem policy OK"),
        "stdout={}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(!output_path.exists(), "--check wrote an output file");
}

#[test]
fn fs_explain_prints_generated_lock_summary() {
    let dir = temp_dir();
    let policy = write_fs_policy(&dir);
    let lock_path = dir.join("fs-lock.compound.yaml");
    assert_success(&run(
        &[
            "fs",
            "lock",
            "--policy",
            policy.to_str().unwrap(),
            "--output",
            lock_path.to_str().unwrap(),
        ],
        &dir,
    ));

    let output = run(
        &["fs", "explain", "--policy", lock_path.to_str().unwrap()],
        &dir,
    );

    assert_success(&output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("filesystem policy:"));
    assert!(stdout.contains("default: deny"));
    assert!(stdout.contains("paths: 1"));
}

#[test]
fn tcp_lock_writes_lock_file() {
    let dir = temp_dir();
    let policy = write_tcp_policy(&dir);
    let output_path = dir.join("tcp-lock.compound.yaml");

    let output = run(
        &[
            "tcp",
            "lock",
            "--policy",
            policy.to_str().unwrap(),
            "--output",
            output_path.to_str().unwrap(),
        ],
        &dir,
    );

    assert_success(&output);
    let lock = fs::read_to_string(&output_path).expect("read tcp lock");
    assert!(lock.contains("kind: tcp-lock"));
    assert!(lock.contains("host: example.com"));
    assert!(lock.contains("ports:"));
}

#[test]
fn tcp_lock_check_validates_without_writing_output() {
    let dir = temp_dir();
    let policy = write_tcp_policy(&dir);
    let output_path = dir.join("should-not-exist.yaml");

    let output = run(
        &[
            "tcp",
            "lock",
            "--policy",
            policy.to_str().unwrap(),
            "--output",
            output_path.to_str().unwrap(),
            "--check",
        ],
        &dir,
    );

    assert_success(&output);
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("TCP policy OK"),
        "stdout={}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(!output_path.exists(), "--check wrote an output file");
}

#[test]
fn tcp_explain_prints_generated_lock_summary() {
    let dir = temp_dir();
    let policy = write_tcp_policy(&dir);
    let lock_path = dir.join("tcp-lock.compound.yaml");
    assert_success(&run(
        &[
            "tcp",
            "lock",
            "--policy",
            policy.to_str().unwrap(),
            "--output",
            lock_path.to_str().unwrap(),
        ],
        &dir,
    ));

    let output = run(
        &["tcp", "explain", "--policy", lock_path.to_str().unwrap()],
        &dir,
    );

    assert_success(&output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("TCP policy:"));
    assert!(stdout.contains("default: deny"));
    assert!(stdout.contains("allow: 1"));
    assert!(stdout.contains("example.com"));
}

#[test]
fn fs_lock_rejects_invalid_policy_and_preserves_existing_output() {
    let dir = temp_dir();
    let policy = dir.join("invalid-fs.compound.yaml");
    let output_path = dir.join("fs-lock.compound.yaml");
    fs::write(
        &policy,
        r#"
version: 1
kind: fs-policy
metadata:
  name: invalid-fs-test
policy:
  default: inherit
  paths: []
"#,
    )
    .expect("write invalid fs policy");
    fs::write(&output_path, "sentinel").expect("write sentinel");

    let output = run(
        &[
            "fs",
            "lock",
            "--policy",
            policy.to_str().unwrap(),
            "--output",
            output_path.to_str().unwrap(),
        ],
        &dir,
    );

    assert_failure(&output);
    assert_eq!(fs::read_to_string(&output_path).unwrap(), "sentinel");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("invalid filesystem policy"),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn tcp_lock_rejects_invalid_policy_and_preserves_existing_output() {
    let dir = temp_dir();
    let policy = dir.join("invalid-tcp.compound.yaml");
    let output_path = dir.join("tcp-lock.compound.yaml");
    fs::write(
        &policy,
        r#"
version: 1
kind: tcp-policy
metadata:
  name: invalid-tcp-test
tcp:
  default: deny
  direct:
    tcp: allow
    udp: deny
    dns: deny
    raw_sockets: deny
  encrypted_hostname_unverifiable: deny
  deny_cidrs:
    - 127.0.0.0/8
  allow: []
"#,
    )
    .expect("write invalid tcp policy");
    fs::write(&output_path, "sentinel").expect("write sentinel");

    let output = run(
        &[
            "tcp",
            "lock",
            "--policy",
            policy.to_str().unwrap(),
            "--output",
            output_path.to_str().unwrap(),
        ],
        &dir,
    );

    assert_failure(&output);
    assert_eq!(fs::read_to_string(&output_path).unwrap(), "sentinel");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("invalid TCP policy"),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn fs_explain_rejects_malformed_lock_input() {
    let dir = temp_dir();
    let lock = dir.join("bad-fs-lock.compound.yaml");
    fs::write(&lock, "not: a valid fs lock\n").expect("write malformed fs lock");

    let output = run(&["fs", "explain", "--policy", lock.to_str().unwrap()], &dir);

    assert_failure(&output);
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("failed to parse YAML"),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn fs_explain_rejects_semantically_invalid_lock_input() {
    let dir = temp_dir();
    let lock = dir.join("invalid-fs-lock.compound.yaml");
    fs::write(
        &lock,
        r#"
version: 1
kind: fs-lock
metadata:
  name: invalid-fs-lock
source:
  root: fs.compound.yaml
policy:
  default: inherit
  paths: []
  inherited_file_descriptors: deny
"#,
    )
    .expect("write invalid fs lock");

    let output = run(&["fs", "explain", "--policy", lock.to_str().unwrap()], &dir);

    assert_failure(&output);
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("invalid fs lock"),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn tcp_explain_rejects_malformed_lock_input() {
    let dir = temp_dir();
    let lock = dir.join("bad-tcp-lock.compound.yaml");
    fs::write(&lock, "not: a valid tcp lock\n").expect("write malformed tcp lock");

    let output = run(
        &["tcp", "explain", "--policy", lock.to_str().unwrap()],
        &dir,
    );

    assert_failure(&output);
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("failed to parse YAML"),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn tcp_explain_rejects_semantically_invalid_lock_input() {
    let dir = temp_dir();
    let lock = dir.join("invalid-tcp-lock.compound.yaml");
    fs::write(
        &lock,
        r#"
version: 1
kind: tcp-lock
metadata:
  name: invalid-tcp-lock
source:
  root: tcp.compound.yaml
tcp:
  default: deny
  direct:
    tcp: allow
    udp: deny
    dns: deny
    raw_sockets: deny
  encrypted_hostname_unverifiable: deny
  deny_cidrs:
    - 127.0.0.0/8
  allow: []
"#,
    )
    .expect("write invalid tcp lock");

    let output = run(
        &["tcp", "explain", "--policy", lock.to_str().unwrap()],
        &dir,
    );

    assert_failure(&output);
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("invalid TCP lock"),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn exec_propagates_target_exit_code_on_linux() {
    let dir = temp_dir();
    let lock = dir.join("fs-lock.compound.yaml");
    fs::write(
        &lock,
        r#"
version: 1
kind: fs-lock
metadata:
  name: exec-exit-code-test
source:
  root: fs.compound.yaml
policy:
  default: deny
  paths:
    - path: /bin
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
  inherited_file_descriptors: deny
"#,
    )
    .expect("write exec lock");

    let output = run(
        &[
            "exec",
            "--fs-lock",
            lock.to_str().unwrap(),
            "--",
            "/bin/sh",
            "-c",
            "exit 17",
        ],
        &dir,
    );

    assert_eq!(
        output.status.code(),
        Some(17),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(not(target_os = "linux"))]
#[test]
fn exec_fails_closed_before_target_on_non_linux() {
    let dir = temp_dir();
    let lock = dir.join("fs-lock.compound.yaml");
    let marker = dir.join("target-ran");
    fs::write(
        &lock,
        r#"
version: 1
kind: fs-lock
metadata:
  name: exec-fail-closed-test
source:
  root: fs.compound.yaml
policy:
  default: deny
  paths: []
  inherited_file_descriptors: deny
"#,
    )
    .expect("write exec lock");

    let output = run(
        &[
            "exec",
            "--fs-lock",
            lock.to_str().unwrap(),
            "--",
            "/bin/sh",
            "-c",
            &format!("touch {}", marker.display()),
        ],
        &dir,
    );

    assert_failure(&output);
    assert!(!marker.exists(), "target ran on an unsupported platform");
}
