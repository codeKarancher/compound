use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
};

static TEMP_ID: AtomicU64 = AtomicU64::new(0);

fn compoundd_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_compoundd"))
}

fn temp_dir() -> PathBuf {
    let id = TEMP_ID.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("compoundd-cli-test-{}-{id}", std::process::id()));
    fs::create_dir_all(&dir).unwrap_or_else(|err| panic!("create {}: {err}", dir.display()));
    dir
}

fn write_tcp_lock(dir: &Path) -> PathBuf {
    let lock = dir.join("tcp-lock.compound.yaml");
    fs::write(
        &lock,
        r#"
version: 1
kind: tcp-lock
metadata:
  name: compoundd-cli-test
source:
  root: tcp.compound.yaml
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
    - cidr: 198.51.100.10/32
      ports: [443]
      protocol: tcp
"#,
    )
    .expect("write tcp lock");
    lock
}

fn run(args: &[&str]) -> Output {
    Command::new(compoundd_bin())
        .args(args)
        .output()
        .expect("run compoundd")
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

#[test]
fn plan_prints_network_setup_without_starting_gateway() {
    let dir = temp_dir();
    let lock = write_tcp_lock(&dir);

    let output = run(&[
        "plan",
        "--tcp-lock",
        lock.to_str().unwrap(),
        "--jail-id",
        "cli-01",
    ]);

    assert_success(&output);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("ip netns add compound-cli01"));
    assert!(stdout.contains("ip protocol tcp tproxy ip to 10.200.0.1:15080"));
    assert!(!stdout.contains("compoundd gateway"));
}

#[test]
fn apply_and_cleanup_dry_run_print_commands_without_privileges() {
    let dir = temp_dir();
    let lock = write_tcp_lock(&dir);

    let apply = run(&[
        "apply",
        "--tcp-lock",
        lock.to_str().unwrap(),
        "--jail-id",
        "cli-02",
        "--dry-run",
    ]);
    assert_success(&apply);
    let apply_stdout = String::from_utf8_lossy(&apply.stdout);
    assert!(apply_stdout.contains("ip netns add compound-cli02"));

    let cleanup = run(&["cleanup", "--jail-id", "cli-02", "--dry-run"]);
    assert_success(&cleanup);
    let cleanup_stdout = String::from_utf8_lossy(&cleanup.stdout);
    assert!(cleanup_stdout.contains("ip netns delete compound-cli02"));
}

#[test]
fn gateway_rejects_invalid_lock_before_binding_listener() {
    let dir = temp_dir();
    let lock = dir.join("invalid-tcp-lock.compound.yaml");
    fs::write(
        &lock,
        r#"
version: 1
kind: tcp-lock
metadata:
  name: invalid
source:
  root: tcp.compound.yaml
tcp:
  default: deny
  allow: []
"#,
    )
    .expect("write invalid lock");

    let output = run(&[
        "gateway",
        "--tcp-lock",
        lock.to_str().unwrap(),
        "--listen",
        "127.0.0.1:0",
    ]);

    assert_failure(&output);
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("invalid TCP lock"),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
}
