#![cfg(target_os = "linux")]

use std::{
    env, fs,
    io::{self, Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};

const UPSTREAM_IP: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 10);
const DENIED_PUBLIC_IP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 77);

fn compound_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_compound"))
}

#[test]
fn compound_exec_tcp_enforces_transparent_gateway_for_target_process() -> io::Result<()> {
    if env::var_os("COMPOUND_RUN_PRIVILEGED_NET_TESTS").is_none() {
        eprintln!(
            "skipping privileged compound exec TCP test; set COMPOUND_RUN_PRIVILEGED_NET_TESTS=1"
        );
        return Ok(());
    }
    require_command("sudo", ["-n", "true"])?;
    require_command("python3", ["--version"])?;
    require_command("ip", ["-Version"])?;
    require_command("nft", ["--version"])?;

    let dir = temp_dir()?;
    let _ = run_sudo(["ip", "addr", "del", "198.51.100.10/32", "dev", "lo"]);
    run_sudo(["ip", "addr", "add", "198.51.100.10/32", "dev", "lo"])?;
    let upstream = start_echo_server(SocketAddr::new(IpAddr::V4(UPSTREAM_IP), 0))?;
    let fs_lock = write_fs_lock(&dir)?;
    let tcp_lock = write_tcp_lock(&dir, upstream.addr.port())?;
    let jail_id = format!("exec{}", std::process::id());
    let bin_dir = compound_bin()
        .parent()
        .expect("compound binary has parent directory")
        .to_path_buf();
    let path = format!(
        "{}:{}",
        bin_dir.display(),
        env::var("PATH").unwrap_or_default()
    );
    let _cleanup = Cleanup {
        jail_id: jail_id.clone(),
        path: path.clone(),
    };

    let output = Command::new("sudo")
        .arg("-n")
        .arg("env")
        .arg(format!("PATH={path}"))
        .arg(compound_bin())
        .arg("exec")
        .arg("--fs-lock")
        .arg(&fs_lock)
        .arg("--tcp-lock")
        .arg(&tcp_lock)
        .arg("--jail-id")
        .arg(&jail_id)
        .arg("--uid")
        .arg("65534")
        .arg("--gid")
        .arg("65534")
        .arg("--")
        .arg("python3")
        .arg("-c")
        .arg(target_probe_script(upstream.addr.port()))
        .output()?;

    assert!(
        output.status.success(),
        "compound exec --tcp failed\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("allowed-ok"),
        "missing allowed probe marker in stdout={stdout:?}"
    );
    assert!(
        stdout.contains("denied-503"),
        "missing denied 503 marker in stdout={stdout:?}"
    );
    assert!(
        stdout.contains("uid=65534 gid=65534"),
        "target did not run under requested identity; stdout={stdout:?}"
    );

    upstream.stop.store(true, Ordering::SeqCst);
    let _ = TcpStream::connect(upstream.addr);
    let _ = upstream.thread.join();
    let _ = run_sudo_with_path(&path, ["compoundd", "cleanup", "--jail-id", &jail_id]);

    Ok(())
}

fn temp_dir() -> io::Result<PathBuf> {
    let dir = env::temp_dir().join(format!("compound-tcp-exec-test-{}", std::process::id()));
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn write_fs_lock(dir: &Path) -> io::Result<PathBuf> {
    let lock = dir.join("fs-lock.compound.yaml");
    fs::write(
        &lock,
        r#"
version: 1
kind: fs-lock
metadata:
  name: tcp-exec-test
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
    )?;
    Ok(lock)
}

fn write_tcp_lock(dir: &Path, port: u16) -> io::Result<PathBuf> {
    let lock = dir.join("tcp-lock.compound.yaml");
    fs::write(
        &lock,
        format!(
            r#"
version: 1
kind: tcp-lock
metadata:
  name: tcp-exec-test
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
    - 10.0.0.0/8
    - 127.0.0.0/8
    - 169.254.0.0/16
    - 172.16.0.0/12
    - 192.168.0.0/16
  allow:
    - cidr: 198.51.100.10/32
      ports: [{port}]
      protocol: tcp
"#
        ),
    )?;
    Ok(lock)
}

struct Cleanup {
    jail_id: String,
    path: String,
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        let _ = run_sudo_with_path(
            &self.path,
            ["compoundd", "cleanup", "--jail-id", &self.jail_id],
        );
        let _ = run_sudo(["ip", "addr", "del", "198.51.100.10/32", "dev", "lo"]);
    }
}

struct EchoServer {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: thread::JoinHandle<()>,
}

fn start_echo_server(addr: SocketAddr) -> io::Result<EchoServer> {
    let listener = TcpListener::bind(addr)?;
    listener.set_nonblocking(true)?;
    let addr = listener.local_addr()?;
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = stop.clone();
    let thread = thread::spawn(move || {
        while !thread_stop.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    thread::spawn(move || {
                        let mut buffer = [0_u8; 64];
                        if let Ok(read) = stream.read(&mut buffer) {
                            let _ = stream.write_all(&buffer[..read]);
                        }
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });

    Ok(EchoServer { addr, stop, thread })
}

fn target_probe_script(allowed_port: u16) -> String {
    format!(
        r#"
import http.client
import os
import socket

s = socket.create_connection(("{UPSTREAM_IP}", {allowed_port}), timeout=3)
s.settimeout(3)
s.sendall(b"allowed")
assert s.recv(64) == b"allowed"
print("allowed-ok")

conn = http.client.HTTPConnection("{DENIED_PUBLIC_IP}", {allowed_port}, timeout=3)
conn.request("GET", "/blocked")
resp = conn.getresponse()
body = resp.read().decode(errors="replace")
assert resp.status == 503, (resp.status, body)
assert "no_matching_allow_rule" not in body
print("denied-503")
print(f"uid={{os.getuid()}} gid={{os.getgid()}}")
"#
    )
}

fn run_sudo<const N: usize>(args: [&str; N]) -> io::Result<Output> {
    run_command(
        "sudo",
        std::iter::once("-n").chain(args).collect::<Vec<_>>(),
    )
}

fn run_sudo_with_path<const N: usize>(path: &str, args: [&str; N]) -> io::Result<Output> {
    let mut command_args = vec!["-n".to_owned(), "env".to_owned(), format!("PATH={path}")];
    command_args.extend(args.into_iter().map(str::to_owned));
    run_command("sudo", command_args)
}

fn require_command<const N: usize>(program: &str, args: [&str; N]) -> io::Result<()> {
    run_command(program, args)?;
    Ok(())
}

fn run_command(
    program: &str,
    args: impl IntoIterator<Item = impl AsRef<std::ffi::OsStr>>,
) -> io::Result<Output> {
    let output = Command::new(program).args(args).output()?;
    if !output.status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "{program} failed with status {:?}\nstdout:\n{}\nstderr:\n{}",
                output.status.code(),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ),
        ));
    }
    Ok(output)
}
