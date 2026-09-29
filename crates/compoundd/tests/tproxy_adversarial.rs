#![cfg(target_os = "linux")]

use compound_tcp::{
    bind_transparent_listener, Gateway, GatewayAuditEvent, GatewayError, MemoryAuditSink,
    StaticResolver, SystemConnector, TcpLockDocument,
};
use compoundd::{build_network_plan, NetworkCommand, NetworkPlan, NetworkPlanOptions};
use std::{
    io::{self, Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    process::{Command, Output},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

const UPSTREAM_IP: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 10);
const DENIED_PUBLIC_IP: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 77);
const METADATA_IP: Ipv4Addr = Ipv4Addr::new(169, 254, 169, 254);

#[test]
fn tproxy_namespace_enforces_tcp_lock_against_adversarial_egress() -> io::Result<()> {
    if std::env::var_os("COMPOUND_RUN_PRIVILEGED_NET_TESTS").is_none() {
        eprintln!(
            "skipping privileged TPROXY integration test; set COMPOUND_RUN_PRIVILEGED_NET_TESTS=1"
        );
        return Ok(());
    }
    require_command("sudo", ["-n", "true"])?;
    require_command("python3", ["--version"])?;
    require_command("ip", ["-Version"])?;
    require_command("nft", ["--version"])?;

    let case = TestCase::new();
    let _cleanup = Cleanup::new(case.options.clone());

    run_sudo(["ip", "addr", "add", "198.51.100.10/32", "dev", "lo"])?;
    let upstream = start_echo_server(SocketAddr::new(IpAddr::V4(UPSTREAM_IP), 0))?;
    let upstream_addr = upstream.addr;
    let lock = tcp_lock(upstream_addr.port());
    let plan = build_network_plan(&lock, &case.options).expect("network plan");
    apply_plan(&plan)?;

    let audit = Arc::new(MemoryAuditSink::default());
    let gateway_stop = Arc::new(AtomicBool::new(false));
    let gateway = Gateway::new(
        lock,
        Arc::new(StaticResolver::default()),
        Arc::new(SystemConnector),
        audit.clone(),
    );
    let gateway_listener = bind_transparent_listener(SocketAddr::V4(plan.gateway_addr))
        .expect("bind transparent gateway listener");
    let gateway_thread = serve_gateway(gateway_listener, gateway, gateway_stop.clone());

    assert_eq!(
        run_netns_python(
            &plan.namespace,
            &tcp_echo_script(&UPSTREAM_IP.to_string(), upstream_addr.port(), "allowed")
        )
        .expect("allowed tcp client"),
        "allowed"
    );

    assert_egress_denied(&plan.namespace, DENIED_PUBLIC_IP, upstream_addr.port())?;
    assert_egress_denied(&plan.namespace, METADATA_IP, 80)?;
    assert_udp_denied(&plan.namespace, METADATA_IP, 53)?;

    wait_for_audit(
        &audit,
        |event| matches!(event, GatewayAuditEvent::Allow { host, port, .. } if host == &format!("{}:{}", UPSTREAM_IP, upstream_addr.port()) && *port == upstream_addr.port()),
    );
    wait_for_audit(
        &audit,
        |event| matches!(event, GatewayAuditEvent::Deny { host, reason, .. } if host.starts_with(&DENIED_PUBLIC_IP.to_string()) && reason == "no_matching_allow_rule"),
    );

    gateway_stop.store(true, Ordering::SeqCst);
    let _ = TcpStream::connect(SocketAddr::V4(plan.gateway_addr));
    let _ = gateway_thread.join();
    upstream.stop.store(true, Ordering::SeqCst);
    let _ = TcpStream::connect(upstream_addr);
    let _ = upstream.thread.join();

    Ok(())
}

struct TestCase {
    options: NetworkPlanOptions,
}

impl TestCase {
    fn new() -> Self {
        let pid = std::process::id();
        let mut options = NetworkPlanOptions::new(format!("adv{pid}"));
        options.gateway_port = 15_000 + (pid % 1_000) as u16;
        options.host_addr = Ipv4Addr::new(10, 250, (pid % 200) as u8, 1);
        options.jail_addr = Ipv4Addr::new(10, 250, (pid % 200) as u8, 2);
        options.fwmark = 10_000 + (pid % 10_000);
        options.routing_table = 10_000 + (pid % 10_000);
        Self { options }
    }
}

struct Cleanup {
    options: NetworkPlanOptions,
}

impl Cleanup {
    fn new(options: NetworkPlanOptions) -> Self {
        let cleanup = Self { options };
        cleanup.run();
        cleanup
    }

    fn run(&self) {
        if let Ok(plan) = compoundd::build_cleanup_plan(&self.options) {
            for command in plan.cleanup_commands {
                let _ = run_sudo_command(&command);
            }
        }
        let _ = run_sudo(["ip", "addr", "del", "198.51.100.10/32", "dev", "lo"]);
    }
}

impl Drop for Cleanup {
    fn drop(&mut self) {
        self.run();
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
                Ok((stream, _)) => {
                    thread::spawn(move || echo(stream));
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

fn echo(mut stream: TcpStream) {
    let mut buffer = [0_u8; 1024];
    loop {
        match stream.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(read) => {
                if stream.write_all(&buffer[..read]).is_err() {
                    break;
                }
            }
        }
    }
}

fn serve_gateway(
    listener: TcpListener,
    gateway: Gateway,
    stop: Arc<AtomicBool>,
) -> thread::JoinHandle<()> {
    listener
        .set_nonblocking(true)
        .expect("set gateway nonblocking");
    thread::spawn(move || {
        while !stop.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((client, _)) => {
                    let gateway = gateway.clone();
                    thread::spawn(move || {
                        let _ = gateway.handle_transparent_client(client);
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    })
}

fn tcp_lock(port: u16) -> TcpLockDocument {
    serde_yaml::from_str(&format!(
        r#"
version: 1
kind: tcp-lock
metadata:
  name: adversarial-tproxy
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
    ))
    .expect("tcp lock fixture")
}

fn apply_plan(plan: &NetworkPlan) -> io::Result<()> {
    for command in &plan.commands {
        if command.program == "compoundd-gateway" {
            continue;
        }
        run_sudo_command(command)?;
    }
    Ok(())
}

fn run_sudo_command(command: &NetworkCommand) -> io::Result<Output> {
    let mut args = Vec::with_capacity(command.args.len() + 2);
    args.push("-n".to_owned());
    args.push(command.program.clone());
    args.extend(command.args.clone());
    run_command("sudo", args)
}

fn run_sudo<const N: usize>(args: [&str; N]) -> io::Result<Output> {
    run_command(
        "sudo",
        std::iter::once("-n").chain(args).collect::<Vec<_>>(),
    )
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

fn run_netns_python(namespace: &str, script: &str) -> io::Result<String> {
    let output = run_sudo(["ip", "netns", "exec", namespace, "python3", "-c", script])?;
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

fn assert_egress_denied(namespace: &str, ip: Ipv4Addr, port: u16) -> io::Result<()> {
    let output = Command::new("sudo")
        .args([
            "-n",
            "ip",
            "netns",
            "exec",
            namespace,
            "python3",
            "-c",
            &denied_tcp_script(&ip.to_string(), port),
        ])
        .output()?;
    if output.status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("expected TCP egress to {ip}:{port} to fail closed"),
        ));
    }
    Ok(())
}

fn assert_udp_denied(namespace: &str, ip: Ipv4Addr, port: u16) -> io::Result<()> {
    let result = run_netns_python(namespace, &udp_probe_script(&ip.to_string(), port))?;
    if result != "udp-denied" {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("expected UDP egress to {ip}:{port} to be denied, got {result:?}"),
        ));
    }
    Ok(())
}

fn tcp_echo_script(ip: &str, port: u16, payload: &str) -> String {
    format!(
        r#"
import socket
s = socket.create_connection(("{ip}", {port}), timeout=3)
s.settimeout(3)
s.sendall({payload:?}.encode())
data = s.recv(64)
print(data.decode(), end="")
"#
    )
}

fn denied_tcp_script(ip: &str, port: u16) -> String {
    format!(
        r#"
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(2)
try:
    s.connect(("{ip}", {port}))
    s.sendall(b"blocked")
    data = s.recv(1)
    raise SystemExit(1 if data else 2)
except OSError:
    raise SystemExit(3)
"#
    )
}

fn udp_probe_script(ip: &str, port: u16) -> String {
    format!(
        r#"
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(1)
try:
    s.sendto(b"x", ("{ip}", {port}))
    s.recvfrom(1)
    print("udp-open", end="")
except OSError:
    print("udp-denied", end="")
"#
    )
}

fn wait_for_audit(audit: &MemoryAuditSink, predicate: impl Fn(&GatewayAuditEvent) -> bool) {
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if audit.events().iter().any(&predicate) {
            return;
        }
        thread::sleep(Duration::from_millis(25));
    }
    panic!("missing expected audit event; saw {:?}", audit.events());
}
