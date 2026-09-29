#![cfg(target_os = "linux")]

use compound_tcp::{
    bind_transparent_listener, Gateway, GatewayAuditEvent, MemoryAuditSink, StaticResolver,
    SystemConnector, TcpLockDocument,
};
use compoundd::{build_network_plan, NetworkCommand, NetworkPlan, NetworkPlanOptions};
use std::{
    fs,
    io::{self, Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket},
    path::PathBuf,
    process::{Command, Output},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
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
    require_command("runuser", ["--version"])?;
    require_command("ip", ["-Version"])?;
    require_command("nft", ["--version"])?;

    let case = TestCase::new();
    let _cleanup = Cleanup::new(case.options.clone());

    run_sudo(["ip", "addr", "add", "198.51.100.10/32", "dev", "lo"])?;
    let upstream = start_echo_server(SocketAddr::new(IpAddr::V4(UPSTREAM_IP), 0))?;
    let upstream_addr = upstream.addr;
    let trap = start_counting_tcp_server(SocketAddr::new(IpAddr::V4(UPSTREAM_IP), 0))?;
    let trap_addr = trap.addr;
    let udp_trap = UdpTrap::bind(SocketAddr::new(IpAddr::V4(UPSTREAM_IP), 0))?;
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
    assert_http_denied_as_service_unavailable(
        &plan.namespace,
        DENIED_PUBLIC_IP,
        upstream_addr.port(),
    )?;
    assert_common_tool_denials(&plan.namespace, DENIED_PUBLIC_IP, upstream_addr.port())?;
    assert_egress_denied(&plan.namespace, UPSTREAM_IP, trap_addr.port())?;
    assert_eq!(
        trap.connection_count(),
        0,
        "denied TCP connection reached trap listener"
    );

    for denied_private in [
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::LOCALHOST,
        Ipv4Addr::new(172, 16, 0, 1),
        Ipv4Addr::new(192, 168, 0, 1),
    ] {
        assert_egress_denied(&plan.namespace, denied_private, 80)?;
    }
    assert_egress_denied(&plan.namespace, METADATA_IP, 80)?;
    assert_udp_denied(&plan.namespace, METADATA_IP, 53)?;
    assert_udp_denied(&plan.namespace, UPSTREAM_IP, 443)?;
    assert_udp_denied(&plan.namespace, UPSTREAM_IP, udp_trap.addr.port())?;
    udp_trap.assert_no_datagram()?;
    assert_egress_denied(&plan.namespace, UPSTREAM_IP, 53)?;
    assert_egress_denied(
        &plan.namespace,
        case.options.host_addr,
        case.options.gateway_port,
    )?;
    assert_unprivileged_raw_socket_denied(&plan.namespace)?;
    assert_unprivileged_network_admin_denied(&plan.namespace)?;

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
    trap.stop.store(true, Ordering::SeqCst);
    let _ = TcpStream::connect(trap_addr);
    let _ = trap.thread.join();

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

struct CountingTcpServer {
    addr: SocketAddr,
    connections: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    thread: thread::JoinHandle<()>,
}

impl CountingTcpServer {
    fn connection_count(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }
}

fn start_counting_tcp_server(addr: SocketAddr) -> io::Result<CountingTcpServer> {
    let listener = TcpListener::bind(addr)?;
    listener.set_nonblocking(true)?;
    let addr = listener.local_addr()?;
    let connections = Arc::new(AtomicUsize::new(0));
    let thread_connections = connections.clone();
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = stop.clone();
    let thread = thread::spawn(move || {
        while !thread_stop.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((_stream, _)) => {
                    thread_connections.fetch_add(1, Ordering::SeqCst);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });

    Ok(CountingTcpServer {
        addr,
        connections,
        stop,
        thread,
    })
}

struct UdpTrap {
    addr: SocketAddr,
    socket: UdpSocket,
}

impl UdpTrap {
    fn bind(addr: SocketAddr) -> io::Result<Self> {
        let socket = UdpSocket::bind(addr)?;
        socket.set_read_timeout(Some(Duration::from_millis(250)))?;
        let addr = socket.local_addr()?;
        Ok(Self { addr, socket })
    }

    fn assert_no_datagram(&self) -> io::Result<()> {
        let mut buffer = [0_u8; 16];
        match self.socket.recv_from(&mut buffer) {
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                Ok(())
            }
            Ok((read, peer)) => Err(io::Error::new(
                io::ErrorKind::Other,
                format!("denied UDP datagram reached trap from {peer}: {read} bytes"),
            )),
            Err(error) => Err(error),
        }
    }
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
        let is_gateway_placeholder = command.program == "compoundd-gateway"
            || (command.program == "compoundd"
                && command.args.first().map(String::as_str) == Some("gateway"));
        if is_gateway_placeholder {
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

fn assert_http_denied_as_service_unavailable(
    namespace: &str,
    ip: Ipv4Addr,
    port: u16,
) -> io::Result<()> {
    let body = run_netns_python(
        namespace,
        &python_http_response_script(&ip.to_string(), port),
    )?;
    if !body.starts_with("503\nService unavailable") {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("expected generic HTTP 503 denial, got {body:?}"),
        ));
    }
    if body.contains("destination_denied")
        || body.contains("no_matching_allow_rule")
        || body.contains("hostname_required")
    {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("HTTP denial leaked policy reason: {body:?}"),
        ));
    }
    Ok(())
}

fn assert_common_tool_denials(namespace: &str, ip: Ipv4Addr, port: u16) -> io::Result<()> {
    assert_python_http_denied(namespace, ip, port)?;

    if command_exists("curl") {
        assert_curl_http_denied(namespace, ip, port)?;
        assert_curl_https_denied(namespace, ip, port)?;
    } else {
        eprintln!("skipping curl adversarial probe; curl is not installed");
    }

    if command_exists("node") {
        assert_node_http_denied(namespace, ip, port)?;
    } else {
        eprintln!("skipping Node adversarial probe; node is not installed");
    }

    if command_exists("go") {
        assert_go_http_denied(namespace, ip, port)?;
    } else {
        eprintln!("skipping Go adversarial probe; go is not installed");
    }

    if command_exists("rustc") {
        assert_rust_http_denied(namespace, ip, port)?;
    } else {
        eprintln!("skipping Rust adversarial probe; rustc is not installed");
    }

    if let Some(netcat) = ["nc", "netcat"]
        .into_iter()
        .find(|program| command_exists(program))
    {
        assert_netcat_http_denied(namespace, netcat, ip, port)?;
    } else {
        eprintln!("skipping netcat adversarial probe; nc/netcat is not installed");
    }

    Ok(())
}

fn assert_python_http_denied(namespace: &str, ip: Ipv4Addr, port: u16) -> io::Result<()> {
    let result = run_netns_python(namespace, &python_http_probe_script(&ip.to_string(), port))?;
    if result != "503" {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("expected Python HTTP probe to see 503, got {result:?}"),
        ));
    }
    Ok(())
}

fn assert_curl_http_denied(namespace: &str, ip: Ipv4Addr, port: u16) -> io::Result<()> {
    let output = run_sudo([
        "ip",
        "netns",
        "exec",
        namespace,
        "curl",
        "--silent",
        "--show-error",
        "--connect-timeout",
        "2",
        "--max-time",
        "3",
        "--output",
        "-",
        "--write-out",
        "\n%{http_code}",
        &format!("http://{ip}:{port}/blocked"),
    ])?;
    let body = String::from_utf8_lossy(&output.stdout);
    if !body.contains("Service unavailable") || !body.trim_end().ends_with("503") {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("expected curl HTTP probe to see 503, got {body:?}"),
        ));
    }
    Ok(())
}

fn assert_curl_https_denied(namespace: &str, ip: Ipv4Addr, port: u16) -> io::Result<()> {
    let output = Command::new("sudo")
        .args([
            "-n",
            "ip",
            "netns",
            "exec",
            namespace,
            "curl",
            "--insecure",
            "--silent",
            "--show-error",
            "--connect-timeout",
            "2",
            "--max-time",
            "3",
            &format!("https://{ip}:{port}/blocked"),
        ])
        .output()?;
    if output.status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "expected curl HTTPS probe to fail closed",
        ));
    }
    Ok(())
}

fn assert_node_http_denied(namespace: &str, ip: Ipv4Addr, port: u16) -> io::Result<()> {
    let script = format!(
        r#"
const http = require("http");
const req = http.get({{ host: "{ip}", port: {port}, path: "/blocked", timeout: 3000 }}, (res) => {{
  console.log(res.statusCode);
  res.resume();
  process.exit(res.statusCode === 503 ? 0 : 1);
}});
req.on("timeout", () => {{ req.destroy(); process.exit(2); }});
req.on("error", () => process.exit(3));
"#
    );
    run_sudo(["ip", "netns", "exec", namespace, "node", "-e", &script])?;
    Ok(())
}

fn assert_go_http_denied(namespace: &str, ip: Ipv4Addr, port: u16) -> io::Result<()> {
    let source = temp_source_path("compound-go-http-probe", "go");
    fs::write(
        &source,
        format!(
            r#"
package main
import (
  "fmt"
  "net/http"
  "os"
  "time"
)
func main() {{
  client := http.Client{{Timeout: 3 * time.Second}}
  resp, err := client.Get("http://{ip}:{port}/blocked")
  if err != nil {{
    os.Exit(2)
  }}
  defer resp.Body.Close()
  fmt.Println(resp.StatusCode)
  if resp.StatusCode != http.StatusServiceUnavailable {{
    os.Exit(1)
  }}
}}
"#
        ),
    )?;
    run_sudo([
        "ip",
        "netns",
        "exec",
        namespace,
        "go",
        "run",
        source.to_str().unwrap(),
    ])?;
    let _ = fs::remove_file(source);
    Ok(())
}

fn assert_rust_http_denied(namespace: &str, ip: Ipv4Addr, port: u16) -> io::Result<()> {
    let source = temp_source_path("compound-rust-http-probe", "rs");
    let binary = temp_source_path("compound-rust-http-probe", "bin");
    fs::write(
        &source,
        format!(
            r#"
use std::io::{{Read, Write}};
use std::net::TcpStream;
use std::time::Duration;

fn main() {{
    let mut stream = TcpStream::connect(("{ip}", {port})).expect("connect");
    stream.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    stream.write_all(b"GET /blocked HTTP/1.1\r\nHost: denied\r\nConnection: close\r\n\r\n").unwrap();
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    if !response.starts_with("HTTP/1.1 503 Service Unavailable") {{
        eprintln!("{{response:?}}");
        std::process::exit(1);
    }}
}}
"#
        ),
    )?;
    run_command(
        "rustc",
        [source.to_str().unwrap(), "-o", binary.to_str().unwrap()],
    )?;
    run_sudo(["ip", "netns", "exec", namespace, binary.to_str().unwrap()])?;
    let _ = fs::remove_file(source);
    let _ = fs::remove_file(binary);
    Ok(())
}

fn assert_netcat_http_denied(
    namespace: &str,
    netcat: &str,
    ip: Ipv4Addr,
    port: u16,
) -> io::Result<()> {
    let script = format!(
        "printf 'GET /blocked HTTP/1.1\\r\\nHost: denied\\r\\nConnection: close\\r\\n\\r\\n' | {netcat} -w 3 {ip} {port}"
    );
    let output = run_sudo(["ip", "netns", "exec", namespace, "sh", "-c", &script])?;
    let response = String::from_utf8_lossy(&output.stdout);
    if !response.starts_with("HTTP/1.1 503 Service Unavailable") {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("expected netcat HTTP probe to see 503, got {response:?}"),
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

fn assert_unprivileged_raw_socket_denied(namespace: &str) -> io::Result<()> {
    let output = Command::new("sudo")
        .args([
            "-n",
            "ip",
            "netns",
            "exec",
            namespace,
            "runuser",
            "-u",
            "nobody",
            "--",
            "python3",
            "-c",
            r#"
import socket
try:
    socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    raise SystemExit(1)
except OSError:
    raise SystemExit(0)
"#,
        ])
        .output()?;
    if !output.status.success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "expected unprivileged raw socket creation to fail\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ),
        ));
    }
    Ok(())
}

fn assert_unprivileged_network_admin_denied(namespace: &str) -> io::Result<()> {
    for args in [
        ["ip", "route", "add", "203.0.113.0/24", "dev", "lo"].as_slice(),
        ["nft", "list", "ruleset"].as_slice(),
    ] {
        let mut command_args = vec![
            "-n", "ip", "netns", "exec", namespace, "runuser", "-u", "nobody", "--",
        ];
        command_args.extend(args);
        let output = Command::new("sudo").args(command_args).output()?;
        if output.status.success() {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("unprivileged command unexpectedly succeeded: {args:?}"),
            ));
        }
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

fn python_http_probe_script(ip: &str, port: u16) -> String {
    format!(
        r#"
import http.client
conn = http.client.HTTPConnection("{ip}", {port}, timeout=3)
conn.request("GET", "/blocked")
resp = conn.getresponse()
print(resp.status, end="")
"#
    )
}

fn python_http_response_script(ip: &str, port: u16) -> String {
    format!(
        r#"
import http.client
conn = http.client.HTTPConnection("{ip}", {port}, timeout=3)
conn.request("GET", "/blocked")
resp = conn.getresponse()
body = resp.read().decode(errors="replace")
print(str(resp.status) + "\n" + body, end="")
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

fn command_exists(program: &str) -> bool {
    Command::new(program)
        .arg("--version")
        .output()
        .map(|output| output.status.success() || !output.stderr.is_empty())
        .unwrap_or(false)
}

fn temp_source_path(stem: &str, extension: &str) -> PathBuf {
    std::env::temp_dir().join(format!("{stem}-{}.{}", std::process::id(), extension))
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
