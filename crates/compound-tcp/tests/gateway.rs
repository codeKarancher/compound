use compound_policy::{DocumentKind, LockSource, Metadata, ValidationReport};
use compound_tcp::{
    original_destination, ByteSize, DirectPolicy, Gateway, GatewayAuditEvent, GatewayError,
    HostnameVerificationPolicy, MemoryAuditSink, PortList, StaticResolver, TcpAllowRule,
    TcpDefault, TcpLimits, TcpLockDocument, TcpPolicyBody, TcpProtocol,
};
use std::{
    collections::BTreeMap,
    io,
    io::{BufRead, BufReader, Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream},
    path::PathBuf,
    sync::Arc,
    thread,
};

#[derive(Debug)]
struct MappedConnector {
    upstream: SocketAddr,
}

impl compound_tcp::Connector for MappedConnector {
    fn connect(&self, _host: &str, _port: u16, _ip: IpAddr) -> Result<TcpStream, GatewayError> {
        Ok(TcpStream::connect(self.upstream)?)
    }
}

fn policy(max_upload_bytes: Option<u64>) -> TcpLockDocument {
    TcpLockDocument {
        version: 1,
        kind: Some(DocumentKind::TcpLock),
        metadata: Metadata {
            name: "gateway-test".to_owned(),
            description: None,
            labels: BTreeMap::new(),
        },
        source: LockSource {
            root: PathBuf::from("tcp.compound.yaml"),
            includes: Vec::new(),
            generated_by: None,
        },
        digest: None,
        tcp: TcpPolicyBody {
            default: Some(TcpDefault::Deny),
            direct: Some(DirectPolicy::deny_all()),
            encrypted_hostname_unverifiable: Some(HostnameVerificationPolicy::Deny),
            deny_cidrs: vec!["10.0.0.0/8".parse().expect("cidr")],
            allow: vec![TcpAllowRule {
                host: Some("allowed.test".to_owned()),
                cidr: None,
                ports: PortList::new([443]),
                protocol: TcpProtocol::Tls,
                limits: max_upload_bytes.map(|bytes| TcpLimits {
                    max_connections: None,
                    max_upload_bytes: Some(ByteSize(bytes)),
                }),
                source: None,
            }],
        },
        audit: None,
        validation: ValidationReport::default(),
    }
}

fn cidr_policy() -> TcpLockDocument {
    TcpLockDocument {
        version: 1,
        kind: Some(DocumentKind::TcpLock),
        metadata: Metadata {
            name: "transparent-gateway-test".to_owned(),
            description: None,
            labels: BTreeMap::new(),
        },
        source: LockSource {
            root: PathBuf::from("tcp.compound.yaml"),
            includes: Vec::new(),
            generated_by: None,
        },
        digest: None,
        tcp: TcpPolicyBody {
            default: Some(TcpDefault::Deny),
            direct: Some(DirectPolicy::deny_all()),
            encrypted_hostname_unverifiable: Some(HostnameVerificationPolicy::Deny),
            deny_cidrs: vec!["10.0.0.0/8".parse().expect("cidr")],
            allow: vec![TcpAllowRule {
                host: None,
                cidr: Some("203.0.113.0/24".parse().expect("cidr")),
                ports: PortList::new([443]),
                protocol: TcpProtocol::Tcp,
                limits: None,
                source: None,
            }],
        },
        audit: None,
        validation: ValidationReport::default(),
    }
}

fn start_echo_server() -> io::Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("echo accept");
        let mut buffer = [0_u8; 1024];
        loop {
            let read = stream.read(&mut buffer).expect("echo read");
            if read == 0 {
                break;
            }
            stream.write_all(&buffer[..read]).expect("echo write");
        }
    });
    Ok(addr)
}

fn start_gateway(gateway: Gateway) -> io::Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    thread::spawn(move || {
        let _ = gateway.serve_once(&listener);
    });
    Ok(addr)
}

fn start_transparent_gateway(gateway: Gateway, destination: SocketAddr) -> io::Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;
    thread::spawn(move || {
        let (client, _) = listener.accept().expect("transparent accept");
        let _ = gateway.handle_transparent_client_with_destination(client, destination);
    });
    Ok(addr)
}

fn gateway(policy: TcpLockDocument, upstream: SocketAddr, audit: Arc<MemoryAuditSink>) -> Gateway {
    let resolver = StaticResolver::new([(
        "allowed.test".to_owned(),
        vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))],
    )]);
    Gateway::new(
        policy,
        Arc::new(resolver),
        Arc::new(MappedConnector { upstream }),
        audit,
    )
}

fn skip_if_bind_denied(error: &io::Error) -> bool {
    if error.kind() == io::ErrorKind::PermissionDenied {
        eprintln!("skipping local TCP gateway test: localhost bind is not permitted");
        true
    } else {
        false
    }
}

#[test]
fn gateway_allows_and_proxies_approved_connect_request() -> io::Result<()> {
    let upstream = match start_echo_server() {
        Ok(upstream) => upstream,
        Err(error) if skip_if_bind_denied(&error) => return Ok(()),
        Err(error) => return Err(error),
    };
    let audit = Arc::new(MemoryAuditSink::default());
    let gateway_addr = start_gateway(gateway(policy(None), upstream, audit.clone()))?;

    let mut client = TcpStream::connect(gateway_addr).expect("connect gateway");
    client
        .write_all(b"CONNECT allowed.test:443\n")
        .expect("write connect");
    let mut reader = BufReader::new(client.try_clone().expect("clone client"));
    let mut response = String::new();
    reader.read_line(&mut response).expect("read response");
    assert_eq!(response, "OK\n");

    client.write_all(b"hello").expect("write payload");
    let mut echoed = [0_u8; 5];
    reader.read_exact(&mut echoed).expect("read echo");
    assert_eq!(&echoed, b"hello");

    assert!(audit
        .events()
        .iter()
        .any(|event| matches!(event, GatewayAuditEvent::Allow { host, port: 443, .. } if host == "allowed.test")));
    Ok(())
}

#[test]
fn gateway_denies_unknown_host_without_connecting_upstream() -> io::Result<()> {
    let upstream = match start_echo_server() {
        Ok(upstream) => upstream,
        Err(error) if skip_if_bind_denied(&error) => return Ok(()),
        Err(error) => return Err(error),
    };
    let audit = Arc::new(MemoryAuditSink::default());
    let gateway_addr = start_gateway(gateway(policy(None), upstream, audit.clone()))?;

    let mut client = TcpStream::connect(gateway_addr).expect("connect gateway");
    client
        .write_all(b"CONNECT blocked.test:443\n")
        .expect("write connect");
    let mut response = String::new();
    BufReader::new(client)
        .read_line(&mut response)
        .expect("read response");

    assert!(response.starts_with("DENY"));
    assert!(audit.events().iter().any(
        |event| matches!(event, GatewayAuditEvent::Deny { host, .. } if host == "blocked.test")
    ));
    Ok(())
}

#[test]
fn gateway_enforces_upload_limit() -> io::Result<()> {
    let upstream = match start_echo_server() {
        Ok(upstream) => upstream,
        Err(error) if skip_if_bind_denied(&error) => return Ok(()),
        Err(error) => return Err(error),
    };
    let audit = Arc::new(MemoryAuditSink::default());
    let gateway_addr = start_gateway(gateway(policy(Some(3)), upstream, audit.clone()))?;

    let mut client = TcpStream::connect(gateway_addr).expect("connect gateway");
    client
        .write_all(b"CONNECT allowed.test:443\n")
        .expect("write connect");
    let mut reader = BufReader::new(client.try_clone().expect("clone client"));
    let mut response = String::new();
    reader.read_line(&mut response).expect("read response");
    assert_eq!(response, "OK\n");

    client.write_all(b"hello").expect("write payload");
    let mut echoed = [0_u8; 3];
    reader.read_exact(&mut echoed).expect("read limited echo");
    assert_eq!(&echoed, b"hel");

    drop(client);
    thread::sleep(std::time::Duration::from_millis(50));
    assert!(audit.events().iter().any(|event| {
        matches!(event, GatewayAuditEvent::Deny { reason, .. } if reason.starts_with("upload_limit_exceeded"))
    }));
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn original_destination_reports_local_destination_on_linux() -> io::Result<()> {
    let listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(error) if skip_if_bind_denied(&error) => return Ok(()),
        Err(error) => return Err(error),
    };
    let expected = listener.local_addr()?;

    let client = TcpStream::connect(expected)?;
    let (accepted, _) = listener.accept()?;

    let original = original_destination(&accepted).expect("recover original destination");
    assert_eq!(original, expected);
    drop(client);
    Ok(())
}

#[cfg(not(target_os = "linux"))]
#[test]
fn original_destination_fails_closed_on_unsupported_platforms() -> io::Result<()> {
    let listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(listener) => listener,
        Err(error) if skip_if_bind_denied(&error) => return Ok(()),
        Err(error) => return Err(error),
    };
    let client = TcpStream::connect(listener.local_addr()?)?;
    let (accepted, _) = listener.accept()?;

    let error = original_destination(&accepted).expect_err("unsupported platform");
    assert!(matches!(
        error,
        GatewayError::TransparentOriginalDestinationUnsupported
    ));
    drop(client);
    Ok(())
}

#[test]
fn transparent_gateway_proxies_cidr_allowed_destination_without_connect_header() -> io::Result<()> {
    let upstream = match start_echo_server() {
        Ok(upstream) => upstream,
        Err(error) if skip_if_bind_denied(&error) => return Ok(()),
        Err(error) => return Err(error),
    };
    let audit = Arc::new(MemoryAuditSink::default());
    let destination = SocketAddr::new("203.0.113.42".parse().expect("ip"), 443);
    let gateway_addr =
        start_transparent_gateway(gateway(cidr_policy(), upstream, audit.clone()), destination)?;

    let mut client = TcpStream::connect(gateway_addr).expect("connect gateway");
    let mut reader = BufReader::new(client.try_clone().expect("clone client"));
    client.write_all(b"hello").expect("write payload");
    let mut echoed = [0_u8; 5];
    reader.read_exact(&mut echoed).expect("read echo");

    assert_eq!(&echoed, b"hello");
    assert!(audit.events().iter().any(|event| {
        matches!(event, GatewayAuditEvent::Allow { host, port: 443, ip, .. } if host == "203.0.113.42:443" && *ip == destination.ip())
    }));
    Ok(())
}

#[test]
fn transparent_gateway_denies_hostname_policy_without_claiming_identity() -> io::Result<()> {
    let upstream = match start_echo_server() {
        Ok(upstream) => upstream,
        Err(error) if skip_if_bind_denied(&error) => return Ok(()),
        Err(error) => return Err(error),
    };
    let audit = Arc::new(MemoryAuditSink::default());
    let destination = SocketAddr::new("203.0.113.42".parse().expect("ip"), 443);
    let gateway_addr =
        start_transparent_gateway(gateway(policy(None), upstream, audit.clone()), destination)?;

    let mut client = TcpStream::connect(gateway_addr).expect("connect gateway");
    client.write_all(b"hello").expect("write payload");
    let mut response = [0_u8; 1];
    match client.read(&mut response) {
        Ok(0) => {}
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe
            ) => {}
        result => panic!("expected transparent close, got {result:?}"),
    }

    assert!(audit.events().iter().any(|event| {
        matches!(event, GatewayAuditEvent::Deny { host, port: 443, reason } if host == "203.0.113.42:443" && reason == "no_matching_allow_rule")
    }));
    Ok(())
}

#[test]
fn transparent_gateway_returns_generic_503_for_denied_http() -> io::Result<()> {
    let upstream = match start_echo_server() {
        Ok(upstream) => upstream,
        Err(error) if skip_if_bind_denied(&error) => return Ok(()),
        Err(error) => return Err(error),
    };
    let audit = Arc::new(MemoryAuditSink::default());
    let destination = SocketAddr::new("203.0.113.42".parse().expect("ip"), 80);
    let gateway_addr =
        start_transparent_gateway(gateway(policy(None), upstream, audit.clone()), destination)?;

    let mut client = TcpStream::connect(gateway_addr).expect("connect gateway");
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")
        .expect("write http request");
    let mut response = String::new();
    client
        .read_to_string(&mut response)
        .expect("read http denial");

    assert!(response.starts_with("HTTP/1.1 503 Service Unavailable\r\n"));
    assert!(response.contains("\r\n\r\nService unavailable"));
    assert!(!response.contains("deny"));
    assert!(!response.contains("policy"));
    assert!(!response.contains("no_matching_allow_rule"));
    assert!(audit.events().iter().any(|event| {
        matches!(event, GatewayAuditEvent::Deny { host, port: 80, reason } if host == "203.0.113.42:80" && reason == "no_matching_allow_rule")
    }));
    Ok(())
}

#[test]
fn transparent_gateway_does_not_send_policy_detail_for_denied_non_http() -> io::Result<()> {
    let upstream = match start_echo_server() {
        Ok(upstream) => upstream,
        Err(error) if skip_if_bind_denied(&error) => return Ok(()),
        Err(error) => return Err(error),
    };
    let audit = Arc::new(MemoryAuditSink::default());
    let destination = SocketAddr::new("203.0.113.42".parse().expect("ip"), 443);
    let gateway_addr =
        start_transparent_gateway(gateway(policy(None), upstream, audit.clone()), destination)?;

    let mut client = TcpStream::connect(gateway_addr).expect("connect gateway");
    client
        .write_all(b"\x16\x03\x01\x00\x2e")
        .expect("write tls-like bytes");
    let mut response = Vec::new();
    match client.read_to_end(&mut response) {
        Ok(_) => {}
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::ConnectionReset | io::ErrorKind::BrokenPipe
            ) => {}
        Err(error) => return Err(error),
    }

    let response = String::from_utf8_lossy(&response);
    assert!(!response.contains("deny"));
    assert!(!response.contains("policy"));
    assert!(!response.contains("no_matching_allow_rule"));
    assert!(audit.events().iter().any(|event| {
        matches!(event, GatewayAuditEvent::Deny { host, port: 443, reason } if host == "203.0.113.42:443" && reason == "no_matching_allow_rule")
    }));
    Ok(())
}
