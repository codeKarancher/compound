use compound_policy::{DocumentKind, LockSource, Metadata, ValidationReport};
use compound_tcp::{
    ByteSize, DirectPolicy, Gateway, GatewayAuditEvent, GatewayError, HostnameVerificationPolicy,
    MemoryAuditSink, PortList, StaticResolver, TcpAllowRule, TcpDefault, TcpLimits,
    TcpLockDocument, TcpPolicyBody, TcpProtocol,
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
