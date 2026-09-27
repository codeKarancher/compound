use crate::{
    evaluate_connection, ConnectionDecision, ConnectionRequest, TcpDenyReason, TcpLockDocument,
    TcpProtocol,
};
use std::{
    collections::BTreeMap,
    io::{self, BufRead, BufReader, Read, Write},
    net::{IpAddr, SocketAddr, TcpListener, TcpStream, ToSocketAddrs},
    sync::{Arc, Mutex},
    thread,
};
use thiserror::Error;

#[derive(Clone)]
pub struct Gateway {
    policy: Arc<TcpLockDocument>,
    resolver: Arc<dyn Resolver>,
    connector: Arc<dyn Connector>,
    audit: Arc<dyn AuditSink>,
}

impl Gateway {
    pub fn new(
        policy: TcpLockDocument,
        resolver: Arc<dyn Resolver>,
        connector: Arc<dyn Connector>,
        audit: Arc<dyn AuditSink>,
    ) -> Self {
        Self {
            policy: Arc::new(policy),
            resolver,
            connector,
            audit,
        }
    }

    pub fn serve_once(&self, listener: &TcpListener) -> Result<(), GatewayError> {
        let (client, _) = listener.accept()?;
        self.handle_client(client)
    }

    pub fn handle_client(&self, mut client: TcpStream) -> Result<(), GatewayError> {
        let request = read_connect_request(&client)?;
        let resolved = self.resolver.resolve_host(&request.host)?;
        if resolved.is_empty() {
            self.audit.record(GatewayAuditEvent::Deny {
                host: request.host.clone(),
                port: request.port,
                reason: "dns_no_addresses".to_owned(),
            });
            writeln!(client, "DENY dns_no_addresses")?;
            return Ok(());
        }

        if let Some(denied_ip) = resolved.iter().copied().find(|ip| {
            self.policy
                .tcp
                .deny_cidrs
                .iter()
                .any(|cidr| cidr.contains(*ip))
        }) {
            self.audit.record(GatewayAuditEvent::Deny {
                host: request.host.clone(),
                port: request.port,
                reason: format!("resolved_denied_cidr:{denied_ip}"),
            });
            writeln!(client, "DENY resolved_denied_cidr")?;
            return Ok(());
        }

        let mut allowed = None;
        let mut last_reason = None;
        for ip in resolved {
            let evaluation = evaluate_connection(
                &self.policy,
                &ConnectionRequest {
                    destination_ip: ip,
                    requested_hostname: Some(request.host.clone()),
                    port: request.port,
                    protocol: TcpProtocol::Tls,
                },
            );
            match evaluation.decision {
                ConnectionDecision::Allow => {
                    allowed = Some((ip, evaluation.rule_index.expect("allow has rule index")));
                    break;
                }
                ConnectionDecision::Deny => {
                    last_reason = evaluation.reason;
                }
            }
        }

        let Some((ip, rule_index)) = allowed else {
            let reason = format_deny_reason(last_reason.as_ref());
            self.audit.record(GatewayAuditEvent::Deny {
                host: request.host.clone(),
                port: request.port,
                reason: reason.clone(),
            });
            writeln!(client, "DENY {reason}")?;
            return Ok(());
        };

        let mut upstream = self.connector.connect(&request.host, request.port, ip)?;
        self.audit.record(GatewayAuditEvent::Allow {
            host: request.host.clone(),
            port: request.port,
            ip,
            rule_index,
        });
        writeln!(client, "OK")?;

        let max_upload_bytes = self.policy.tcp.allow[rule_index]
            .limits
            .as_ref()
            .and_then(|limits| limits.max_upload_bytes)
            .map(|bytes| bytes.as_u64());
        proxy(client, &mut upstream, max_upload_bytes).map_err(|error| match error {
            ProxyError::Io(error) => GatewayError::Io(error),
            ProxyError::UploadLimitExceeded { limit } => {
                self.audit.record(GatewayAuditEvent::Deny {
                    host: request.host.clone(),
                    port: request.port,
                    reason: format!("upload_limit_exceeded:{limit}"),
                });
                GatewayError::UploadLimitExceeded { limit }
            }
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatewayAuditEvent {
    Allow {
        host: String,
        port: u16,
        ip: IpAddr,
        rule_index: usize,
    },
    Deny {
        host: String,
        port: u16,
        reason: String,
    },
}

pub trait AuditSink: Send + Sync {
    fn record(&self, event: GatewayAuditEvent);
}

#[derive(Debug, Default)]
pub struct MemoryAuditSink {
    events: Mutex<Vec<GatewayAuditEvent>>,
}

impl MemoryAuditSink {
    pub fn events(&self) -> Vec<GatewayAuditEvent> {
        self.events.lock().expect("audit mutex").clone()
    }
}

impl AuditSink for MemoryAuditSink {
    fn record(&self, event: GatewayAuditEvent) {
        self.events.lock().expect("audit mutex").push(event);
    }
}

pub trait Resolver: Send + Sync {
    fn resolve_host(&self, host: &str) -> Result<Vec<IpAddr>, GatewayError>;
}

#[derive(Debug, Default)]
pub struct SystemResolver;

impl Resolver for SystemResolver {
    fn resolve_host(&self, host: &str) -> Result<Vec<IpAddr>, GatewayError> {
        Ok((host, 0).to_socket_addrs()?.map(|addr| addr.ip()).collect())
    }
}

#[derive(Debug, Default)]
pub struct StaticResolver {
    hosts: BTreeMap<String, Vec<IpAddr>>,
}

impl StaticResolver {
    pub fn new(hosts: impl IntoIterator<Item = (String, Vec<IpAddr>)>) -> Self {
        Self {
            hosts: hosts.into_iter().collect(),
        }
    }
}

impl Resolver for StaticResolver {
    fn resolve_host(&self, host: &str) -> Result<Vec<IpAddr>, GatewayError> {
        Ok(self.hosts.get(host).cloned().unwrap_or_default())
    }
}

pub trait Connector: Send + Sync {
    fn connect(&self, host: &str, port: u16, ip: IpAddr) -> Result<TcpStream, GatewayError>;
}

#[derive(Debug, Default)]
pub struct SystemConnector;

impl Connector for SystemConnector {
    fn connect(&self, _host: &str, port: u16, ip: IpAddr) -> Result<TcpStream, GatewayError> {
        Ok(TcpStream::connect(SocketAddr::new(ip, port))?)
    }
}

#[derive(Debug)]
struct ConnectRequest {
    host: String,
    port: u16,
}

fn read_connect_request(client: &TcpStream) -> Result<ConnectRequest, GatewayError> {
    let mut reader = BufReader::new(client.try_clone()?);
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let line = line.trim();
    let target = line
        .strip_prefix("CONNECT ")
        .ok_or_else(|| GatewayError::InvalidRequest(line.to_owned()))?;
    let (host, port) = target
        .rsplit_once(':')
        .ok_or_else(|| GatewayError::InvalidRequest(line.to_owned()))?;
    let port = port
        .parse::<u16>()
        .map_err(|_| GatewayError::InvalidRequest(line.to_owned()))?;
    if host.is_empty() || port == 0 {
        return Err(GatewayError::InvalidRequest(line.to_owned()));
    }
    Ok(ConnectRequest {
        host: host.to_owned(),
        port,
    })
}

fn proxy(
    client: TcpStream,
    upstream: &mut TcpStream,
    max_upload_bytes: Option<u64>,
) -> Result<(), ProxyError> {
    let mut client_reader = client.try_clone()?;
    let mut client_writer = client;
    let mut upstream_reader = upstream.try_clone()?;
    let mut upstream_writer = upstream.try_clone()?;

    let upload = thread::spawn(move || {
        let mut uploaded = 0_u64;
        let mut buffer = [0_u8; 8192];
        loop {
            let read = client_reader.read(&mut buffer)?;
            if read == 0 {
                let _ = upstream_writer.shutdown(std::net::Shutdown::Write);
                return Ok(());
            }
            let next = uploaded.saturating_add(read as u64);
            if let Some(limit) = max_upload_bytes {
                if next > limit {
                    let remaining = limit.saturating_sub(uploaded) as usize;
                    if remaining > 0 {
                        upstream_writer.write_all(&buffer[..remaining])?;
                    }
                    let _ = upstream_writer.shutdown(std::net::Shutdown::Write);
                    return Err(ProxyError::UploadLimitExceeded { limit });
                }
            }
            upstream_writer.write_all(&buffer[..read])?;
            uploaded = next;
        }
    });

    let download = thread::spawn(move || {
        io::copy(&mut upstream_reader, &mut client_writer)?;
        Ok::<_, io::Error>(())
    });

    let upload_result = upload
        .join()
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "upload thread panicked"))?;
    let download_result = download
        .join()
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "download thread panicked"))?;

    upload_result?;
    download_result?;
    Ok(())
}

fn format_deny_reason(reason: Option<&TcpDenyReason>) -> String {
    match reason {
        Some(TcpDenyReason::DestinationDeniedByCidr(cidr)) => {
            format!("destination_denied_by_cidr:{cidr}")
        }
        Some(TcpDenyReason::NoMatchingAllowRule) => "no_matching_allow_rule".to_owned(),
        Some(TcpDenyReason::HostnameRequired) => "hostname_required".to_owned(),
        Some(TcpDenyReason::HostnameMismatch) => "hostname_mismatch".to_owned(),
        None => "no_matching_allow_rule".to_owned(),
    }
}

#[derive(Debug, Error)]
pub enum GatewayError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("invalid gateway request: {0}")]
    InvalidRequest(String),
    #[error("upload limit exceeded: {limit} bytes")]
    UploadLimitExceeded { limit: u64 },
}

#[derive(Debug, Error)]
enum ProxyError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("upload limit exceeded: {limit} bytes")]
    UploadLimitExceeded { limit: u64 },
}
