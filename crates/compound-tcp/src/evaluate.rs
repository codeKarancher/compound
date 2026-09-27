use crate::schema::{normalize_host, Cidr, TcpLockDocument, TcpProtocol};
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionRequest {
    pub destination_ip: IpAddr,
    pub requested_hostname: Option<String>,
    pub port: u16,
    pub protocol: TcpProtocol,
}

impl ConnectionRequest {
    pub fn tls(requested_hostname: impl Into<String>, destination_ip: IpAddr, port: u16) -> Self {
        Self {
            destination_ip,
            requested_hostname: Some(requested_hostname.into()),
            port,
            protocol: TcpProtocol::Tls,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionEvaluation {
    pub decision: ConnectionDecision,
    pub rule_index: Option<usize>,
    pub reason: Option<TcpDenyReason>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionDecision {
    Allow,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TcpDenyReason {
    DestinationDeniedByCidr(Cidr),
    NoMatchingAllowRule,
    HostnameRequired,
    HostnameMismatch,
}

pub fn evaluate_connection(
    lock: &TcpLockDocument,
    request: &ConnectionRequest,
) -> ConnectionEvaluation {
    if let Some(cidr) = lock
        .tcp
        .deny_cidrs
        .iter()
        .copied()
        .find(|cidr| cidr.contains(request.destination_ip))
    {
        return deny(TcpDenyReason::DestinationDeniedByCidr(cidr));
    }

    for (index, rule) in lock.tcp.allow.iter().enumerate() {
        if rule.protocol != request.protocol || !rule.ports.contains(request.port) {
            continue;
        }

        if let Some(cidr) = rule.cidr {
            if cidr.contains(request.destination_ip) {
                return allow(index);
            }
            continue;
        }

        if let Some(rule_host) = &rule.host {
            let Some(requested_hostname) = &request.requested_hostname else {
                return deny(TcpDenyReason::HostnameRequired);
            };

            if normalize_host(requested_hostname) == normalize_host(rule_host) {
                return allow(index);
            }
        }
    }

    if request.requested_hostname.is_some()
        && lock.tcp.allow.iter().any(|rule| {
            rule.host.is_some()
                && rule.protocol == request.protocol
                && rule.ports.contains(request.port)
        })
    {
        return deny(TcpDenyReason::HostnameMismatch);
    }

    deny(TcpDenyReason::NoMatchingAllowRule)
}

fn allow(rule_index: usize) -> ConnectionEvaluation {
    ConnectionEvaluation {
        decision: ConnectionDecision::Allow,
        rule_index: Some(rule_index),
        reason: None,
    }
}

fn deny(reason: TcpDenyReason) -> ConnectionEvaluation {
    ConnectionEvaluation {
        decision: ConnectionDecision::Deny,
        rule_index: None,
        reason: Some(reason),
    }
}
