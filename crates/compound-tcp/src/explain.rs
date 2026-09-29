use crate::schema::{DirectAction, DirectPolicy};
use crate::TcpLockDocument;
use compound_policy::{Digest, LockSource, ValidationFinding};
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpExplanation {
    pub digest: Option<Digest>,
    pub source: LockSource,
    pub default: String,
    pub direct: TcpDirectExplanation,
    pub encrypted_hostname_unverifiable: String,
    pub deny_cidr_count: usize,
    pub allow_count: usize,
    pub validation_findings: Vec<ValidationFinding>,
    pub allow: Vec<TcpAllowExplanation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpAllowExplanation {
    pub index: usize,
    pub host: String,
    pub ports: Vec<u16>,
    pub protocol: String,
    pub source: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpDirectExplanation {
    pub tcp: String,
    pub udp: String,
    pub dns: String,
    pub raw_sockets: String,
}

pub fn explain_lock(lock: &TcpLockDocument) -> TcpExplanation {
    TcpExplanation {
        digest: lock.digest.clone(),
        source: lock.source.clone(),
        default: lock
            .tcp
            .default
            .map(|default| format!("{default:?}").to_ascii_lowercase())
            .unwrap_or_else(|| "unspecified".to_owned()),
        direct: explain_direct(lock.tcp.direct),
        encrypted_hostname_unverifiable: lock
            .tcp
            .encrypted_hostname_unverifiable
            .map(|policy| format!("{policy:?}").to_ascii_lowercase())
            .unwrap_or_else(|| "unspecified".to_owned()),
        deny_cidr_count: lock.tcp.deny_cidrs.len(),
        allow_count: lock.tcp.allow.len(),
        validation_findings: lock.validation.findings.clone(),
        allow: lock
            .tcp
            .allow
            .iter()
            .cloned()
            .enumerate()
            .map(|(index, rule)| TcpAllowExplanation {
                index,
                host: rule
                    .host
                    .unwrap_or_else(|| rule.cidr.map(|cidr| cidr.to_string()).unwrap_or_default()),
                ports: rule.ports.0,
                protocol: format!("{:?}", rule.protocol).to_ascii_lowercase(),
                source: rule.source,
            })
            .collect(),
    }
}

fn explain_direct(direct: Option<DirectPolicy>) -> TcpDirectExplanation {
    let direct = direct.unwrap_or_else(DirectPolicy::deny_all);
    TcpDirectExplanation {
        tcp: explain_action(direct.tcp),
        udp: explain_action(direct.udp),
        dns: explain_action(direct.dns),
        raw_sockets: explain_action(direct.raw_sockets),
    }
}

fn explain_action(action: DirectAction) -> String {
    format!("{action:?}").to_ascii_lowercase()
}
