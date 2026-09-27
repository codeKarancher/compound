use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AuditConfig {
    #[serde(default)]
    pub required: bool,
    #[serde(default)]
    pub event_sink: Option<AuditSink>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub include: Vec<AuditEventKind>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditSink {
    Stderr,
    Stdout,
    File,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventKind {
    PolicyDigest,
    ProcessStart,
    LandlockSetup,
    FilesystemAllow,
    FilesystemDeny,
    NetworkAllow,
    NetworkDeny,
    DnsResolution,
}
