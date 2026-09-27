use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DocumentKind {
    FsPolicy,
    FsLock,
    TcpPolicy,
    TcpLock,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionedDocument {
    pub version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<DocumentKind>,
}
