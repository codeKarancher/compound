use crate::Include;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct LockSource {
    pub root: PathBuf,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub includes: Vec<Include>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generated_by: Option<GeneratedBy>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneratedBy {
    pub name: String,
    pub version: String,
}
