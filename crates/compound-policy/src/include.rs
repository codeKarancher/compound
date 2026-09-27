use crate::Digest;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Include {
    pub path: PathBuf,
    pub digest: Digest,
}
