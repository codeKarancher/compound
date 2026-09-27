use crate::schema::{FsAccess, FsLockDocument};
use std::{collections::BTreeSet, path::PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsExplanation {
    pub default: String,
    pub inherited_file_descriptors: String,
    pub path_count: usize,
    pub paths: Vec<FsPathExplanation>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsPathExplanation {
    pub path: PathBuf,
    pub access: BTreeSet<FsAccess>,
    pub source: Option<PathBuf>,
}

pub fn explain_lock(lock: &FsLockDocument) -> FsExplanation {
    FsExplanation {
        default: format!("{:?}", lock.policy.default).to_ascii_lowercase(),
        inherited_file_descriptors: lock
            .policy
            .inherited_file_descriptors
            .map(|value| format!("{value:?}").to_ascii_lowercase())
            .unwrap_or_else(|| "unspecified".to_owned()),
        path_count: lock.policy.paths.len(),
        paths: lock
            .policy
            .paths
            .iter()
            .map(|rule| FsPathExplanation {
                path: rule.path.clone(),
                access: rule.access.clone(),
                source: rule.source.clone(),
            })
            .collect(),
    }
}
