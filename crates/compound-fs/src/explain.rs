use crate::schema::{FsAccess, FsLockDocument};
use compound_policy::{Digest, LockSource, ValidationFinding};
use std::{collections::BTreeSet, path::PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsExplanation {
    pub digest: Option<Digest>,
    pub source: LockSource,
    pub default: String,
    pub inherited_file_descriptors: String,
    pub path_count: usize,
    pub validation_findings: Vec<ValidationFinding>,
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
        digest: lock.digest.clone(),
        source: lock.source.clone(),
        default: format!("{:?}", lock.policy.default).to_ascii_lowercase(),
        inherited_file_descriptors: lock
            .policy
            .inherited_file_descriptors
            .map(|value| format!("{value:?}").to_ascii_lowercase())
            .unwrap_or_else(|| "unspecified".to_owned()),
        path_count: lock.policy.paths.len(),
        validation_findings: lock.validation.findings.clone(),
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
