use crate::schema::{
    FsLockDocument, FsPathRule, FsPolicyBody, FsSourceDocument, InheritedFileDescriptors,
};
use compound_policy::{Digest, DocumentKind, Include, LockSource, ValidationReport};
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct FsLockOptions {
    pub root_policy_path: PathBuf,
    pub verify_include_digests: bool,
}

impl FsLockOptions {
    pub fn new(root_policy_path: impl Into<PathBuf>) -> Self {
        Self {
            root_policy_path: root_policy_path.into(),
            verify_include_digests: true,
        }
    }

    pub fn without_digest_verification(mut self) -> Self {
        self.verify_include_digests = false;
        self
    }
}

pub fn lock_policy_from_path(options: &FsLockOptions) -> Result<FsLockDocument, FsLockError> {
    let bytes = fs::read(&options.root_policy_path).map_err(|source| FsLockError::ReadPolicy {
        path: options.root_policy_path.clone(),
        source,
    })?;
    let source =
        serde_yaml::from_reader::<_, FsSourceDocument>(bytes.as_slice()).map_err(|source| {
            FsLockError::ParsePolicy {
                path: options.root_policy_path.clone(),
                source,
            }
        })?;
    lock_policy(source, options)
}

pub fn lock_policy(
    root: FsSourceDocument,
    options: &FsLockOptions,
) -> Result<FsLockDocument, FsLockError> {
    validate_source_document(&root)?;

    let root_dir = options
        .root_policy_path
        .parent()
        .unwrap_or_else(|| Path::new("."));

    let mut includes = Vec::new();
    let mut rules = BTreeMap::<PathBuf, FsPathRule>::new();

    for include in &root.include {
        let include_path = root_dir.join(&include.path);
        let include_bytes = fs::read(&include_path).map_err(|source| FsLockError::ReadPolicy {
            path: include_path.clone(),
            source,
        })?;
        verify_include_digest(include, &include_bytes, options)?;

        let fragment = serde_yaml::from_reader::<_, FsSourceDocument>(include_bytes.as_slice())
            .map_err(|source| FsLockError::ParsePolicy {
                path: include_path.clone(),
                source,
            })?;
        validate_fragment_document(&fragment, &include.path)?;

        for rule in fragment.policy.paths {
            insert_rule(&mut rules, rule.with_source(include.path.clone()))?;
        }

        includes.push(include.clone());
    }

    for rule in root.policy.paths {
        insert_rule(
            &mut rules,
            rule.with_source(options.root_policy_path.clone()),
        )?;
    }

    let policy = FsPolicyBody {
        default: root.policy.default,
        paths: rules.into_values().collect(),
        inherited_file_descriptors: root
            .policy
            .inherited_file_descriptors
            .or(Some(InheritedFileDescriptors::Deny)),
    };

    let mut lock = FsLockDocument {
        version: root.version,
        kind: Some(DocumentKind::FsLock),
        metadata: root.metadata,
        source: LockSource {
            root: options.root_policy_path.clone(),
            includes,
            generated_by: None,
        },
        digest: None,
        policy,
        audit: root.audit,
        validation: ValidationReport::default(),
    };
    lock.validation.findings = lock.policy.validation_warnings();

    let canonical_without_digest =
        serde_yaml::to_string(&lock).map_err(FsLockError::SerializeLock)?;
    lock.digest = Some(Digest::sha256(canonical_without_digest.as_bytes()));

    Ok(lock)
}

fn validate_source_document(document: &FsSourceDocument) -> Result<(), FsLockError> {
    document
        .validate_root_policy()
        .map_err(|errors| FsLockError::InvalidPolicy(format!("{errors:?}")))
}

fn validate_fragment_document(document: &FsSourceDocument, path: &Path) -> Result<(), FsLockError> {
    document.validate_fragment().map_err(|errors| {
        FsLockError::InvalidPolicy(format!(
            "included filesystem policy fragment {} is invalid: {errors:?}",
            path.display()
        ))
    })
}

fn verify_include_digest(
    include: &Include,
    bytes: &[u8],
    options: &FsLockOptions,
) -> Result<(), FsLockError> {
    if !options.verify_include_digests || include.digest.is_placeholder() {
        return Ok(());
    }

    let actual = Digest::sha256(bytes);
    if actual != include.digest {
        return Err(FsLockError::DigestMismatch {
            path: include.path.clone(),
            expected: include.digest.clone(),
            actual,
        });
    }

    Ok(())
}

fn insert_rule(
    rules: &mut BTreeMap<PathBuf, FsPathRule>,
    rule: FsPathRule,
) -> Result<(), FsLockError> {
    if !rule.path.is_absolute() {
        return Err(FsLockError::InvalidPolicy(format!(
            "filesystem policy path must be absolute: {}",
            rule.path.display()
        )));
    }

    match rules.get(&rule.path) {
        Some(existing) if existing.access != rule.access => {
            Err(FsLockError::ConflictingPathRule { path: rule.path })
        }
        Some(_) => Ok(()),
        None => {
            rules.insert(rule.path.clone(), rule);
            Ok(())
        }
    }
}

#[derive(Debug, Error)]
pub enum FsLockError {
    #[error("failed to read filesystem policy {path}: {source}")]
    ReadPolicy {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to parse filesystem policy {path}: {source}")]
    ParsePolicy {
        path: PathBuf,
        source: serde_yaml::Error,
    },
    #[error("failed to serialize filesystem lock: {0}")]
    SerializeLock(serde_yaml::Error),
    #[error("unsupported filesystem policy version {0}")]
    UnsupportedVersion(u32),
    #[error("wrong document kind: expected {expected:?}, got {actual:?}")]
    WrongKind {
        expected: DocumentKind,
        actual: Option<DocumentKind>,
    },
    #[error("invalid filesystem policy: {0}")]
    InvalidPolicy(String),
    #[error("conflicting filesystem access declarations for path {path}")]
    ConflictingPathRule { path: PathBuf },
    #[error("include digest mismatch for {path}: expected {expected}, got {actual}")]
    DigestMismatch {
        path: PathBuf,
        expected: Digest,
        actual: Digest,
    },
}
