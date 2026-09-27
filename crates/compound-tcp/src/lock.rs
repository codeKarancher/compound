use crate::schema::{
    normalize_host, DirectPolicy, HostnameVerificationPolicy, TcpAllowRule, TcpLockDocument,
    TcpPolicyBody, TcpSourceDocument,
};
use compound_policy::{Digest, DocumentKind, Include, LockSource, ValidationReport};
use std::{
    fs,
    path::{Path, PathBuf},
};
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct TcpLockOptions {
    pub root_policy_path: PathBuf,
    pub verify_include_digests: bool,
}

impl TcpLockOptions {
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

pub fn lock_policy_from_path(options: &TcpLockOptions) -> Result<TcpLockDocument, TcpLockError> {
    let bytes = fs::read(&options.root_policy_path).map_err(|source| TcpLockError::ReadPolicy {
        path: options.root_policy_path.clone(),
        source,
    })?;
    let source =
        serde_yaml::from_reader::<_, TcpSourceDocument>(bytes.as_slice()).map_err(|source| {
            TcpLockError::ParsePolicy {
                path: options.root_policy_path.clone(),
                source,
            }
        })?;
    lock_policy(source, options)
}

pub fn lock_policy(
    root: TcpSourceDocument,
    options: &TcpLockOptions,
) -> Result<TcpLockDocument, TcpLockError> {
    validate_source_document(&root)?;

    let root_dir = options
        .root_policy_path
        .parent()
        .unwrap_or_else(|| Path::new("."));

    let mut includes = Vec::new();
    let mut allow = Vec::<TcpAllowRule>::new();

    for include in &root.include {
        let include_path = root_dir.join(&include.path);
        let include_bytes = fs::read(&include_path).map_err(|source| TcpLockError::ReadPolicy {
            path: include_path.clone(),
            source,
        })?;
        verify_include_digest(include, &include_bytes, options)?;

        let fragment = serde_yaml::from_reader::<_, TcpSourceDocument>(include_bytes.as_slice())
            .map_err(|source| TcpLockError::ParsePolicy {
                path: include_path.clone(),
                source,
            })?;
        validate_fragment_document(&fragment, &include.path)?;

        for rule in fragment.tcp.allow {
            insert_or_replace_rule(&mut allow, normalize_rule(rule));
        }

        includes.push(include.clone());
    }

    for rule in root.tcp.allow {
        insert_or_replace_rule(&mut allow, normalize_rule(rule));
    }

    let tcp = TcpPolicyBody {
        default: root.tcp.default,
        direct: root.tcp.direct.or(Some(DirectPolicy::deny_all())),
        encrypted_hostname_unverifiable: root
            .tcp
            .encrypted_hostname_unverifiable
            .or(Some(HostnameVerificationPolicy::Deny)),
        deny_cidrs: root.tcp.deny_cidrs,
        allow,
    };

    let mut lock = TcpLockDocument {
        version: root.version,
        kind: Some(DocumentKind::TcpLock),
        metadata: root.metadata,
        source: LockSource {
            root: options.root_policy_path.clone(),
            includes,
            generated_by: None,
        },
        digest: None,
        tcp,
        audit: root.audit,
        validation: ValidationReport::default(),
    };

    let canonical_without_digest =
        serde_yaml::to_string(&lock).map_err(TcpLockError::SerializeLock)?;
    lock.digest = Some(Digest::sha256(canonical_without_digest.as_bytes()));

    Ok(lock)
}

fn validate_source_document(document: &TcpSourceDocument) -> Result<(), TcpLockError> {
    if document.version != 1 {
        return Err(TcpLockError::UnsupportedVersion(document.version));
    }

    if matches!(document.kind, Some(kind) if kind != DocumentKind::TcpPolicy) {
        return Err(TcpLockError::WrongKind {
            expected: DocumentKind::TcpPolicy,
            actual: document.kind,
        });
    }

    document
        .validate_root_policy()
        .map_err(TcpLockError::InvalidPolicy)?;

    Ok(())
}

fn validate_fragment_document(
    document: &TcpSourceDocument,
    _path: &Path,
) -> Result<(), TcpLockError> {
    if document.version != 1 {
        return Err(TcpLockError::UnsupportedVersion(document.version));
    }

    if matches!(document.kind, Some(kind) if kind != DocumentKind::TcpPolicy) {
        return Err(TcpLockError::WrongKind {
            expected: DocumentKind::TcpPolicy,
            actual: document.kind,
        });
    }

    document
        .validate_fragment()
        .map_err(TcpLockError::InvalidPolicy)?;

    Ok(())
}

fn verify_include_digest(
    include: &Include,
    bytes: &[u8],
    options: &TcpLockOptions,
) -> Result<(), TcpLockError> {
    if !options.verify_include_digests || include.digest.is_placeholder() {
        return Ok(());
    }

    let actual = Digest::sha256(bytes);
    if actual != include.digest {
        return Err(TcpLockError::DigestMismatch {
            path: include.path.clone(),
            expected: include.digest.clone(),
            actual,
        });
    }

    Ok(())
}

fn insert_or_replace_rule(rules: &mut Vec<TcpAllowRule>, rule: TcpAllowRule) {
    let key = rule.identity_key();
    if let Some(existing) = rules
        .iter_mut()
        .find(|existing| existing.identity_key() == key)
    {
        *existing = rule;
    } else {
        rules.push(rule);
    }
}

fn normalize_rule(mut rule: TcpAllowRule) -> TcpAllowRule {
    if let Some(host) = &mut rule.host {
        *host = normalize_host(host);
    }
    rule.ports.0.sort_unstable();
    rule.ports.0.dedup();
    rule
}

#[derive(Debug, Error)]
pub enum TcpLockError {
    #[error("failed to read TCP policy {path}: {source}")]
    ReadPolicy {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to parse TCP policy {path}: {source}")]
    ParsePolicy {
        path: PathBuf,
        source: serde_yaml::Error,
    },
    #[error("failed to serialize TCP lock: {0}")]
    SerializeLock(serde_yaml::Error),
    #[error("unsupported TCP policy version {0}")]
    UnsupportedVersion(u32),
    #[error("wrong document kind: expected {expected:?}, got {actual:?}")]
    WrongKind {
        expected: DocumentKind,
        actual: Option<DocumentKind>,
    },
    #[error("invalid TCP policy: {0:?}")]
    InvalidPolicy(Vec<crate::schema::TcpValidationError>),
    #[error("include digest mismatch for {path}: expected {expected}, got {actual}")]
    DigestMismatch {
        path: PathBuf,
        expected: Digest,
        actual: Digest,
    },
}
