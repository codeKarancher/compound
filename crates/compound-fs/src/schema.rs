use compound_policy::{
    AuditConfig, Digest, DocumentKind, Include, LockSource, Metadata, ValidationFinding,
    ValidationReport,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, path::PathBuf};

pub type FsValidationResult<T = ()> = Result<T, Vec<FsValidationError>>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct FsSourceDocument {
    pub version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<DocumentKind>,
    pub metadata: Metadata,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub include: Vec<Include>,
    pub policy: FsPolicyBody,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit: Option<AuditConfig>,
}

impl FsSourceDocument {
    pub fn validate_root_policy(&self) -> FsValidationResult {
        let mut errors = Vec::new();

        validate_version(self.version, &mut errors);
        validate_kind(self.kind, DocumentKind::FsPolicy, &mut errors);
        validate_metadata(&self.metadata, &mut errors);
        self.policy.validate_complete(&mut errors);

        finish_validation(errors)
    }

    pub fn validate_fragment(&self) -> FsValidationResult {
        let mut errors = Vec::new();

        validate_version(self.version, &mut errors);
        validate_kind(self.kind, DocumentKind::FsPolicy, &mut errors);
        validate_metadata(&self.metadata, &mut errors);
        self.policy.validate_fragment(&mut errors);

        finish_validation(errors)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct FsLockDocument {
    pub version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<DocumentKind>,
    pub metadata: Metadata,
    pub source: LockSource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<Digest>,
    pub policy: FsPolicyBody,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit: Option<AuditConfig>,
    #[serde(default, skip_serializing_if = "ValidationReport::is_empty")]
    pub validation: ValidationReport,
}

impl FsLockDocument {
    pub fn validate_lock(&self) -> FsValidationResult {
        let mut errors = Vec::new();

        validate_version(self.version, &mut errors);
        validate_kind(self.kind, DocumentKind::FsLock, &mut errors);
        validate_metadata(&self.metadata, &mut errors);
        self.policy.validate_complete(&mut errors);

        finish_validation(errors)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct FsPolicyBody {
    pub default: FsDefault,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<FsPathRule>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inherited_file_descriptors: Option<InheritedFileDescriptors>,
}

impl FsPolicyBody {
    pub fn validate_complete(&self, errors: &mut Vec<FsValidationError>) {
        if self.default != FsDefault::Deny {
            errors.push(FsValidationError::new(
                "policy.default",
                "complete filesystem policies must set default: deny",
            ));
        }

        self.validate_paths(errors);
    }

    pub fn validate_fragment(&self, errors: &mut Vec<FsValidationError>) {
        if self.default != FsDefault::Inherit {
            errors.push(FsValidationError::new(
                "policy.default",
                "filesystem policy fragments must set default: inherit",
            ));
        }

        self.validate_paths(errors);
    }

    fn validate_paths(&self, errors: &mut Vec<FsValidationError>) {
        let mut seen = BTreeSet::new();

        for rule in &self.paths {
            if !rule.path.is_absolute() {
                errors.push(FsValidationError::new(
                    "policy.paths.path",
                    format!(
                        "filesystem policy path must be absolute: {}",
                        rule.path.display()
                    ),
                ));
            }

            if rule.access.is_empty() {
                errors.push(FsValidationError::new(
                    "policy.paths.access",
                    format!("access list cannot be empty for {}", rule.path.display()),
                ));
            }

            if !seen.insert(rule.path.clone()) {
                errors.push(FsValidationError::new(
                    "policy.paths.path",
                    format!("duplicate filesystem path rule: {}", rule.path.display()),
                ));
            }
        }
    }

    pub fn validation_warnings(&self) -> Vec<ValidationFinding> {
        let mut warnings = Vec::new();

        for rule in &self.paths {
            let writable = rule.access.iter().any(|access| {
                matches!(
                    access,
                    FsAccess::Write | FsAccess::Create | FsAccess::Delete | FsAccess::Rename
                )
            });
            let executable = rule.access.contains(&FsAccess::Execute);

            if writable && executable {
                warnings.push(warning(format!(
                    "{} grants write/create/delete/rename together with execute",
                    rule.path.display()
                )));
            }

            if writable && is_broad_write_path(&rule.path) {
                warnings.push(warning(format!(
                    "{} is a broad host path with write-like access",
                    rule.path.display()
                )));
            }

            if writable && executable && is_temp_or_workspace_path(&rule.path) {
                warnings.push(warning(format!(
                    "{} is executable and writable by the confined process",
                    rule.path.display()
                )));
            }

            if is_runtime_path(&rule.path) && has_runtime_write_or_execute(&rule.access) {
                warnings.push(warning(format!(
                    "{} is a runtime/system path with write-like or execute access",
                    rule.path.display()
                )));
            }
        }

        warnings
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FsDefault {
    Deny,
    Inherit,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct FsPathRule {
    pub path: PathBuf,
    pub access: BTreeSet<FsAccess>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<PathBuf>,
}

impl FsPathRule {
    pub fn new(path: impl Into<PathBuf>, access: impl IntoIterator<Item = FsAccess>) -> Self {
        Self {
            path: path.into(),
            access: access.into_iter().collect(),
            source: None,
        }
    }

    pub fn with_source(mut self, source: impl Into<PathBuf>) -> Self {
        self.source = Some(source.into());
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FsAccess {
    Read,
    List,
    Write,
    Create,
    Delete,
    Rename,
    Execute,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InheritedFileDescriptors {
    Deny,
    Allow,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsValidationError {
    pub field: &'static str,
    pub message: String,
}

impl FsValidationError {
    pub fn new(field: &'static str, message: impl Into<String>) -> Self {
        Self {
            field,
            message: message.into(),
        }
    }
}

fn validate_version(version: u32, errors: &mut Vec<FsValidationError>) {
    if version != 1 {
        errors.push(FsValidationError::new(
            "version",
            format!("unsupported filesystem policy version: {version}"),
        ));
    }
}

fn validate_kind(
    actual: Option<DocumentKind>,
    expected: DocumentKind,
    errors: &mut Vec<FsValidationError>,
) {
    match actual {
        Some(actual) if actual == expected => {}
        Some(actual) => {
            errors.push(FsValidationError::new(
                "kind",
                format!("expected document kind {expected:?}, got {actual:?}"),
            ));
        }
        None => errors.push(FsValidationError::new(
            "kind",
            format!("document kind is required: {expected:?}"),
        )),
    }
}

fn validate_metadata(metadata: &Metadata, errors: &mut Vec<FsValidationError>) {
    if metadata.name.trim().is_empty() {
        errors.push(FsValidationError::new(
            "metadata.name",
            "metadata.name is required",
        ));
    }

    for key in metadata.labels.keys() {
        if key.trim().is_empty() {
            errors.push(FsValidationError::new(
                "metadata.labels",
                "metadata label keys cannot be empty",
            ));
        }
    }
}

fn finish_validation(errors: Vec<FsValidationError>) -> FsValidationResult {
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

fn warning(message: impl Into<String>) -> ValidationFinding {
    ValidationFinding {
        severity: compound_policy::Severity::Warning,
        message: message.into(),
    }
}

fn is_broad_write_path(path: &std::path::Path) -> bool {
    matches!(
        path.to_str(),
        Some("/") | Some("/usr") | Some("/bin") | Some("/etc") | Some("/home")
    )
}

fn is_temp_or_workspace_path(path: &std::path::Path) -> bool {
    matches!(
        path.to_str(),
        Some("/tmp") | Some("/var/tmp") | Some("/workspace")
    )
}

fn is_runtime_path(path: &std::path::Path) -> bool {
    path.starts_with("/proc") || path.starts_with("/sys") || path.starts_with("/dev")
}

fn has_runtime_write_or_execute(access: &BTreeSet<FsAccess>) -> bool {
    access.iter().any(|access| {
        matches!(
            access,
            FsAccess::Write
                | FsAccess::Create
                | FsAccess::Delete
                | FsAccess::Rename
                | FsAccess::Execute
        )
    })
}
