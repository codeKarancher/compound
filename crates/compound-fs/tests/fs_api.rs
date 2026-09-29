use compound_fs::{
    explain_lock, lock_policy_from_path, FsAccess, FsDefault, FsLockDocument, FsLockError,
    FsLockOptions, FsSourceDocument, InheritedFileDescriptors,
};
use compound_policy::Severity;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

static TEMP_ID: AtomicU64 = AtomicU64::new(0);

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read_yaml<T: serde::de::DeserializeOwned>(relative: &str) -> T {
    let path = repo_root().join(relative);
    let bytes = fs::read(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
    serde_yaml::from_reader(bytes.as_slice())
        .unwrap_or_else(|err| panic!("parse {}: {err}", path.display()))
}

fn access(values: &[FsAccess]) -> BTreeSet<FsAccess> {
    values.iter().copied().collect()
}

fn path_access_map(lock: &FsLockDocument) -> BTreeMap<String, BTreeSet<FsAccess>> {
    lock.policy
        .paths
        .iter()
        .map(|rule| (rule.path.display().to_string(), rule.access.clone()))
        .collect()
}

fn parse_source(yaml: &str) -> FsSourceDocument {
    serde_yaml::from_str(yaml).expect("parse source policy")
}

fn temp_policy_dir() -> PathBuf {
    let id = TEMP_ID.fetch_add(1, Ordering::Relaxed);
    let dir =
        std::env::temp_dir().join(format!("compound-fs-api-test-{}-{id}", std::process::id()));
    fs::create_dir_all(&dir).unwrap_or_else(|err| panic!("create {}: {err}", dir.display()));
    dir
}

fn write_policy(dir: &Path, relative: &str, contents: &str) -> PathBuf {
    let path = dir.join(relative);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .unwrap_or_else(|err| panic!("create {}: {err}", parent.display()));
    }
    fs::write(&path, contents).unwrap_or_else(|err| panic!("write {}: {err}", path.display()));
    path
}

#[test]
fn parses_root_fs_policy_fixture() {
    let policy: FsSourceDocument = read_yaml("fs.compound.yaml");

    assert_eq!(policy.version, 1);
    assert_eq!(policy.metadata.name, "github-coding-agent-fs");
    assert_eq!(policy.include.len(), 1);
    assert_eq!(
        policy.include[0].path,
        PathBuf::from("./policies/proc-minimal.fs.compound.yaml")
    );
    assert_eq!(policy.policy.default, FsDefault::Deny);
    assert_eq!(
        policy.policy.inherited_file_descriptors,
        Some(InheritedFileDescriptors::Deny)
    );

    let paths: BTreeSet<_> = policy
        .policy
        .paths
        .iter()
        .map(|rule| rule.path.display().to_string())
        .collect();
    for expected in [
        "/workspace",
        "/inputs",
        "/outputs",
        "/tmp",
        "/usr",
        "/bin",
        "/lib",
        "/lib64",
    ] {
        assert!(paths.contains(expected), "missing {expected}");
    }
}

#[test]
fn parses_proc_fragment_fixture() {
    let fragment: FsSourceDocument = read_yaml("policies/proc-minimal.fs.compound.yaml");

    assert_eq!(fragment.policy.default, FsDefault::Inherit);
    assert_eq!(fragment.policy.paths.len(), 7);

    let by_path: BTreeMap<_, _> = fragment
        .policy
        .paths
        .iter()
        .map(|rule| (rule.path.display().to_string(), rule.access.clone()))
        .collect();

    assert_eq!(
        by_path["/proc/self"],
        access(&[FsAccess::Read, FsAccess::List])
    );
    assert_eq!(
        by_path["/proc/thread-self"],
        access(&[FsAccess::Read, FsAccess::List])
    );
    assert_eq!(by_path["/proc/cpuinfo"], access(&[FsAccess::Read]));
}

#[test]
fn parses_existing_fs_lock_fixture() {
    let lock: FsLockDocument = read_yaml("fs-lock.compound.yaml");

    assert_eq!(lock.version, 1);
    assert_eq!(lock.source.root, PathBuf::from("fs.compound.yaml"));
    assert_eq!(lock.source.includes.len(), 1);
    assert_eq!(lock.policy.default, FsDefault::Deny);
    assert_eq!(lock.policy.paths.len(), 15);
}

#[test]
fn generates_fs_lock_from_source_and_includes() {
    let options = FsLockOptions::new(repo_root().join("fs.compound.yaml"));
    let lock = lock_policy_from_path(&options).expect("lock policy");
    let fixture: FsLockDocument = read_yaml("fs-lock.compound.yaml");

    assert_eq!(lock.kind, Some(compound_policy::DocumentKind::FsLock));
    assert_eq!(lock.metadata, fixture.metadata);
    assert_eq!(lock.policy.default, fixture.policy.default);
    assert_eq!(
        lock.policy.inherited_file_descriptors,
        Some(InheritedFileDescriptors::Deny)
    );
    assert_eq!(lock.policy.paths.len(), fixture.policy.paths.len());
    assert_eq!(path_access_map(&lock), path_access_map(&fixture));
    assert!(lock.digest.is_some());
}

#[test]
fn explains_generated_lock() {
    let options = FsLockOptions::new(repo_root().join("fs.compound.yaml"));
    let lock = lock_policy_from_path(&options).expect("lock policy");
    let explanation = explain_lock(&lock);

    assert_eq!(explanation.default, "deny");
    assert_eq!(explanation.inherited_file_descriptors, "deny");
    assert_eq!(explanation.path_count, 15);
    assert_eq!(explanation.paths.len(), 15);
    assert!(explanation.digest.is_some());
    assert_eq!(
        explanation.source.root,
        repo_root().join("fs.compound.yaml")
    );
    assert!(explanation.validation_findings.is_empty());

    let proc_self = explanation
        .paths
        .iter()
        .find(|path| path.path == PathBuf::from("/proc/self"))
        .expect("explain /proc/self");
    assert_eq!(proc_self.access, access(&[FsAccess::Read, FsAccess::List]));
    assert_eq!(
        proc_self.source,
        Some(PathBuf::from("./policies/proc-minimal.fs.compound.yaml"))
    );

    let workspace = explanation
        .paths
        .iter()
        .find(|path| path.path == PathBuf::from("/workspace"))
        .expect("explain /workspace");
    assert_eq!(
        workspace.access,
        access(&[
            FsAccess::Read,
            FsAccess::List,
            FsAccess::Write,
            FsAccess::Create,
            FsAccess::Delete,
            FsAccess::Rename,
        ])
    );
    assert_eq!(workspace.source, Some(repo_root().join("fs.compound.yaml")));
}

#[test]
fn root_policy_validation_rejects_missing_kind() {
    let policy = parse_source(
        r#"
version: 1
metadata:
  name: missing-kind
policy:
  default: deny
  paths:
    - path: /workspace
      access: [read]
"#,
    );

    let errors = policy
        .validate_root_policy()
        .expect_err("root policy should require kind");

    assert!(errors.iter().any(|error| {
        error.field == "kind" && error.message.contains("document kind is required")
    }));
}

#[test]
fn root_policy_validation_warns_about_risky_grants() {
    let policy = parse_source(
        r#"
version: 1
kind: fs-policy
metadata:
  name: risky-grants
policy:
  default: deny
  paths:
    - path: /tmp
      access: [read, list, write, create, execute]
    - path: /etc
      access: [read, list, write]
    - path: /proc
      access: [read, list, write]
"#,
    );

    let warnings = policy.policy.validation_warnings();

    assert!(warnings
        .iter()
        .all(|finding| finding.severity == Severity::Warning));
    assert!(warnings
        .iter()
        .any(|finding| finding.message.contains("executable and writable")));
    assert!(warnings
        .iter()
        .any(|finding| finding.message.contains("broad host path")));
    assert!(warnings
        .iter()
        .any(|finding| finding.message.contains("runtime/system path")));
}

#[test]
fn root_policy_validation_rejects_inherited_default() {
    let policy = parse_source(
        r#"
version: 1
kind: fs-policy
metadata:
  name: invalid-root
policy:
  default: inherit
  paths:
    - path: /workspace
      access: [read]
"#,
    );

    let errors = policy
        .validate_root_policy()
        .expect_err("root policy should reject inherited default");

    assert!(errors.iter().any(|error| {
        error.field == "policy.default"
            && error
                .message
                .contains("complete filesystem policies must set default: deny")
    }));
}

#[test]
fn fragment_validation_rejects_deny_default() {
    let fragment = parse_source(
        r#"
version: 1
kind: fs-policy
metadata:
  name: invalid-fragment
policy:
  default: deny
  paths:
    - path: /proc/self
      access: [read]
"#,
    );

    let errors = fragment
        .validate_fragment()
        .expect_err("fragment should reject deny default");

    assert!(errors.iter().any(|error| {
        error.field == "policy.default"
            && error
                .message
                .contains("filesystem policy fragments must set default: inherit")
    }));
}

#[test]
fn root_policy_validation_rejects_non_absolute_paths() {
    let policy = parse_source(
        r#"
version: 1
kind: fs-policy
metadata:
  name: relative-path
policy:
  default: deny
  paths:
    - path: workspace
      access: [read]
"#,
    );

    let errors = policy
        .validate_root_policy()
        .expect_err("root policy should reject relative paths");

    assert!(errors.iter().any(|error| {
        error.field == "policy.paths.path"
            && error
                .message
                .contains("filesystem policy path must be absolute: workspace")
    }));
}

#[test]
fn root_policy_validation_rejects_duplicate_paths() {
    let policy = parse_source(
        r#"
version: 1
kind: fs-policy
metadata:
  name: duplicate-paths
policy:
  default: deny
  paths:
    - path: /workspace
      access: [read]
    - path: /workspace
      access: [read, list]
"#,
    );

    let errors = policy
        .validate_root_policy()
        .expect_err("root policy should reject duplicate paths");

    assert!(errors.iter().any(|error| {
        error.field == "policy.paths.path"
            && error
                .message
                .contains("duplicate filesystem path rule: /workspace")
    }));
}

#[test]
fn lock_generation_rejects_root_with_inherited_default() {
    let dir = temp_policy_dir();
    let root = write_policy(
        &dir,
        "fs.compound.yaml",
        r#"
version: 1
kind: fs-policy
metadata:
  name: invalid-root-lock
policy:
  default: inherit
  paths:
    - path: /workspace
      access: [read]
"#,
    );

    let error = lock_policy_from_path(&FsLockOptions::new(root))
        .expect_err("lock generation should reject inherited root default");

    assert!(
        matches!(error, FsLockError::InvalidPolicy(message) if message.contains("complete filesystem policies must set default: deny"))
    );
}

#[test]
fn lock_generation_rejects_fragment_with_deny_default() {
    let dir = temp_policy_dir();
    write_policy(
        &dir,
        "fragment.fs.compound.yaml",
        r#"
version: 1
kind: fs-policy
metadata:
  name: invalid-fragment-lock
policy:
  default: deny
  paths:
    - path: /proc/self
      access: [read]
"#,
    );
    let root = write_policy(
        &dir,
        "fs.compound.yaml",
        r#"
version: 1
kind: fs-policy
metadata:
  name: root
include:
  - path: fragment.fs.compound.yaml
    digest: sha256:REPLACE_WITH_PINNED_DIGEST
policy:
  default: deny
  paths:
    - path: /workspace
      access: [read]
"#,
    );

    let error = lock_policy_from_path(&FsLockOptions::new(root))
        .expect_err("lock generation should reject deny-default fragment");

    match error {
        FsLockError::InvalidPolicy(message) => {
            assert!(message.contains("policy.default"), "{message}");
            assert!(message.contains("inherit"), "{message}");
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn lock_generation_rejects_conflicting_include_and_root_paths() {
    let dir = temp_policy_dir();
    write_policy(
        &dir,
        "fragment.fs.compound.yaml",
        r#"
version: 1
kind: fs-policy
metadata:
  name: conflicting-fragment
policy:
  default: inherit
  paths:
    - path: /workspace
      access: [read]
"#,
    );
    let root = write_policy(
        &dir,
        "fs.compound.yaml",
        r#"
version: 1
kind: fs-policy
metadata:
  name: conflicting-root
include:
  - path: fragment.fs.compound.yaml
    digest: sha256:REPLACE_WITH_PINNED_DIGEST
policy:
  default: deny
  paths:
    - path: /workspace
      access: [read, list]
"#,
    );

    let error = lock_policy_from_path(&FsLockOptions::new(root))
        .expect_err("lock generation should reject conflicting path grants");

    assert!(
        matches!(error, FsLockError::ConflictingPathRule { path } if path == PathBuf::from("/workspace"))
    );
}

#[test]
fn lock_generation_allows_identical_include_and_root_paths_once() {
    let dir = temp_policy_dir();
    write_policy(
        &dir,
        "fragment.fs.compound.yaml",
        r#"
version: 1
kind: fs-policy
metadata:
  name: duplicate-fragment
policy:
  default: inherit
  paths:
    - path: /workspace
      access: [read, list]
"#,
    );
    let root = write_policy(
        &dir,
        "fs.compound.yaml",
        r#"
version: 1
kind: fs-policy
metadata:
  name: duplicate-root
include:
  - path: fragment.fs.compound.yaml
    digest: sha256:REPLACE_WITH_PINNED_DIGEST
policy:
  default: deny
  paths:
    - path: /workspace
      access: [list, read]
"#,
    );

    let lock = lock_policy_from_path(&FsLockOptions::new(root)).expect("lock policy");

    assert_eq!(lock.policy.paths.len(), 1);
    assert_eq!(lock.policy.paths[0].path, PathBuf::from("/workspace"));
    assert_eq!(
        lock.policy.paths[0].access,
        access(&[FsAccess::Read, FsAccess::List])
    );
}

#[test]
fn lock_generation_rejects_non_absolute_include_paths() {
    let dir = temp_policy_dir();
    write_policy(
        &dir,
        "fragment.fs.compound.yaml",
        r#"
version: 1
kind: fs-policy
metadata:
  name: relative-fragment
policy:
  default: inherit
  paths:
    - path: proc/self
      access: [read]
"#,
    );
    let root = write_policy(
        &dir,
        "fs.compound.yaml",
        r#"
version: 1
kind: fs-policy
metadata:
  name: root
include:
  - path: fragment.fs.compound.yaml
    digest: sha256:REPLACE_WITH_PINNED_DIGEST
policy:
  default: deny
  paths:
    - path: /workspace
      access: [read]
"#,
    );

    let error = lock_policy_from_path(&FsLockOptions::new(root))
        .expect_err("lock generation should reject relative include path grants");

    assert!(
        matches!(error, FsLockError::InvalidPolicy(message) if message.contains("filesystem policy path must be absolute: proc/self"))
    );
}
