use compound_fs::{
    compile_landlock_plan, FsAccess, FsDefault, FsLockDocument, FsPathRule, FsPolicyBody,
    InheritedFileDescriptors,
};
use compound_policy::{DocumentKind, LockSource, Metadata, ValidationReport};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

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

fn plan_access_map(
    lock: &FsLockDocument,
) -> Result<BTreeMap<PathBuf, BTreeSet<FsAccess>>, Box<dyn std::error::Error>> {
    let plan = compile_landlock_plan(lock)?;
    Ok(plan
        .rules
        .into_iter()
        .map(|rule| (rule.path, rule.access))
        .collect())
}

fn lock_with_paths(default: FsDefault, paths: Vec<FsPathRule>) -> FsLockDocument {
    FsLockDocument {
        version: 1,
        kind: Some(DocumentKind::FsLock),
        metadata: Metadata {
            name: "landlock-plan-test".to_owned(),
            description: None,
            labels: BTreeMap::new(),
        },
        source: LockSource {
            root: PathBuf::from("fs.compound.yaml"),
            includes: Vec::new(),
            generated_by: None,
        },
        digest: None,
        policy: FsPolicyBody {
            default,
            paths,
            inherited_file_descriptors: Some(InheritedFileDescriptors::Deny),
        },
        audit: None,
        validation: ValidationReport::default(),
    }
}

#[test]
fn existing_fs_lock_fixture_compiles_to_fifteen_landlock_rules() {
    let lock: FsLockDocument = read_yaml("fs-lock.compound.yaml");
    let plan = compile_landlock_plan(&lock).expect("compile landlock plan");

    assert_eq!(plan.rules.len(), 15);
}

#[test]
fn compiled_plan_preserves_access_sets_from_lock() {
    let lock: FsLockDocument = read_yaml("fs-lock.compound.yaml");
    let rules = plan_access_map(&lock).expect("compile landlock plan");

    assert_eq!(
        rules[Path::new("/workspace")],
        access(&[
            FsAccess::Read,
            FsAccess::List,
            FsAccess::Write,
            FsAccess::Create,
            FsAccess::Delete,
            FsAccess::Rename,
        ])
    );
    assert_eq!(
        rules[Path::new("/usr")],
        access(&[FsAccess::Read, FsAccess::List, FsAccess::Execute])
    );
    assert_eq!(
        rules[Path::new("/inputs")],
        access(&[FsAccess::Read, FsAccess::List])
    );
    assert_eq!(rules[Path::new("/proc/cpuinfo")], access(&[FsAccess::Read]));
}

#[test]
fn landlock_plan_rejects_relative_paths() {
    let lock = lock_with_paths(
        FsDefault::Deny,
        vec![FsPathRule::new("workspace", [FsAccess::Read])],
    );

    let error =
        compile_landlock_plan(&lock).expect_err("relative lock paths must not compile to a plan");

    assert!(error.to_string().contains("absolute"));
}

#[test]
fn landlock_plan_rejects_default_inherit_locks() {
    let lock = lock_with_paths(
        FsDefault::Inherit,
        vec![FsPathRule::new("/workspace", [FsAccess::Read])],
    );

    let error = compile_landlock_plan(&lock).expect_err("inherited-default locks must not compile");

    assert!(error.to_string().contains("default"));
}

#[test]
fn landlock_plan_rejects_empty_path_lists() {
    let lock = lock_with_paths(FsDefault::Deny, Vec::new());

    let error = compile_landlock_plan(&lock).expect_err("empty lock paths must not compile");

    assert!(error.to_string().contains("path"));
}

#[test]
fn landlock_plan_collapses_identical_duplicate_paths() {
    let lock = lock_with_paths(
        FsDefault::Deny,
        vec![
            FsPathRule::new("/workspace", [FsAccess::Read, FsAccess::List]),
            FsPathRule::new("/workspace", [FsAccess::List, FsAccess::Read]),
        ],
    );

    let plan = compile_landlock_plan(&lock).expect("compile duplicate-identical path plan");

    assert_eq!(plan.rules.len(), 1);
    assert_eq!(plan.rules[0].path, PathBuf::from("/workspace"));
    assert_eq!(
        plan.rules[0].access,
        access(&[FsAccess::Read, FsAccess::List])
    );
}

#[test]
fn landlock_plan_rejects_conflicting_duplicate_paths() {
    let lock = lock_with_paths(
        FsDefault::Deny,
        vec![
            FsPathRule::new("/workspace", [FsAccess::Read]),
            FsPathRule::new("/workspace", [FsAccess::Read, FsAccess::Write]),
        ],
    );

    let error =
        compile_landlock_plan(&lock).expect_err("conflicting duplicate paths must not compile");

    assert!(error.to_string().contains("/workspace"));
}
