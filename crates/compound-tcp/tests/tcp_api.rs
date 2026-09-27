use compound_tcp::{
    evaluate_connection, explain_lock, lock_policy_from_path, ConnectionDecision,
    ConnectionRequest, DirectAction, EncryptedHostnamePolicy, TcpAllowRule, TcpDefault,
    TcpDirectPolicy, TcpLockDocument, TcpLockOptions, TcpProtocol, TcpSourceDocument,
};
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

fn parse_source(yaml: &str) -> TcpSourceDocument {
    serde_yaml::from_str(yaml).expect("parse source policy")
}

fn parse_lock(yaml: &str) -> TcpLockDocument {
    serde_yaml::from_str(yaml).expect("parse lock policy")
}

fn temp_policy_dir() -> PathBuf {
    let id = TEMP_ID.fetch_add(1, Ordering::Relaxed);
    let dir =
        std::env::temp_dir().join(format!("compound-tcp-api-test-{}-{id}", std::process::id()));
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

fn allow_map(lock: &TcpLockDocument) -> BTreeMap<String, TcpAllowRule> {
    lock.tcp
        .allow
        .iter()
        .map(|rule| (rule.host.clone().expect("host allow rule"), rule.clone()))
        .collect()
}

fn ports(values: &[u16]) -> BTreeSet<u16> {
    values.iter().copied().collect()
}

#[test]
fn parses_root_tcp_policy_fixture() {
    let policy: TcpSourceDocument = read_yaml("tcp.compound.yaml");

    assert_eq!(policy.version, 1);
    assert_eq!(policy.metadata.name, "github-coding-agent-tcp");
    assert_eq!(policy.include.len(), 1);
    assert_eq!(
        policy.include[0].path,
        PathBuf::from("./policies/github-npm.tcp.compound.yaml")
    );
    assert_eq!(policy.tcp.default, Some(TcpDefault::Deny));
    assert_eq!(
        policy.tcp.direct,
        Some(TcpDirectPolicy {
            tcp: DirectAction::Deny,
            udp: DirectAction::Deny,
            dns: DirectAction::Deny,
            raw_sockets: DirectAction::Deny,
        })
    );
    assert_eq!(
        policy.tcp.encrypted_hostname_unverifiable,
        Some(EncryptedHostnamePolicy::Deny)
    );
    assert_eq!(policy.tcp.deny_cidrs.len(), 10);

    let api_github = policy
        .tcp
        .allow
        .iter()
        .find(|rule| rule.host.as_deref() == Some("api.github.com"))
        .expect("api.github.com allow rule");
    assert_eq!(api_github.ports, ports(&[443]));
    assert_eq!(api_github.protocol, TcpProtocol::Tls);
    assert_eq!(
        api_github
            .limits
            .as_ref()
            .and_then(|limits| limits.max_upload_bytes)
            .expect("max upload bytes")
            .as_u64(),
        10 * 1024 * 1024
    );
}

#[test]
fn parses_github_npm_fragment_fixture() {
    let fragment: TcpSourceDocument = read_yaml("policies/github-npm.tcp.compound.yaml");

    assert_eq!(fragment.version, 1);
    assert_eq!(fragment.metadata.name, "github-npm-tcp");
    assert_eq!(fragment.tcp.default, None);
    assert_eq!(fragment.tcp.direct, None);

    let hosts: BTreeSet<_> = fragment
        .tcp
        .allow
        .iter()
        .map(|rule| rule.host.as_deref().expect("host rule"))
        .collect();
    assert_eq!(
        hosts,
        BTreeSet::from([
            "api.github.com",
            "codeload.github.com",
            "github.com",
            "objects.githubusercontent.com",
            "registry.npmjs.org",
        ])
    );
}

#[test]
fn parses_existing_tcp_lock_fixture() {
    let lock: TcpLockDocument = read_yaml("tcp-lock.compound.yaml");

    assert_eq!(lock.version, 1);
    assert_eq!(lock.source.root, PathBuf::from("tcp.compound.yaml"));
    assert_eq!(lock.source.includes.len(), 1);
    assert_eq!(lock.tcp.default, Some(TcpDefault::Deny));
    assert_eq!(lock.tcp.allow.len(), 5);
    assert_eq!(allow_map(&lock)["api.github.com"].ports, ports(&[443]));
}

#[test]
fn generates_tcp_lock_from_source_and_includes() {
    let options = TcpLockOptions::new(repo_root().join("tcp.compound.yaml"));
    let lock = lock_policy_from_path(&options).expect("lock policy");
    let fixture: TcpLockDocument = read_yaml("tcp-lock.compound.yaml");

    assert_eq!(lock.metadata, fixture.metadata);
    assert_eq!(lock.tcp.default, fixture.tcp.default);
    assert_eq!(lock.tcp.direct, fixture.tcp.direct);
    assert_eq!(
        lock.tcp.encrypted_hostname_unverifiable,
        fixture.tcp.encrypted_hostname_unverifiable
    );
    assert_eq!(lock.tcp.deny_cidrs, fixture.tcp.deny_cidrs);
    assert_eq!(allow_map(&lock), allow_map(&fixture));
    assert!(lock.digest.is_some());
}

#[test]
fn root_allow_rule_overrides_identical_fragment_destination() {
    let dir = temp_policy_dir();
    write_policy(
        &dir,
        "fragment.tcp.compound.yaml",
        r#"
version: 1
metadata:
  name: fragment
tcp:
  allow:
    - host: api.github.com
      ports: [443]
      protocol: tls
      limits:
        max_connections: 2
"#,
    );
    let root = write_policy(
        &dir,
        "tcp.compound.yaml",
        r#"
version: 1
metadata:
  name: root
include:
  - path: ./fragment.tcp.compound.yaml
    digest: sha256:REPLACE_WITH_PINNED_DIGEST
tcp:
  default: deny
  direct:
    tcp: deny
    udp: deny
    dns: deny
    raw_sockets: deny
  encrypted_hostname_unverifiable: deny
  deny_cidrs:
    - 127.0.0.0/8
  allow:
    - host: api.github.com
      ports: [443]
      protocol: tls
      limits:
        max_connections: 20
        max_upload_bytes: 10MiB
"#,
    );

    let lock = lock_policy_from_path(&TcpLockOptions::new(root)).expect("lock policy");
    let api_github = &allow_map(&lock)["api.github.com"];

    assert_eq!(lock.tcp.allow.len(), 1);
    assert_eq!(
        api_github
            .limits
            .as_ref()
            .and_then(|limits| limits.max_connections),
        Some(20)
    );
    assert_eq!(
        api_github
            .limits
            .as_ref()
            .and_then(|limits| limits.max_upload_bytes)
            .expect("max upload bytes")
            .as_u64(),
        10 * 1024 * 1024
    );
}

#[test]
fn root_policy_validation_rejects_missing_default() {
    let policy = parse_source(
        r#"
version: 1
metadata:
  name: missing-default
tcp:
  direct:
    tcp: deny
    udp: deny
    dns: deny
    raw_sockets: deny
  allow: []
"#,
    );

    let errors = policy
        .validate_root_policy()
        .expect_err("root policy should reject missing default");

    assert!(errors.iter().any(|error| {
        error.field == "tcp.default"
            && error
                .message
                .contains("root TCP policies must set default: deny")
    }));
}

#[test]
fn root_policy_validation_rejects_direct_network_allows() {
    let policy = parse_source(
        r#"
version: 1
metadata:
  name: direct-network
tcp:
  default: deny
  direct:
    tcp: allow
    udp: deny
    dns: deny
    raw_sockets: deny
  allow: []
"#,
    );

    let errors = policy
        .validate_root_policy()
        .expect_err("root policy should reject direct TCP allow");

    assert!(errors.iter().any(|error| {
        error.field == "tcp.direct.tcp" && error.message.contains("direct TCP must be denied")
    }));
}

#[test]
fn fragment_validation_rejects_root_only_defaults() {
    let fragment = parse_source(
        r#"
version: 1
metadata:
  name: invalid-fragment
tcp:
  default: deny
  allow:
    - host: github.com
      ports: [443]
      protocol: tls
"#,
    );

    let errors = fragment
        .validate_fragment()
        .expect_err("fragment should reject root-only defaults");

    assert!(errors.iter().any(|error| {
        error.field == "tcp.default" && error.message.contains("fragments must not set tcp.default")
    }));
}

#[test]
fn source_validation_rejects_invalid_ports() {
    let invalid = serde_yaml::from_str::<TcpSourceDocument>(
        r#"
version: 1
metadata:
  name: invalid-port
tcp:
  default: deny
  direct:
    tcp: deny
    udp: deny
    dns: deny
    raw_sockets: deny
  allow:
    - host: github.com
      ports: [0, 443, 70000]
      protocol: tls
"#,
    );

    assert!(invalid.is_err(), "ports must be in the range 1..=65535");
}

#[test]
fn source_validation_rejects_invalid_cidrs() {
    let invalid = serde_yaml::from_str::<TcpSourceDocument>(
        r#"
version: 1
metadata:
  name: invalid-cidr
tcp:
  default: deny
  direct:
    tcp: deny
    udp: deny
    dns: deny
    raw_sockets: deny
  deny_cidrs:
    - not-a-cidr
  allow: []
"#,
    );

    assert!(
        invalid.is_err(),
        "invalid CIDRs should be rejected while parsing"
    );
}

#[test]
fn root_policy_validation_rejects_missing_deny_cidrs() {
    let policy = parse_source(
        r#"
version: 1
metadata:
  name: missing-deny-cidrs
tcp:
  default: deny
  direct:
    tcp: deny
    udp: deny
    dns: deny
    raw_sockets: deny
  encrypted_hostname_unverifiable: deny
  allow:
    - host: github.com
      ports: [443]
      protocol: tls
"#,
    );

    let errors = policy
        .validate_root_policy()
        .expect_err("root policy should require denied CIDR ranges");

    assert!(errors.iter().any(|error| {
        error.field == "tcp.deny_cidrs"
            && error
                .message
                .contains("must define prohibited destination CIDRs")
    }));
}

#[test]
fn source_validation_rejects_url_like_hosts() {
    let policy = parse_source(
        r#"
version: 1
metadata:
  name: url-like-host
tcp:
  default: deny
  direct:
    tcp: deny
    udp: deny
    dns: deny
    raw_sockets: deny
  encrypted_hostname_unverifiable: deny
  deny_cidrs:
    - 127.0.0.0/8
  allow:
    - host: https://github.com/path
      ports: [443]
      protocol: tls
"#,
    );

    let errors = policy
        .validate_root_policy()
        .expect_err("root policy should reject URL-like host values");

    assert!(errors.iter().any(|error| {
        error.field == "tcp.allow.host" && error.message.contains("host must be a DNS hostname")
    }));
}

#[test]
fn parses_binary_byte_sizes() {
    let policy = parse_source(
        r#"
version: 1
metadata:
  name: byte-size
tcp:
  default: deny
  direct:
    tcp: deny
    udp: deny
    dns: deny
    raw_sockets: deny
  allow:
    - host: registry.npmjs.org
      ports: [443]
      protocol: tls
      limits:
        max_upload_bytes: 10MiB
"#,
    );

    let bytes = policy.tcp.allow[0]
        .limits
        .as_ref()
        .and_then(|limits| limits.max_upload_bytes)
        .expect("max upload bytes");

    assert_eq!(bytes.as_u64(), 10 * 1024 * 1024);
}

#[test]
fn explains_generated_lock() {
    let options = TcpLockOptions::new(repo_root().join("tcp.compound.yaml"));
    let lock = lock_policy_from_path(&options).expect("lock policy");
    let explanation = explain_lock(&lock);

    assert_eq!(explanation.default, "deny");
    assert_eq!(explanation.direct.tcp, "deny");
    assert_eq!(explanation.direct.udp, "deny");
    assert_eq!(explanation.direct.dns, "deny");
    assert_eq!(explanation.direct.raw_sockets, "deny");
    assert_eq!(explanation.allow_count, 5);
    assert_eq!(explanation.deny_cidr_count, 10);

    let hosts: BTreeSet<_> = explanation
        .allow
        .iter()
        .map(|rule| rule.host.as_str())
        .collect();
    assert!(hosts.contains("github.com"));
    assert!(hosts.contains("api.github.com"));
    assert!(hosts.contains("registry.npmjs.org"));
}

#[test]
fn evaluates_connections_against_lock() {
    let options = TcpLockOptions::new(repo_root().join("tcp.compound.yaml"));
    let lock = lock_policy_from_path(&options).expect("lock policy");

    let allowed = evaluate_connection(
        &lock,
        &ConnectionRequest::tls("api.github.com", "140.82.114.6".parse().unwrap(), 443),
    );
    assert_eq!(allowed.decision, ConnectionDecision::Allow);

    let wrong_port = evaluate_connection(
        &lock,
        &ConnectionRequest::tls("api.github.com", "140.82.114.6".parse().unwrap(), 80),
    );
    assert_eq!(wrong_port.decision, ConnectionDecision::Deny);

    let denied_cidr = evaluate_connection(
        &lock,
        &ConnectionRequest::tls("api.github.com", "127.0.0.1".parse().unwrap(), 443),
    );
    assert_eq!(denied_cidr.decision, ConnectionDecision::Deny);

    let unknown_host = evaluate_connection(
        &lock,
        &ConnectionRequest::tls("example.com", "93.184.216.34".parse().unwrap(), 443),
    );
    assert_eq!(unknown_host.decision, ConnectionDecision::Deny);
}

#[test]
fn lock_validation_rejects_incomplete_tcp_lock() {
    let lock = parse_lock(
        r#"
version: 1
metadata:
  name: incomplete-lock
source:
  root: tcp.compound.yaml
tcp:
  allow:
    - host: github.com
      ports: [443]
      protocol: tls
"#,
    );

    let errors = lock
        .validate_lock()
        .expect_err("lock should require complete deny-by-default policy");

    assert!(errors.iter().any(|error| error.field == "tcp.default"));
    assert!(errors.iter().any(|error| error.field == "tcp.direct"));
}
