use compound_policy::{
    AuditConfig, Digest, DocumentKind, Include, LockSource, Metadata, ValidationFinding,
    ValidationReport,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{
    collections::BTreeSet,
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    path::PathBuf,
    str::FromStr,
};

pub type TcpValidationResult<T = ()> = Result<T, Vec<TcpValidationError>>;
pub type TcpDirectPolicy = DirectPolicy;
pub type EncryptedHostnamePolicy = HostnameVerificationPolicy;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct TcpSourceDocument {
    pub version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<DocumentKind>,
    pub metadata: Metadata,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub include: Vec<Include>,
    pub tcp: TcpPolicyBody,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit: Option<AuditConfig>,
}

impl TcpSourceDocument {
    pub fn validate_root_policy(&self) -> TcpValidationResult {
        let mut errors = Vec::new();

        validate_version(self.version, &mut errors);
        validate_kind(self.kind, DocumentKind::TcpPolicy, &mut errors);
        validate_metadata(&self.metadata, &mut errors);
        self.tcp.validate_complete(&mut errors);

        finish_validation(errors)
    }

    pub fn validate_fragment(&self) -> TcpValidationResult {
        let mut errors = Vec::new();

        validate_version(self.version, &mut errors);
        validate_kind(self.kind, DocumentKind::TcpPolicy, &mut errors);
        validate_metadata(&self.metadata, &mut errors);
        self.tcp.validate_fragment(&mut errors);

        finish_validation(errors)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct TcpLockDocument {
    pub version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<DocumentKind>,
    pub metadata: Metadata,
    pub source: LockSource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<Digest>,
    pub tcp: TcpPolicyBody,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit: Option<AuditConfig>,
    #[serde(default, skip_serializing_if = "ValidationReport::is_empty")]
    pub validation: ValidationReport,
}

impl TcpLockDocument {
    pub fn validate_lock(&self) -> TcpValidationResult {
        let mut errors = Vec::new();

        validate_version(self.version, &mut errors);
        validate_kind(self.kind, DocumentKind::TcpLock, &mut errors);
        validate_metadata(&self.metadata, &mut errors);
        self.tcp.validate_complete(&mut errors);

        finish_validation(errors)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct TcpPolicyBody {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default: Option<TcpDefault>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direct: Option<DirectPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_hostname_unverifiable: Option<HostnameVerificationPolicy>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deny_cidrs: Vec<Cidr>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<TcpAllowRule>,
}

impl TcpPolicyBody {
    pub fn validate_complete(&self, errors: &mut Vec<TcpValidationError>) {
        if self.default != Some(TcpDefault::Deny) {
            errors.push(TcpValidationError::new(
                "tcp.default",
                "root TCP policies must set default: deny",
            ));
        }

        match self.direct {
            Some(direct) => direct.validate_deny_all(errors),
            None => errors.push(TcpValidationError::new(
                "tcp.direct",
                "complete TCP policies must define direct traffic controls",
            )),
        }

        if self.encrypted_hostname_unverifiable != Some(HostnameVerificationPolicy::Deny) {
            errors.push(TcpValidationError::new(
                "tcp.encrypted_hostname_unverifiable",
                "complete TCP policies must deny unverifiable encrypted hostnames",
            ));
        }

        if self.deny_cidrs.is_empty() {
            errors.push(TcpValidationError::new(
                "tcp.deny_cidrs",
                "complete TCP policies must define prohibited destination CIDRs",
            ));
        }

        self.validate_rules(errors);
    }

    pub fn validate_fragment(&self, errors: &mut Vec<TcpValidationError>) {
        if self.default.is_some() {
            errors.push(TcpValidationError::new(
                "tcp.default",
                "fragments must not set tcp.default",
            ));
        }
        if self.direct.is_some() {
            errors.push(TcpValidationError::new(
                "tcp.direct",
                "fragments must not set tcp.direct",
            ));
        }
        if self.encrypted_hostname_unverifiable.is_some() {
            errors.push(TcpValidationError::new(
                "tcp.encrypted_hostname_unverifiable",
                "fragments must not set tcp.encrypted_hostname_unverifiable",
            ));
        }
        if !self.deny_cidrs.is_empty() {
            errors.push(TcpValidationError::new(
                "tcp.deny_cidrs",
                "fragments must not set tcp.deny_cidrs",
            ));
        }

        self.validate_rules(errors);
    }

    fn validate_rules(&self, errors: &mut Vec<TcpValidationError>) {
        for cidr in &self.deny_cidrs {
            if cidr.prefix_len > cidr.max_prefix_len() {
                errors.push(TcpValidationError::new(
                    "tcp.deny_cidrs",
                    format!("CIDR prefix is out of range: {cidr}"),
                ));
            }
        }

        let mut seen = BTreeSet::new();
        for rule in &self.allow {
            rule.validate(errors);
            if !seen.insert(rule.identity_key()) {
                errors.push(TcpValidationError::new(
                    "tcp.allow",
                    "duplicate TCP allow rule destination/ports/protocol",
                ));
            }

            if let Some(allow_cidr) = rule.cidr {
                for deny_cidr in &self.deny_cidrs {
                    if cidr_contains_cidr(*deny_cidr, allow_cidr) {
                        errors.push(TcpValidationError::new(
                            "tcp.allow.cidr",
                            format!(
                                "allow CIDR {allow_cidr} is covered by denied CIDR {deny_cidr}"
                            ),
                        ));
                    }
                }
            }
        }
    }

    pub fn validation_warnings(&self) -> Vec<ValidationFinding> {
        let mut warnings = Vec::new();

        for (left_index, left) in self.deny_cidrs.iter().enumerate() {
            for right in self.deny_cidrs.iter().skip(left_index + 1) {
                if cidr_contains_cidr(*left, *right) || cidr_contains_cidr(*right, *left) {
                    warnings.push(warning(format!(
                        "denied CIDRs {left} and {right} overlap; the narrower rule is redundant"
                    )));
                }
            }
        }

        for (left_index, left) in self.allow.iter().enumerate() {
            let Some(left_cidr) = left.cidr else {
                continue;
            };
            for right in self.allow.iter().skip(left_index + 1) {
                let Some(right_cidr) = right.cidr else {
                    continue;
                };

                if left.protocol == right.protocol
                    && ports_overlap(&left.ports, &right.ports)
                    && cidrs_overlap(left_cidr, right_cidr)
                {
                    warnings.push(warning(format!(
                        "allow CIDRs {left_cidr} and {right_cidr} overlap for {:?} on at least one port",
                        left.protocol
                    )));
                }
            }
        }

        for rule in &self.allow {
            if rule.cidr.is_some() && rule.protocol == TcpProtocol::Tls {
                warnings.push(warning(
                    "TLS CIDR allow rule cannot authenticate a hostname without SNI/hostname verification",
                ));
            }
            if rule.host.is_some() && rule.protocol == TcpProtocol::Tcp {
                warnings.push(warning(
                    "plain TCP hostname allow rule depends on gateway-controlled DNS identity",
                ));
            }
        }

        warnings
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TcpDefault {
    Deny,
    Inherit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DirectPolicy {
    pub tcp: DirectAction,
    pub udp: DirectAction,
    pub dns: DirectAction,
    pub raw_sockets: DirectAction,
}

impl DirectPolicy {
    pub fn deny_all() -> Self {
        Self {
            tcp: DirectAction::Deny,
            udp: DirectAction::Deny,
            dns: DirectAction::Deny,
            raw_sockets: DirectAction::Deny,
        }
    }

    fn validate_deny_all(&self, errors: &mut Vec<TcpValidationError>) {
        for (field, label, action) in [
            ("tcp.direct.tcp", "TCP", self.tcp),
            ("tcp.direct.udp", "UDP", self.udp),
            ("tcp.direct.dns", "DNS", self.dns),
            ("tcp.direct.raw_sockets", "raw sockets", self.raw_sockets),
        ] {
            if action != DirectAction::Deny {
                errors.push(TcpValidationError::new(
                    field,
                    format!("direct {label} must be denied"),
                ));
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectAction {
    Deny,
    Allow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostnameVerificationPolicy {
    Deny,
    Allow,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct TcpAllowRule {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cidr: Option<Cidr>,
    pub ports: PortList,
    pub protocol: TcpProtocol,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<TcpLimits>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<PathBuf>,
}

impl TcpAllowRule {
    pub fn host(
        host: impl Into<String>,
        ports: impl IntoIterator<Item = u16>,
        protocol: TcpProtocol,
    ) -> Self {
        Self {
            host: Some(host.into()),
            cidr: None,
            ports: PortList::new(ports),
            protocol,
            limits: None,
            source: None,
        }
    }

    pub fn identity_key(&self) -> TcpAllowKey {
        TcpAllowKey {
            destination: match (&self.host, self.cidr) {
                (Some(host), _) => TcpDestinationKey::Host(normalize_host(host)),
                (None, Some(cidr)) => TcpDestinationKey::Cidr(cidr),
                (None, None) => TcpDestinationKey::Invalid,
            },
            ports: self.ports.0.clone(),
            protocol: self.protocol,
        }
    }

    pub fn with_source(mut self, source: impl Into<PathBuf>) -> Self {
        self.source = Some(source.into());
        self
    }

    fn validate(&self, errors: &mut Vec<TcpValidationError>) {
        match (&self.host, self.cidr) {
            (Some(host), None) => validate_host(host, errors),
            (None, Some(_)) => {}
            (Some(_), Some(_)) => errors.push(TcpValidationError::new(
                "tcp.allow",
                "allow rules must specify either host or cidr, not both",
            )),
            (None, None) => errors.push(TcpValidationError::new(
                "tcp.allow",
                "allow rules must specify host or cidr",
            )),
        }

        if self.ports.0.is_empty() {
            errors.push(TcpValidationError::new(
                "tcp.allow.ports",
                "allow rules must specify at least one port",
            ));
        }

        for port in &self.ports.0 {
            if *port == 0 {
                errors.push(TcpValidationError::new(
                    "tcp.allow.ports",
                    "port 0 is not valid in TCP allow rules",
                ));
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TcpAllowKey {
    pub destination: TcpDestinationKey,
    pub ports: Vec<u16>,
    pub protocol: TcpProtocol,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TcpDestinationKey {
    Host(String),
    Cidr(Cidr),
    Invalid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PortList(pub Vec<u16>);

impl PortList {
    pub fn new(ports: impl IntoIterator<Item = u16>) -> Self {
        let mut ports = ports.into_iter().collect::<Vec<_>>();
        ports.sort_unstable();
        ports.dedup();
        Self(ports)
    }

    pub fn contains(&self, port: u16) -> bool {
        self.0.binary_search(&port).is_ok()
    }
}

impl PartialEq<std::collections::BTreeSet<u16>> for PortList {
    fn eq(&self, other: &std::collections::BTreeSet<u16>) -> bool {
        self.0
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<_>>()
            == *other
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TcpProtocol {
    Tls,
    Tcp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct TcpLimits {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_connections: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_upload_bytes: Option<ByteSize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ByteSize(pub u64);

impl ByteSize {
    pub fn as_u64(self) -> u64 {
        self.0
    }
}

impl Serialize for ByteSize {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u64(self.0)
    }
}

impl<'de> Deserialize<'de> for ByteSize {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = ByteSize;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a byte count or byte-size string such as 10MiB")
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(ByteSize(value))
            }

            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                u64::try_from(value)
                    .map(ByteSize)
                    .map_err(|_| E::custom("byte size cannot be negative"))
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                ByteSize::from_str(value).map_err(E::custom)
            }
        }

        deserializer.deserialize_any(Visitor)
    }
}

impl FromStr for ByteSize {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let value = value.trim();
        if value.is_empty() {
            return Err("byte size cannot be empty".to_owned());
        }

        let digit_len = value
            .chars()
            .take_while(|character| character.is_ascii_digit())
            .count();
        if digit_len == 0 {
            return Err(format!("byte size must start with a number: {value}"));
        }

        let amount = value[..digit_len]
            .parse::<u64>()
            .map_err(|err| format!("invalid byte size amount {value}: {err}"))?;
        let suffix = value[digit_len..].trim();
        let multiplier = match suffix {
            "" | "B" => 1,
            "KiB" => 1024,
            "MiB" => 1024 * 1024,
            "GiB" => 1024 * 1024 * 1024,
            "KB" => 1000,
            "MB" => 1000 * 1000,
            "GB" => 1000 * 1000 * 1000,
            _ => return Err(format!("unsupported byte-size suffix: {suffix}")),
        };

        amount
            .checked_mul(multiplier)
            .map(ByteSize)
            .ok_or_else(|| format!("byte size overflows u64: {value}"))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Cidr {
    pub addr: IpAddr,
    pub prefix_len: u8,
}

impl Cidr {
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(network), IpAddr::V4(ip)) => contains_v4(network, ip, self.prefix_len),
            (IpAddr::V6(network), IpAddr::V6(ip)) => contains_v6(network, ip, self.prefix_len),
            _ => false,
        }
    }

    fn max_prefix_len(&self) -> u8 {
        match self.addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        }
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix_len)
    }
}

impl Serialize for Cidr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Cidr {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Cidr::from_str(&value).map_err(serde::de::Error::custom)
    }
}

impl FromStr for Cidr {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (addr, prefix_len) = value
            .split_once('/')
            .ok_or_else(|| format!("CIDR must contain / prefix: {value}"))?;
        let addr = addr
            .parse::<IpAddr>()
            .map_err(|err| format!("invalid CIDR address {value}: {err}"))?;
        let prefix_len = prefix_len
            .parse::<u8>()
            .map_err(|err| format!("invalid CIDR prefix {value}: {err}"))?;
        let cidr = Self { addr, prefix_len };

        if cidr.prefix_len > cidr.max_prefix_len() {
            return Err(format!("CIDR prefix is out of range: {value}"));
        }

        Ok(cidr)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpValidationError {
    pub field: &'static str,
    pub message: String,
}

impl TcpValidationError {
    pub fn new(field: &'static str, message: impl Into<String>) -> Self {
        Self {
            field,
            message: message.into(),
        }
    }
}

pub fn normalize_host(host: &str) -> String {
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn validate_host(host: &str, errors: &mut Vec<TcpValidationError>) {
    let normalized = normalize_host(host);
    if normalized.is_empty() {
        errors.push(TcpValidationError::new(
            "tcp.allow.host",
            "host cannot be empty",
        ));
        return;
    }

    if normalized.contains('*') {
        errors.push(TcpValidationError::new(
            "tcp.allow.host",
            "wildcard hosts are not supported in v1",
        ));
    }

    if normalized.contains('/')
        || normalized.contains(':')
        || normalized.chars().any(char::is_whitespace)
    {
        errors.push(TcpValidationError::new(
            "tcp.allow.host",
            "host must be a DNS hostname, not a URL or host:port value",
        ));
    }

    if normalized.split('.').any(str::is_empty) {
        errors.push(TcpValidationError::new(
            "tcp.allow.host",
            "host labels cannot be empty",
        ));
    }

    if normalized.parse::<IpAddr>().is_ok() {
        errors.push(TcpValidationError::new(
            "tcp.allow.host",
            "direct IP grants must use cidr, not host",
        ));
    }
}

fn validate_version(version: u32, errors: &mut Vec<TcpValidationError>) {
    if version != 1 {
        errors.push(TcpValidationError::new(
            "version",
            format!("unsupported TCP policy version: {version}"),
        ));
    }
}

fn validate_kind(
    actual: Option<DocumentKind>,
    expected: DocumentKind,
    errors: &mut Vec<TcpValidationError>,
) {
    match actual {
        Some(actual) if actual == expected => {}
        Some(actual) => {
            errors.push(TcpValidationError::new(
                "kind",
                format!("expected document kind {expected:?}, got {actual:?}"),
            ));
        }
        None => errors.push(TcpValidationError::new(
            "kind",
            format!("document kind is required: {expected:?}"),
        )),
    }
}

fn validate_metadata(metadata: &Metadata, errors: &mut Vec<TcpValidationError>) {
    if metadata.name.trim().is_empty() {
        errors.push(TcpValidationError::new(
            "metadata.name",
            "metadata.name is required",
        ));
    }
}

fn finish_validation(errors: Vec<TcpValidationError>) -> TcpValidationResult {
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

fn contains_v4(network: Ipv4Addr, ip: Ipv4Addr, prefix_len: u8) -> bool {
    if prefix_len > 32 {
        return false;
    }
    let mask = if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    };
    u32::from(network) & mask == u32::from(ip) & mask
}

fn contains_v6(network: Ipv6Addr, ip: Ipv6Addr, prefix_len: u8) -> bool {
    if prefix_len > 128 {
        return false;
    }
    let mask = if prefix_len == 0 {
        0
    } else {
        u128::MAX << (128 - prefix_len)
    };
    u128::from(network) & mask == u128::from(ip) & mask
}

fn cidr_contains_cidr(container: Cidr, candidate: Cidr) -> bool {
    match (container.addr, candidate.addr) {
        (IpAddr::V4(_), IpAddr::V4(candidate_addr)) => {
            candidate.prefix_len >= container.prefix_len
                && container.contains(IpAddr::V4(candidate_addr))
        }
        (IpAddr::V6(_), IpAddr::V6(candidate_addr)) => {
            candidate.prefix_len >= container.prefix_len
                && container.contains(IpAddr::V6(candidate_addr))
        }
        _ => false,
    }
}

fn warning(message: impl Into<String>) -> ValidationFinding {
    ValidationFinding {
        severity: compound_policy::Severity::Warning,
        message: message.into(),
    }
}

fn ports_overlap(left: &PortList, right: &PortList) -> bool {
    left.0.iter().any(|port| right.contains(*port))
}

fn cidrs_overlap(left: Cidr, right: Cidr) -> bool {
    cidr_contains_cidr(left, right) || cidr_contains_cidr(right, left)
}
