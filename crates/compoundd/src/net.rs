use compound_tcp::TcpLockDocument;
use std::{
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddrV4},
    path::{Path, PathBuf},
    process::Command,
};
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkPlanOptions {
    pub jail_id: String,
    pub gateway_port: u16,
    pub host_addr: Ipv4Addr,
    pub jail_addr: Ipv4Addr,
    pub prefix_len: u8,
    pub fwmark: u32,
    pub routing_table: u32,
}

impl NetworkPlanOptions {
    pub fn new(jail_id: impl Into<String>) -> Self {
        Self {
            jail_id: jail_id.into(),
            gateway_port: 15080,
            host_addr: Ipv4Addr::new(10, 200, 0, 1),
            jail_addr: Ipv4Addr::new(10, 200, 0, 2),
            prefix_len: 30,
            fwmark: 1,
            routing_table: 100,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkPlan {
    pub jail_id: String,
    pub namespace: String,
    pub host_veth: String,
    pub jail_veth: String,
    pub gateway_addr: SocketAddrV4,
    pub commands: Vec<NetworkCommand>,
    pub cleanup_commands: Vec<NetworkCommand>,
}

impl NetworkPlan {
    pub fn render_shell(&self) -> String {
        render_commands(&self.commands)
    }

    pub fn render_cleanup_shell(&self) -> String {
        render_commands(&self.cleanup_commands)
    }

    pub fn apply<R: CommandRunner>(&self, runner: &mut R) -> Result<(), NetworkError> {
        for command in &self.commands {
            runner.run(command)?;
        }
        Ok(())
    }

    pub fn cleanup<R: CommandRunner>(&self, runner: &mut R) -> Result<(), NetworkError> {
        for command in &self.cleanup_commands {
            runner.run(command)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkCommand {
    pub program: String,
    pub args: Vec<String>,
}

impl NetworkCommand {
    pub fn new(
        program: impl Into<String>,
        args: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            program: program.into(),
            args: args.into_iter().map(Into::into).collect(),
        }
    }

    pub fn render_shell(&self) -> String {
        std::iter::once(shell_quote(&self.program))
            .chain(self.args.iter().map(|arg| shell_quote(arg)))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

pub trait CommandRunner {
    fn run(&mut self, command: &NetworkCommand) -> Result<(), NetworkError>;
}

#[derive(Debug, Default)]
pub struct DryRunRunner {
    pub commands: Vec<NetworkCommand>,
}

impl CommandRunner for DryRunRunner {
    fn run(&mut self, command: &NetworkCommand) -> Result<(), NetworkError> {
        self.commands.push(command.clone());
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct SystemRunner;

impl CommandRunner for SystemRunner {
    fn run(&mut self, command: &NetworkCommand) -> Result<(), NetworkError> {
        let status = Command::new(&command.program)
            .args(&command.args)
            .status()?;
        if !status.success() {
            return Err(NetworkError::CommandFailed {
                command: command.render_shell(),
                code: status.code(),
            });
        }
        Ok(())
    }
}

pub fn build_network_plan(
    lock: &TcpLockDocument,
    options: &NetworkPlanOptions,
) -> Result<NetworkPlan, NetworkError> {
    lock.validate_lock().map_err(NetworkError::InvalidTcpLock)?;
    validate_options(options)?;

    let jail_key = sanitize_identifier(&options.jail_id);
    let namespace = format!("compound-{jail_key}");
    let host_veth = interface_name("ch", &jail_key);
    let jail_veth = interface_name("cj", &jail_key);
    let table = format!("compound_{jail_key}");
    let gateway_addr = SocketAddrV4::new(options.host_addr, options.gateway_port);
    let host_cidr = format!("{}/{}", options.host_addr, options.prefix_len);
    let jail_cidr = format!("{}/{}", options.jail_addr, options.prefix_len);
    let gateway = gateway_addr.to_string();
    let host_addr = options.host_addr.to_string();
    let fwmark = options.fwmark.to_string();
    let routing_table = options.routing_table.to_string();

    let mut commands = vec![
        cmd("ip", ["netns", "add", namespace.as_str()]),
        cmd(
            "ip",
            [
                "link",
                "add",
                host_veth.as_str(),
                "type",
                "veth",
                "peer",
                "name",
                jail_veth.as_str(),
            ],
        ),
        cmd(
            "ip",
            [
                "link",
                "set",
                jail_veth.as_str(),
                "netns",
                namespace.as_str(),
            ],
        ),
        cmd(
            "ip",
            ["addr", "add", host_cidr.as_str(), "dev", host_veth.as_str()],
        ),
        cmd("ip", ["link", "set", host_veth.as_str(), "up"]),
        netns_cmd(
            &namespace,
            [
                "ip",
                "addr",
                "add",
                jail_cidr.as_str(),
                "dev",
                jail_veth.as_str(),
            ],
        ),
        netns_cmd(&namespace, ["ip", "link", "set", "lo", "up"]),
        netns_cmd(&namespace, ["ip", "link", "set", jail_veth.as_str(), "up"]),
        netns_cmd(
            &namespace,
            ["ip", "route", "add", "default", "via", host_addr.as_str()],
        ),
        cmd("nft", ["add", "table", "inet", table.as_str()]),
        cmd(
            "nft",
            [
                "add",
                "chain",
                "inet",
                table.as_str(),
                "prerouting",
                "{",
                "type",
                "filter",
                "hook",
                "prerouting",
                "priority",
                "mangle",
                ";",
                "policy",
                "accept",
                ";",
                "}",
            ],
        ),
        cmd(
            "nft",
            [
                "add",
                "rule",
                "inet",
                table.as_str(),
                "prerouting",
                "iifname",
                host_veth.as_str(),
                "ip",
                "protocol",
                "udp",
                "drop",
            ],
        ),
        cmd(
            "nft",
            [
                "add",
                "rule",
                "inet",
                table.as_str(),
                "prerouting",
                "iifname",
                host_veth.as_str(),
                "ip",
                "protocol",
                "icmp",
                "drop",
            ],
        ),
        cmd(
            "nft",
            [
                "add",
                "rule",
                "inet",
                table.as_str(),
                "prerouting",
                "iifname",
                host_veth.as_str(),
                "tcp",
                "dport",
                "53",
                "drop",
            ],
        ),
    ];

    for cidr in &lock.tcp.deny_cidrs {
        let family = match cidr.addr {
            IpAddr::V4(_) => "ip",
            IpAddr::V6(_) => "ip6",
        };
        commands.push(cmd(
            "nft",
            [
                "add",
                "rule",
                "inet",
                table.as_str(),
                "prerouting",
                "iifname",
                host_veth.as_str(),
                family,
                "daddr",
                &cidr.to_string(),
                "drop",
            ],
        ));
    }

    commands.extend([
        cmd(
            "nft",
            [
                "add",
                "rule",
                "inet",
                table.as_str(),
                "prerouting",
                "iifname",
                host_veth.as_str(),
                "udp",
                "dport",
                "53",
                "drop",
            ],
        ),
        cmd(
            "nft",
            [
                "add",
                "rule",
                "inet",
                table.as_str(),
                "prerouting",
                "iifname",
                host_veth.as_str(),
                "ip",
                "protocol",
                "tcp",
                "tproxy",
                "ip",
                "to",
                gateway.as_str(),
                "meta",
                "mark",
                "set",
                fwmark.as_str(),
                "accept",
            ],
        ),
        cmd(
            "ip",
            [
                "rule",
                "add",
                "fwmark",
                fwmark.as_str(),
                "lookup",
                routing_table.as_str(),
            ],
        ),
        cmd(
            "ip",
            [
                "route",
                "add",
                "local",
                "0.0.0.0/0",
                "dev",
                "lo",
                "table",
                routing_table.as_str(),
            ],
        ),
    ]);

    commands.push(cmd(
        "compoundd-gateway",
        [
            "--tcp-lock",
            "<tcp-lock>",
            "--listen",
            gateway.as_str(),
            "--namespace",
            namespace.as_str(),
        ],
    ));

    let cleanup_commands = build_cleanup_commands(&namespace, &host_veth, &table, options);

    Ok(NetworkPlan {
        jail_id: options.jail_id.clone(),
        namespace,
        host_veth,
        jail_veth,
        gateway_addr,
        commands,
        cleanup_commands,
    })
}

pub fn build_cleanup_plan(options: &NetworkPlanOptions) -> Result<NetworkPlan, NetworkError> {
    validate_options(options)?;

    let jail_key = sanitize_identifier(&options.jail_id);
    let namespace = format!("compound-{jail_key}");
    let host_veth = interface_name("ch", &jail_key);
    let jail_veth = interface_name("cj", &jail_key);
    let table = format!("compound_{jail_key}");
    let gateway_addr = SocketAddrV4::new(options.host_addr, options.gateway_port);
    let cleanup_commands = build_cleanup_commands(&namespace, &host_veth, &table, options);

    Ok(NetworkPlan {
        jail_id: options.jail_id.clone(),
        namespace,
        host_veth,
        jail_veth,
        gateway_addr,
        commands: Vec::new(),
        cleanup_commands,
    })
}

pub fn read_tcp_lock(path: &Path) -> Result<TcpLockDocument, NetworkError> {
    let bytes = fs::read(path).map_err(|source| NetworkError::ReadTcpLock {
        path: path.to_path_buf(),
        source,
    })?;
    serde_yaml::from_reader(bytes.as_slice()).map_err(|source| NetworkError::ParseTcpLock {
        path: path.to_path_buf(),
        source,
    })
}

fn validate_options(options: &NetworkPlanOptions) -> Result<(), NetworkError> {
    if sanitize_identifier(&options.jail_id).is_empty() {
        return Err(NetworkError::InvalidOptions(
            "jail id must contain at least one ASCII letter or digit".to_owned(),
        ));
    }
    if options.gateway_port == 0 {
        return Err(NetworkError::InvalidOptions(
            "gateway port must be non-zero".to_owned(),
        ));
    }
    if options.prefix_len > 32 {
        return Err(NetworkError::InvalidOptions(
            "IPv4 prefix length must be <= 32".to_owned(),
        ));
    }
    if options.fwmark == 0 {
        return Err(NetworkError::InvalidOptions(
            "fwmark must be non-zero".to_owned(),
        ));
    }
    if options.routing_table == 0 {
        return Err(NetworkError::InvalidOptions(
            "routing table must be non-zero".to_owned(),
        ));
    }
    Ok(())
}

fn build_cleanup_commands(
    namespace: &str,
    host_veth: &str,
    table: &str,
    options: &NetworkPlanOptions,
) -> Vec<NetworkCommand> {
    let fwmark = options.fwmark.to_string();
    let routing_table = options.routing_table.to_string();

    vec![
        cmd(
            "ip",
            [
                "route",
                "delete",
                "local",
                "0.0.0.0/0",
                "dev",
                "lo",
                "table",
                routing_table.as_str(),
            ],
        ),
        cmd(
            "ip",
            [
                "rule",
                "delete",
                "fwmark",
                fwmark.as_str(),
                "lookup",
                routing_table.as_str(),
            ],
        ),
        cmd("nft", ["delete", "table", "inet", table]),
        cmd("ip", ["link", "delete", host_veth]),
        cmd("ip", ["netns", "delete", namespace]),
    ]
}

fn cmd(program: &str, args: impl IntoIterator<Item = impl Into<String>>) -> NetworkCommand {
    NetworkCommand::new(program, args)
}

fn netns_cmd(namespace: &str, args: impl IntoIterator<Item = impl Into<String>>) -> NetworkCommand {
    let mut command_args = vec!["netns".to_owned(), "exec".to_owned(), namespace.to_owned()];
    command_args.extend(args.into_iter().map(Into::into));
    NetworkCommand::new("ip", command_args)
}

fn interface_name(prefix: &str, jail_id: &str) -> String {
    let mut name = format!("{prefix}{}", sanitize_identifier(jail_id));
    name.truncate(15);
    name
}

fn sanitize_identifier(value: &str) -> String {
    value
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_lowercase()
}

fn shell_quote(value: &str) -> String {
    if value
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || "-_./:{}<>".contains(character))
    {
        return value.to_owned();
    }
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn render_commands(commands: &[NetworkCommand]) -> String {
    commands
        .iter()
        .map(NetworkCommand::render_shell)
        .collect::<Vec<_>>()
        .join("\n")
}

#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("invalid TCP lock: {0:?}")]
    InvalidTcpLock(Vec<compound_tcp::TcpValidationError>),
    #[error("invalid network plan options: {0}")]
    InvalidOptions(String),
    #[error("failed to read tcp lock {}: {source}", path.display())]
    ReadTcpLock {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to parse tcp lock {}: {source}", path.display())]
    ParseTcpLock {
        path: PathBuf,
        source: serde_yaml::Error,
    },
    #[error("failed to execute command: {0}")]
    Io(#[from] std::io::Error),
    #[error("network setup command failed with code {code:?}: {command}")]
    CommandFailed { command: String, code: Option<i32> },
}
