use compound_fs::{explain_lock as explain_fs_lock, FsLockDocument, FsLockOptions};
use compound_policy::{Severity, ValidationFinding};
use compound_runtime::ExecOptions;
use compound_tcp::{explain_lock as explain_tcp_lock, TcpLockDocument, TcpLockOptions};
use std::{
    ffi::OsString,
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
};
use thiserror::Error;

const DEFAULT_FS_POLICY: &str = "fs.compound.yaml";
const DEFAULT_FS_LOCK: &str = "fs-lock.compound.yaml";
const DEFAULT_TCP_POLICY: &str = "tcp.compound.yaml";
const DEFAULT_TCP_LOCK: &str = "tcp-lock.compound.yaml";

pub fn run<I>(args: I) -> Result<i32, CliError>
where
    I: IntoIterator<Item = OsString>,
{
    let command = Command::parse(args)?;
    command.execute(&mut io::stdout())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    Exec(ExecCommand),
    FsLock(LockCommand),
    FsExplain(ExplainCommand),
    TcpLock(LockCommand),
    TcpExplain(ExplainCommand),
}

impl Command {
    pub fn parse<I>(args: I) -> Result<Self, CliError>
    where
        I: IntoIterator<Item = OsString>,
    {
        let mut args = Args::new(args);
        let Some(domain) = args.next_string()? else {
            return Err(CliError::Help(usage()));
        };

        if domain == "-h" || domain == "--help" || domain == "help" {
            return Err(CliError::Help(usage()));
        }

        if domain == "exec" {
            return Ok(Self::Exec(parse_exec_args(args)?));
        }

        let Some(action) = args.next_string()? else {
            return Err(CliError::InvalidArguments(format!(
                "missing command after `{domain}`\n\n{}",
                usage()
            )));
        };

        match (domain.as_str(), action.as_str()) {
            ("fs", "lock") => Ok(Self::FsLock(parse_lock_args(
                args,
                DEFAULT_FS_POLICY,
                DEFAULT_FS_LOCK,
            )?)),
            ("fs", "explain") => Ok(Self::FsExplain(parse_explain_args(args, DEFAULT_FS_LOCK)?)),
            ("tcp", "lock") => Ok(Self::TcpLock(parse_lock_args(
                args,
                DEFAULT_TCP_POLICY,
                DEFAULT_TCP_LOCK,
            )?)),
            ("tcp", "explain") => Ok(Self::TcpExplain(parse_explain_args(
                args,
                DEFAULT_TCP_LOCK,
            )?)),
            _ => Err(CliError::InvalidArguments(format!(
                "unknown command `{domain} {action}`\n\n{}",
                usage()
            ))),
        }
    }

    pub fn execute<W: Write>(&self, writer: &mut W) -> Result<i32, CliError> {
        match self {
            Self::Exec(command) => exec(command),
            Self::FsLock(command) => fs_lock(command, writer),
            Self::FsExplain(command) => fs_explain(command, writer),
            Self::TcpLock(command) => tcp_lock(command, writer),
            Self::TcpExplain(command) => tcp_explain(command, writer),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecCommand {
    pub fs_lock: PathBuf,
    pub tcp_lock: Option<PathBuf>,
    pub jail_id: String,
    pub workdir: Option<PathBuf>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub clear_environment: bool,
    pub keep_environment: Vec<OsString>,
    pub command: Vec<OsString>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockCommand {
    pub policy: PathBuf,
    pub output: PathBuf,
    pub check: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExplainCommand {
    pub policy: PathBuf,
}

fn parse_lock_args(
    mut args: Args,
    default_policy: &str,
    default_output: &str,
) -> Result<LockCommand, CliError> {
    let mut command = LockCommand {
        policy: PathBuf::from(default_policy),
        output: PathBuf::from(default_output),
        check: false,
    };

    while let Some(arg) = args.next_string()? {
        match arg.as_str() {
            "--policy" => command.policy = args.required_path("--policy")?,
            "--output" => command.output = args.required_path("--output")?,
            "--check" => command.check = true,
            "-h" | "--help" => return Err(CliError::Help(usage())),
            _ => {
                return Err(CliError::InvalidArguments(format!(
                    "unexpected argument `{arg}`"
                )))
            }
        }
    }

    Ok(command)
}

fn parse_explain_args(mut args: Args, default_policy: &str) -> Result<ExplainCommand, CliError> {
    let mut command = ExplainCommand {
        policy: PathBuf::from(default_policy),
    };

    while let Some(arg) = args.next_string()? {
        match arg.as_str() {
            "--policy" => command.policy = args.required_path("--policy")?,
            "-h" | "--help" => return Err(CliError::Help(usage())),
            _ => {
                return Err(CliError::InvalidArguments(format!(
                    "unexpected argument `{arg}`"
                )))
            }
        }
    }

    Ok(command)
}

fn parse_exec_args(mut args: Args) -> Result<ExecCommand, CliError> {
    let mut command = ExecCommand {
        fs_lock: PathBuf::from(DEFAULT_FS_LOCK),
        tcp_lock: None,
        jail_id: "default".to_owned(),
        workdir: None,
        uid: None,
        gid: None,
        clear_environment: false,
        keep_environment: Vec::new(),
        command: Vec::new(),
    };

    while let Some(arg) = args.next_os() {
        if arg == "--" {
            command.command = args.rest();
            break;
        }

        let arg = arg.into_string().map_err(|value| {
            CliError::InvalidArguments(format!("argument is not valid UTF-8: {value:?}"))
        })?;
        match arg.as_str() {
            "--fs-lock" => command.fs_lock = args.required_path("--fs-lock")?,
            "--tcp" => command.tcp_lock = Some(PathBuf::from(DEFAULT_TCP_LOCK)),
            "--tcp-lock" => command.tcp_lock = Some(args.required_path("--tcp-lock")?),
            "--jail-id" => {
                command.jail_id = args.next_string()?.ok_or_else(|| {
                    CliError::InvalidArguments("missing value for `--jail-id`".to_owned())
                })?
            }
            "--workdir" => command.workdir = Some(args.required_path("--workdir")?),
            "--uid" => command.uid = Some(args.required_u32("--uid")?),
            "--gid" => command.gid = Some(args.required_u32("--gid")?),
            "--clear-env" => command.clear_environment = true,
            "--keep-env" => command
                .keep_environment
                .push(args.required_os("--keep-env")?),
            "-h" | "--help" => return Err(CliError::Help(usage())),
            _ => {
                return Err(CliError::InvalidArguments(format!(
                    "unexpected argument `{arg}` before --"
                )))
            }
        }
    }

    if command.command.is_empty() {
        return Err(CliError::InvalidArguments(
            "`compound exec` requires a command after --".to_owned(),
        ));
    }

    Ok(command)
}

fn exec(command: &ExecCommand) -> Result<i32, CliError> {
    let options = ExecOptions {
        fs_lock: command.fs_lock.clone(),
        tcp_lock: command.tcp_lock.clone(),
        jail_id: command.jail_id.clone(),
        workdir: command.workdir.clone(),
        uid: command.uid,
        gid: command.gid,
        clear_environment: command.clear_environment,
        keep_environment: command.keep_environment.clone(),
        command: command.command.clone(),
    };
    let status = compound_runtime::exec(&options)?;
    Ok(status.code().unwrap_or(1))
}

fn fs_lock<W: Write>(command: &LockCommand, writer: &mut W) -> Result<i32, CliError> {
    let lock = compound_fs::lock_policy_from_path(&FsLockOptions::new(&command.policy))?;
    if command.check {
        writeln!(
            writer,
            "filesystem policy OK: {} paths",
            lock.policy.paths.len()
        )?;
        return Ok(0);
    }

    write_yaml(&command.output, &lock)?;
    writeln!(writer, "wrote {}", command.output.display())?;
    Ok(0)
}

fn fs_explain<W: Write>(command: &ExplainCommand, writer: &mut W) -> Result<i32, CliError> {
    let lock: FsLockDocument = read_yaml(&command.policy)?;
    lock.validate_lock().map_err(CliError::InvalidFsLock)?;
    let explanation = explain_fs_lock(&lock);

    writeln!(writer, "filesystem policy:")?;
    if let Some(digest) = explanation.digest {
        writeln!(writer, "  digest: {digest}")?;
    }
    writeln!(
        writer,
        "  source.root: {}",
        explanation.source.root.display()
    )?;
    writeln!(
        writer,
        "  source.includes: {}",
        explanation.source.includes.len()
    )?;
    writeln!(writer, "  default: {}", explanation.default)?;
    writeln!(
        writer,
        "  inherited_file_descriptors: {}",
        explanation.inherited_file_descriptors
    )?;
    writeln!(writer, "  paths: {}", explanation.path_count)?;
    write_validation_findings(writer, &explanation.validation_findings)?;
    for path in explanation.paths {
        writeln!(
            writer,
            "    {}: {}{}",
            path.path.display(),
            format_debug_set(&path.access),
            path.source
                .as_ref()
                .map(|source| format!(" (from {})", source.display()))
                .unwrap_or_default()
        )?;
    }

    Ok(0)
}

fn tcp_lock<W: Write>(command: &LockCommand, writer: &mut W) -> Result<i32, CliError> {
    let lock = compound_tcp::lock_policy_from_path(&TcpLockOptions::new(&command.policy))?;
    if command.check {
        writeln!(
            writer,
            "TCP policy OK: {} allow rules",
            lock.tcp.allow.len()
        )?;
        return Ok(0);
    }

    write_yaml(&command.output, &lock)?;
    writeln!(writer, "wrote {}", command.output.display())?;
    Ok(0)
}

fn tcp_explain<W: Write>(command: &ExplainCommand, writer: &mut W) -> Result<i32, CliError> {
    let lock: TcpLockDocument = read_yaml(&command.policy)?;
    lock.validate_lock().map_err(CliError::InvalidTcpLock)?;
    let explanation = explain_tcp_lock(&lock);

    writeln!(writer, "TCP policy:")?;
    if let Some(digest) = explanation.digest {
        writeln!(writer, "  digest: {digest}")?;
    }
    writeln!(
        writer,
        "  source.root: {}",
        explanation.source.root.display()
    )?;
    writeln!(
        writer,
        "  source.includes: {}",
        explanation.source.includes.len()
    )?;
    writeln!(writer, "  default: {}", explanation.default)?;
    writeln!(writer, "  direct.tcp: {}", explanation.direct.tcp)?;
    writeln!(writer, "  direct.udp: {}", explanation.direct.udp)?;
    writeln!(writer, "  direct.dns: {}", explanation.direct.dns)?;
    writeln!(
        writer,
        "  direct.raw_sockets: {}",
        explanation.direct.raw_sockets
    )?;
    writeln!(
        writer,
        "  encrypted_hostname_unverifiable: {}",
        explanation.encrypted_hostname_unverifiable
    )?;
    writeln!(writer, "  deny_cidrs: {}", explanation.deny_cidr_count)?;
    writeln!(writer, "  allow: {}", explanation.allow_count)?;
    write_validation_findings(writer, &explanation.validation_findings)?;
    for rule in explanation.allow {
        writeln!(
            writer,
            "    {} {:?}: {}{}",
            rule.host,
            rule.ports,
            rule.protocol,
            rule.source
                .as_ref()
                .map(|source| format!(" (from {})", source.display()))
                .unwrap_or_default()
        )?;
    }

    Ok(0)
}

fn read_yaml<T>(path: &Path) -> Result<T, CliError>
where
    T: serde::de::DeserializeOwned,
{
    let bytes = fs::read(path).map_err(|source| CliError::ReadFile {
        path: path.to_path_buf(),
        source,
    })?;
    serde_yaml::from_reader(bytes.as_slice()).map_err(|source| CliError::ParseYaml {
        path: path.to_path_buf(),
        source,
    })
}

fn write_yaml<T>(path: &Path, value: &T) -> Result<(), CliError>
where
    T: serde::Serialize,
{
    let yaml = serde_yaml::to_string(value)?;
    fs::write(path, yaml).map_err(|source| CliError::WriteFile {
        path: path.to_path_buf(),
        source,
    })
}

fn format_debug_set<T: std::fmt::Debug>(value: &T) -> String {
    format!("{value:?}").to_ascii_lowercase()
}

fn write_validation_findings<W: Write>(
    writer: &mut W,
    findings: &[ValidationFinding],
) -> Result<(), CliError> {
    if findings.is_empty() {
        return Ok(());
    }

    writeln!(writer, "  validation:")?;
    for finding in findings {
        let severity = match finding.severity {
            Severity::Warning => "warning",
            Severity::Error => "error",
        };
        writeln!(writer, "    {severity}: {}", finding.message)?;
    }
    Ok(())
}

fn usage() -> String {
    [
        "Usage:",
        "  compound fs lock [--policy fs.compound.yaml] [--output fs-lock.compound.yaml] [--check]",
        "  compound fs explain [--policy fs-lock.compound.yaml]",
        "  compound tcp lock [--policy tcp.compound.yaml] [--output tcp-lock.compound.yaml] [--check]",
        "  compound tcp explain [--policy tcp-lock.compound.yaml]",
        "  compound exec [--fs-lock fs-lock.compound.yaml] [--tcp | --tcp-lock tcp-lock.compound.yaml] [--jail-id ID] [--workdir PATH] [--uid UID] [--gid GID] [--clear-env] [--keep-env NAME]... -- <command...>",
    ]
    .join("\n")
}

#[derive(Debug)]
struct Args {
    values: std::vec::IntoIter<OsString>,
}

impl Args {
    fn new<I>(args: I) -> Self
    where
        I: IntoIterator<Item = OsString>,
    {
        Self {
            values: args.into_iter().collect::<Vec<_>>().into_iter(),
        }
    }

    fn next_string(&mut self) -> Result<Option<String>, CliError> {
        self.values
            .next()
            .map(|value| {
                value.into_string().map_err(|value| {
                    CliError::InvalidArguments(format!("argument is not valid UTF-8: {value:?}"))
                })
            })
            .transpose()
    }

    fn next_os(&mut self) -> Option<OsString> {
        self.values.next()
    }

    fn rest(&mut self) -> Vec<OsString> {
        self.values.by_ref().collect()
    }

    fn required_path(&mut self, flag: &str) -> Result<PathBuf, CliError> {
        self.next_string()?
            .map(PathBuf::from)
            .ok_or_else(|| CliError::InvalidArguments(format!("missing value for `{flag}`")))
    }

    fn required_os(&mut self, flag: &str) -> Result<OsString, CliError> {
        self.next_os()
            .ok_or_else(|| CliError::InvalidArguments(format!("missing value for `{flag}`")))
    }

    fn required_u32(&mut self, flag: &str) -> Result<u32, CliError> {
        let value = self
            .next_string()?
            .ok_or_else(|| CliError::InvalidArguments(format!("missing value for `{flag}`")))?;
        value.parse().map_err(|_| {
            CliError::InvalidArguments(format!("invalid integer for `{flag}`: {value}"))
        })
    }
}

#[derive(Debug, Error)]
pub enum CliError {
    #[error("{0}")]
    Help(String),
    #[error("{0}")]
    InvalidArguments(String),
    #[error("{0}")]
    Unsupported(String),
    #[error("failed to read {}: {source}", path.display())]
    ReadFile {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to write {}: {source}", path.display())]
    WriteFile {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to parse YAML {}: {source}", path.display())]
    ParseYaml {
        path: PathBuf,
        source: serde_yaml::Error,
    },
    #[error(transparent)]
    SerializeYaml(#[from] serde_yaml::Error),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    FsLock(#[from] compound_fs::FsLockError),
    #[error(transparent)]
    TcpLock(#[from] compound_tcp::TcpLockError),
    #[error(transparent)]
    Runtime(#[from] compound_runtime::RuntimeError),
    #[error("invalid fs lock: {0:?}")]
    InvalidFsLock(Vec<compound_fs::FsValidationError>),
    #[error("invalid TCP lock: {0:?}")]
    InvalidTcpLock(Vec<compound_tcp::TcpValidationError>),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Command {
        Command::parse(args.iter().map(OsString::from)).expect("parse command")
    }

    #[test]
    fn parses_fs_lock_defaults() {
        assert_eq!(
            parse(&["fs", "lock"]),
            Command::FsLock(LockCommand {
                policy: PathBuf::from(DEFAULT_FS_POLICY),
                output: PathBuf::from(DEFAULT_FS_LOCK),
                check: false,
            })
        );
    }

    #[test]
    fn parses_tcp_lock_options() {
        assert_eq!(
            parse(&[
                "tcp",
                "lock",
                "--policy",
                "custom-tcp.yaml",
                "--output",
                "custom-lock.yaml",
                "--check",
            ]),
            Command::TcpLock(LockCommand {
                policy: PathBuf::from("custom-tcp.yaml"),
                output: PathBuf::from("custom-lock.yaml"),
                check: true,
            })
        );
    }

    #[test]
    fn parses_explain_defaults() {
        assert_eq!(
            parse(&["tcp", "explain"]),
            Command::TcpExplain(ExplainCommand {
                policy: PathBuf::from(DEFAULT_TCP_LOCK),
            })
        );
    }

    #[test]
    fn parses_exec_defaults() {
        assert_eq!(
            parse(&["exec", "--", "echo", "hi"]),
            Command::Exec(ExecCommand {
                fs_lock: PathBuf::from(DEFAULT_FS_LOCK),
                tcp_lock: None,
                jail_id: "default".to_owned(),
                workdir: None,
                uid: None,
                gid: None,
                clear_environment: false,
                keep_environment: Vec::new(),
                command: vec![OsString::from("echo"), OsString::from("hi")],
            })
        );
    }

    #[test]
    fn parses_exec_options() {
        assert_eq!(
            parse(&[
                "exec",
                "--fs-lock",
                "custom-fs-lock.yaml",
                "--tcp-lock",
                "custom-tcp-lock.yaml",
                "--jail-id",
                "build-42",
                "--workdir",
                "/workspace",
                "--uid",
                "1000",
                "--gid",
                "1001",
                "--clear-env",
                "--keep-env",
                "PATH",
                "--keep-env",
                "HOME",
                "--",
                "npm",
                "test",
            ]),
            Command::Exec(ExecCommand {
                fs_lock: PathBuf::from("custom-fs-lock.yaml"),
                tcp_lock: Some(PathBuf::from("custom-tcp-lock.yaml")),
                jail_id: "build-42".to_owned(),
                workdir: Some(PathBuf::from("/workspace")),
                uid: Some(1000),
                gid: Some(1001),
                clear_environment: true,
                keep_environment: vec![OsString::from("PATH"), OsString::from("HOME")],
                command: vec![OsString::from("npm"), OsString::from("test")],
            })
        );
    }

    #[test]
    fn rejects_invalid_exec_uid() {
        let error = Command::parse([
            OsString::from("exec"),
            OsString::from("--uid"),
            OsString::from("nobody"),
            OsString::from("--"),
            OsString::from("true"),
        ])
        .expect_err("uid should be numeric");
        assert!(matches!(error, CliError::InvalidArguments(_)));
    }

    #[test]
    fn rejects_exec_without_command() {
        let error = Command::parse([OsString::from("exec"), OsString::from("--")])
            .expect_err("exec should require a command");
        assert!(matches!(error, CliError::InvalidArguments(_)));
    }

    #[test]
    fn parses_tcp_exec_default_lock() {
        assert_eq!(
            Command::parse([
                OsString::from("exec"),
                OsString::from("--tcp"),
                OsString::from("--"),
                OsString::from("true"),
            ])
            .expect("parse tcp exec"),
            Command::Exec(ExecCommand {
                fs_lock: PathBuf::from(DEFAULT_FS_LOCK),
                tcp_lock: Some(PathBuf::from(DEFAULT_TCP_LOCK)),
                jail_id: "default".to_owned(),
                workdir: None,
                uid: None,
                gid: None,
                clear_environment: false,
                keep_environment: Vec::new(),
                command: vec![OsString::from("true")],
            })
        );
    }

    #[test]
    fn parses_tcp_exec_custom_lock() {
        assert_eq!(
            Command::parse([
                OsString::from("exec"),
                OsString::from("--tcp-lock"),
                OsString::from("tcp-lock.compound.yaml"),
                OsString::from("--"),
                OsString::from("true"),
            ])
            .expect("parse tcp exec"),
            Command::Exec(ExecCommand {
                fs_lock: PathBuf::from(DEFAULT_FS_LOCK),
                tcp_lock: Some(PathBuf::from("tcp-lock.compound.yaml")),
                jail_id: "default".to_owned(),
                workdir: None,
                uid: None,
                gid: None,
                clear_environment: false,
                keep_environment: Vec::new(),
                command: vec![OsString::from("true")],
            })
        );
    }
}
