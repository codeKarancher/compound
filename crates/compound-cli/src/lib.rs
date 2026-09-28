use compound_fs::{explain_lock as explain_fs_lock, FsLockDocument, FsLockOptions};
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
    pub workdir: Option<PathBuf>,
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
        workdir: None,
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
            "--workdir" => command.workdir = Some(args.required_path("--workdir")?),
            "--tcp" | "--tcp-lock" => {
                return Err(CliError::Unsupported(
                    "TCP enforcement for `compound exec` requires compoundd/gateway and is not implemented yet".to_owned(),
                ));
            }
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
        workdir: command.workdir.clone(),
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
    writeln!(writer, "  default: {}", explanation.default)?;
    writeln!(
        writer,
        "  inherited_file_descriptors: {}",
        explanation.inherited_file_descriptors
    )?;
    writeln!(writer, "  paths: {}", explanation.path_count)?;
    for path in explanation.paths {
        writeln!(
            writer,
            "    {}: {}",
            path.path.display(),
            format_debug_set(&path.access)
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
    writeln!(writer, "  default: {}", explanation.default)?;
    writeln!(writer, "  direct.tcp: {}", explanation.direct.tcp)?;
    writeln!(writer, "  direct.udp: {}", explanation.direct.udp)?;
    writeln!(writer, "  direct.dns: {}", explanation.direct.dns)?;
    writeln!(
        writer,
        "  direct.raw_sockets: {}",
        explanation.direct.raw_sockets
    )?;
    writeln!(writer, "  deny_cidrs: {}", explanation.deny_cidr_count)?;
    writeln!(writer, "  allow: {}", explanation.allow_count)?;
    for rule in explanation.allow {
        writeln!(
            writer,
            "    {} {:?}: {}",
            rule.host, rule.ports, rule.protocol
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

fn usage() -> String {
    [
        "Usage:",
        "  compound fs lock [--policy fs.compound.yaml] [--output fs-lock.compound.yaml] [--check]",
        "  compound fs explain [--policy fs-lock.compound.yaml]",
        "  compound tcp lock [--policy tcp.compound.yaml] [--output tcp-lock.compound.yaml] [--check]",
        "  compound tcp explain [--policy tcp-lock.compound.yaml]",
        "  compound exec [--fs-lock fs-lock.compound.yaml] [--workdir PATH] -- <command...>",
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
                workdir: None,
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
                "--workdir",
                "/workspace",
                "--",
                "npm",
                "test",
            ]),
            Command::Exec(ExecCommand {
                fs_lock: PathBuf::from("custom-fs-lock.yaml"),
                workdir: Some(PathBuf::from("/workspace")),
                command: vec![OsString::from("npm"), OsString::from("test")],
            })
        );
    }

    #[test]
    fn rejects_exec_without_command() {
        let error = Command::parse([OsString::from("exec"), OsString::from("--")])
            .expect_err("exec should require a command");
        assert!(matches!(error, CliError::InvalidArguments(_)));
    }

    #[test]
    fn rejects_tcp_exec_until_gateway_exists() {
        let error = Command::parse([
            OsString::from("exec"),
            OsString::from("--tcp-lock"),
            OsString::from("tcp-lock.compound.yaml"),
            OsString::from("--"),
            OsString::from("true"),
        ])
        .expect_err("tcp exec should be unsupported");
        assert!(matches!(error, CliError::Unsupported(_)));
    }
}
