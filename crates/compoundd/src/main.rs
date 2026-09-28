use compoundd::{
    build_network_plan, read_tcp_lock, DryRunRunner, NetworkPlanOptions, SystemRunner,
};
use std::{env, net::Ipv4Addr, path::PathBuf};

fn main() {
    match run() {
        Ok(()) => {}
        Err(error) => {
            eprintln!("compoundd: {error}");
            std::process::exit(1);
        }
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let Some(command) = args.next() else {
        return Err(usage());
    };

    let mut tcp_lock = PathBuf::from("tcp-lock.compound.yaml");
    let mut options = NetworkPlanOptions::new("default");
    let mut dry_run = command == "plan";

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--tcp-lock" => {
                tcp_lock = PathBuf::from(
                    args.next()
                        .ok_or_else(|| "missing --tcp-lock value".to_owned())?,
                )
            }
            "--jail-id" => {
                options.jail_id = args
                    .next()
                    .ok_or_else(|| "missing --jail-id value".to_owned())?
            }
            "--gateway-port" => {
                options.gateway_port = args
                    .next()
                    .ok_or_else(|| "missing --gateway-port value".to_owned())?
                    .parse()
                    .map_err(|err| format!("invalid --gateway-port: {err}"))?;
            }
            "--host-addr" => {
                options.host_addr = args
                    .next()
                    .ok_or_else(|| "missing --host-addr value".to_owned())?
                    .parse::<Ipv4Addr>()
                    .map_err(|err| format!("invalid --host-addr: {err}"))?;
            }
            "--jail-addr" => {
                options.jail_addr = args
                    .next()
                    .ok_or_else(|| "missing --jail-addr value".to_owned())?
                    .parse::<Ipv4Addr>()
                    .map_err(|err| format!("invalid --jail-addr: {err}"))?;
            }
            "--dry-run" => dry_run = true,
            "-h" | "--help" => return Err(usage()),
            _ => return Err(format!("unexpected argument `{arg}`\n\n{}", usage())),
        }
    }

    let lock = read_tcp_lock(&tcp_lock).map_err(|error| error.to_string())?;
    let plan = build_network_plan(&lock, &options).map_err(|error| error.to_string())?;

    match command.as_str() {
        "plan" => {
            println!("{}", plan.render_shell());
            Ok(())
        }
        "apply" => {
            if dry_run {
                let mut runner = DryRunRunner::default();
                plan.apply(&mut runner).map_err(|error| error.to_string())?;
                for command in runner.commands {
                    println!("{}", command.render_shell());
                }
                return Ok(());
            }
            let mut runner = SystemRunner;
            plan.apply(&mut runner).map_err(|error| error.to_string())
        }
        _ => Err(format!("unknown command `{command}`\n\n{}", usage())),
    }
}

fn usage() -> String {
    [
        "Usage:",
        "  compoundd plan [--tcp-lock tcp-lock.compound.yaml] [--jail-id ID]",
        "  compoundd apply [--tcp-lock tcp-lock.compound.yaml] [--jail-id ID] [--dry-run]",
        "",
        "Options:",
        "  --gateway-port PORT",
        "  --host-addr IPv4",
        "  --jail-addr IPv4",
    ]
    .join("\n")
}
