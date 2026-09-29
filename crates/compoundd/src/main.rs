use compound_tcp::{
    bind_transparent_listener, AuditSink, Gateway, GatewayAuditEvent, MemoryAuditSink,
    StaticResolver, SystemConnector,
};
use compoundd::{
    build_cleanup_plan, build_network_plan, read_tcp_lock, DryRunRunner, NetworkPlanOptions,
    SystemRunner,
};
use std::{
    env,
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    thread,
};

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
    let mut listen = None::<SocketAddr>;

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
            "--fwmark" => {
                options.fwmark = args
                    .next()
                    .ok_or_else(|| "missing --fwmark value".to_owned())?
                    .parse()
                    .map_err(|err| format!("invalid --fwmark: {err}"))?;
            }
            "--routing-table" => {
                options.routing_table = args
                    .next()
                    .ok_or_else(|| "missing --routing-table value".to_owned())?
                    .parse()
                    .map_err(|err| format!("invalid --routing-table: {err}"))?;
            }
            "--listen" => {
                listen = Some(
                    args.next()
                        .ok_or_else(|| "missing --listen value".to_owned())?
                        .parse::<SocketAddr>()
                        .map_err(|err| format!("invalid --listen: {err}"))?,
                );
            }
            "--dry-run" => dry_run = true,
            "-h" | "--help" => return Err(usage()),
            _ => return Err(format!("unexpected argument `{arg}`\n\n{}", usage())),
        }
    }

    match command.as_str() {
        "plan" => {
            let lock = read_tcp_lock(&tcp_lock).map_err(|error| error.to_string())?;
            let plan = build_network_plan(&lock, &options).map_err(|error| error.to_string())?;
            println!("{}", plan.render_shell());
            Ok(())
        }
        "apply" => {
            let lock = read_tcp_lock(&tcp_lock).map_err(|error| error.to_string())?;
            let plan = build_network_plan(&lock, &options).map_err(|error| error.to_string())?;
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
        "cleanup" => {
            let plan = build_cleanup_plan(&options).map_err(|error| error.to_string())?;
            if dry_run {
                let mut runner = DryRunRunner::default();
                plan.cleanup(&mut runner)
                    .map_err(|error| error.to_string())?;
                for command in runner.commands {
                    println!("{}", command.render_shell());
                }
                return Ok(());
            }
            let mut runner = SystemRunner;
            plan.cleanup(&mut runner).map_err(|error| error.to_string())
        }
        "gateway" => {
            let lock = read_tcp_lock(&tcp_lock).map_err(|error| error.to_string())?;
            let listen = listen.unwrap_or_else(|| options.gateway_addr().into());
            serve_gateway(lock, listen).map_err(|error| error.to_string())
        }
        _ => Err(format!("unknown command `{command}`\n\n{}", usage())),
    }
}

fn serve_gateway(lock: compound_tcp::TcpLockDocument, listen: SocketAddr) -> Result<(), String> {
    lock.validate_lock()
        .map_err(|errors| format!("invalid TCP lock: {errors:?}"))?;
    let listener = bind_transparent_listener(listen).map_err(|error| error.to_string())?;
    let gateway = Gateway::new(
        lock,
        Arc::new(StaticResolver::default()),
        Arc::new(SystemConnector),
        Arc::new(StderrAuditSink {
            fallback: MemoryAuditSink::default(),
        }),
    );

    loop {
        let (client, _) = listener.accept().map_err(|error| error.to_string())?;
        let gateway = gateway.clone();
        thread::spawn(move || {
            if let Err(error) = gateway.handle_transparent_client(client) {
                eprintln!("compoundd gateway: {error}");
            }
        });
    }
}

#[derive(Debug, Default)]
struct StderrAuditSink {
    fallback: MemoryAuditSink,
}

impl AuditSink for StderrAuditSink {
    fn record(&self, event: GatewayAuditEvent) {
        eprintln!("compoundd gateway audit: {event:?}");
        self.fallback.record(event);
    }
}

fn usage() -> String {
    [
        "Usage:",
        "  compoundd plan [--tcp-lock tcp-lock.compound.yaml] [--jail-id ID]",
        "  compoundd apply [--tcp-lock tcp-lock.compound.yaml] [--jail-id ID] [--dry-run]",
        "  compoundd cleanup [--jail-id ID] [--dry-run]",
        "  compoundd gateway [--tcp-lock tcp-lock.compound.yaml] [--listen ADDR:PORT]",
        "",
        "Options:",
        "  --gateway-port PORT",
        "  --host-addr IPv4",
        "  --jail-addr IPv4",
        "  --listen ADDR:PORT",
        "  --fwmark MARK",
        "  --routing-table TABLE",
    ]
    .join("\n")
}
