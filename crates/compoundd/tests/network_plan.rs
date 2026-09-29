use compound_tcp::TcpLockDocument;
use compoundd::{build_cleanup_plan, build_network_plan, DryRunRunner, NetworkPlanOptions};

fn lock() -> TcpLockDocument {
    serde_yaml::from_str(
        r#"
version: 1
kind: tcp-lock
metadata:
  name: network-plan-test
source:
  root: tcp.compound.yaml
tcp:
  default: deny
  direct:
    tcp: deny
    udp: deny
    dns: deny
    raw_sockets: deny
  encrypted_hostname_unverifiable: deny
  deny_cidrs:
    - 10.0.0.0/8
    - 127.0.0.0/8
    - 169.254.0.0/16
    - ::1/128
    - fc00::/7
  allow:
    - host: api.github.com
      ports: [443]
      protocol: tls
"#,
    )
    .expect("parse tcp lock")
}

#[test]
fn network_plan_creates_namespace_veth_and_gateway_path() {
    let plan = build_network_plan(&lock(), &NetworkPlanOptions::new("agent-01"))
        .expect("build network plan");
    let rendered = plan.render_shell();

    assert!(rendered.contains("ip netns add compound-agent01"));
    assert!(rendered.contains("ip link add chagent01 type veth peer name cjagent01"));
    assert!(rendered.contains("ip netns exec compound-agent01 ip route add default"));
    assert!(!rendered.contains("compoundd gateway"));
    assert_eq!(plan.gateway_addr.port(), 15080);
}

#[test]
fn network_plan_denies_udp_dns_direct_tcp_and_denied_cidrs() {
    let plan = build_network_plan(&lock(), &NetworkPlanOptions::new("agent-01"))
        .expect("build network plan");
    let rendered = plan.render_shell();

    assert!(rendered.contains("ip protocol udp drop"));
    assert!(rendered.contains("tcp dport 53 drop"));
    assert!(rendered.contains("udp dport 53 drop"));
    assert!(rendered.contains("ip daddr 10.0.0.0/8 drop"));
    assert!(rendered.contains("ip daddr 127.0.0.0/8 drop"));
    assert!(rendered.contains("ip6 daddr ::1/128 drop"));
    assert!(rendered.contains("ip6 daddr fc00::/7 drop"));
    assert!(rendered.contains("ip protocol tcp tproxy ip to 10.200.0.1:15080"));
}

#[test]
fn network_plan_tproxies_tcp_to_gateway_and_installs_policy_route() {
    let plan = build_network_plan(&lock(), &NetworkPlanOptions::new("agent-01"))
        .expect("build network plan");
    let rendered = plan.render_shell();

    assert!(rendered.contains("iifname chagent01 ip protocol tcp tproxy ip to 10.200.0.1:15080"));
    assert!(rendered.contains("ip rule add fwmark 1 lookup 100"));
    assert!(rendered.contains("ip route add local 0.0.0.0/0 dev lo table 100"));
}

#[test]
fn network_plan_rejects_invalid_tcp_lock() {
    let mut lock = lock();
    lock.tcp.direct = None;

    let error = build_network_plan(&lock, &NetworkPlanOptions::new("agent-01"))
        .expect_err("invalid tcp lock should fail");

    assert!(error.to_string().contains("invalid TCP lock"));
}

#[test]
fn dry_run_runner_records_commands_without_executing() {
    let plan = build_network_plan(&lock(), &NetworkPlanOptions::new("agent-01"))
        .expect("build network plan");
    let mut runner = DryRunRunner::default();

    plan.apply(&mut runner).expect("dry run should succeed");

    assert_eq!(runner.commands, plan.commands);
}

#[test]
fn network_plan_has_cleanup_for_policy_route_nft_veth_and_namespace() {
    let plan = build_network_plan(&lock(), &NetworkPlanOptions::new("agent-01"))
        .expect("build network plan");
    let cleanup = plan.render_cleanup_shell();

    assert!(cleanup.contains("ip route delete local 0.0.0.0/0 dev lo table 100"));
    assert!(cleanup.contains("ip rule delete fwmark 1 lookup 100"));
    assert!(cleanup.contains("nft delete table inet compound_agent01"));
    assert!(cleanup.contains("ip link delete chagent01"));
    assert!(cleanup.contains("ip netns delete compound-agent01"));
}

#[test]
fn cleanup_plan_does_not_need_tcp_lock() {
    let plan =
        build_cleanup_plan(&NetworkPlanOptions::new("agent-01")).expect("build cleanup plan");
    let mut runner = DryRunRunner::default();

    plan.cleanup(&mut runner).expect("cleanup dry run");

    assert_eq!(runner.commands, plan.cleanup_commands);
    assert!(plan.commands.is_empty());
}

#[test]
fn network_plan_uses_custom_fwmark_and_routing_table() {
    let mut options = NetworkPlanOptions::new("agent-01");
    options.fwmark = 77;
    options.routing_table = 177;
    let plan = build_network_plan(&lock(), &options).expect("build network plan");
    let setup = plan.render_shell();
    let cleanup = plan.render_cleanup_shell();

    assert!(setup.contains("meta mark set 77 accept"));
    assert!(setup.contains("ip rule add fwmark 77 lookup 177"));
    assert!(setup.contains("ip route add local 0.0.0.0/0 dev lo table 177"));
    assert!(cleanup.contains("ip rule delete fwmark 77 lookup 177"));
    assert!(cleanup.contains("ip route delete local 0.0.0.0/0 dev lo table 177"));
}
