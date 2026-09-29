# Compound

Compound is a Linux-first process confinement project for agentic and untrusted
workloads. It aims to make a spawned process technically unable to use filesystem
or network authority that its policy did not grant, even when that process runs
arbitrary shell commands, child processes, scripts, or developer CLIs.

## Product Shape

Compound is being built around four user-facing pieces:

- **Filesystem confinement**: declare path-level access in `fs.compound.yaml`,
  generate a reviewed `fs-lock.compound.yaml`, and run a command under Linux
  Landlock with deny-by-default file access.
- **TCP egress policy**: declare allowed destinations in `tcp.compound.yaml` and
  generate a reviewed `tcp-lock.compound.yaml`. The schema, lock generation,
  evaluator, and explicit gateway test harness exist today.
- **Runtime launcher**: `compound exec --fs-lock ... -- <command...>` applies
  filesystem confinement, sanitizes dangerous environment variables, closes
  inherited file descriptors by default, sets `no_new_privs`, and fails closed
  outside Linux.
- **Transparent network enforcement planning**: `compoundd` now validates
  `tcp-lock` files and builds a namespace/veth/nftables/TPROXY command plan
  that routes jailed TCP through a trusted gateway while dropping denied
  transports and CIDRs. The plan is tested and inspectable; the privileged
  end-to-end process lifecycle is still being built.

Current tested claim:

> On supported Linux hosts, Compound can enforce filesystem restrictions for a
> spawned process tree using Landlock and has CI coverage for multiple
> adversarial file-access attempts.

Not yet claimed:

> Compound does not yet provide a fully integrated `compound exec --tcp`
> experience. `compoundd` can plan/apply the network boundary, but automatic
> privileged setup, gateway lifecycle management, and workload launch are still
> under construction.

## Commands

Build and test:

```sh
cargo fmt --all -- --check
cargo test --workspace
```

Generate a filesystem lock:

```sh
cargo run -p compound-cli -- fs lock \
  --policy fs.compound.yaml \
  --output fs-lock.compound.yaml
```

Validate without writing:

```sh
cargo run -p compound-cli -- fs lock --check
```

Explain a filesystem lock:

```sh
cargo run -p compound-cli -- fs explain --policy fs-lock.compound.yaml
```

Generate and explain a TCP lock:

```sh
cargo run -p compound-cli -- tcp lock
cargo run -p compound-cli -- tcp explain
```

Inspect the transparent network setup plan:

```sh
cargo run -p compoundd -- plan \
  --tcp-lock tcp-lock.compound.yaml \
  --jail-id demo
```

Dry-run the same plan through the runner:

```sh
cargo run -p compoundd -- apply \
  --tcp-lock tcp-lock.compound.yaml \
  --jail-id demo \
  --dry-run
```

Inspect the cleanup plan for the same jail:

```sh
cargo run -p compoundd -- cleanup \
  --jail-id demo \
  --dry-run
```

Run a command with filesystem enforcement on Linux:

```sh
cargo run -p compound-cli -- exec \
  --fs-lock fs-lock.compound.yaml \
  --workdir /workspace \
  -- \
  /bin/sh -c 'pwd'
```

On macOS and other non-Linux platforms, `compound exec` fails closed before
running the target command.

## Policy Files

The repo includes example policy and lock files:

- `fs.compound.yaml`: source filesystem policy.
- `fs-lock.compound.yaml`: generated filesystem lock file.
- `tcp.compound.yaml`: source TCP egress policy.
- `tcp-lock.compound.yaml`: generated TCP lock file.
- `policies/proc-minimal.fs.compound.yaml`: reusable filesystem fragment.
- `policies/github-npm.tcp.compound.yaml`: reusable TCP destination fragment.

Source policies are author-friendly. Lock files are the reviewed deployment
artifacts after includes are resolved, digests are checked, and validation has
run.

## Tested Filesystem Behavior

Linux CI runs actual `compound` subprocesses under Landlock. The current
end-to-end suite verifies that confined commands cannot:

- read files outside granted paths
- write, create, or delete outside granted paths
- execute files without an `execute` grant
- escape through symlinks
- escape through `..` parent traversal
- read through inherited file descriptors via `/proc/self/fd`
- read through inherited file descriptors via `/dev/fd`
- use an ungranted `--workdir` as an implicit read capability
- escape confinement from descendant processes
- read realistic secret fixtures such as fake SSH, cloud, kube, Docker, and
  browser credential files
- run at all when the lock is malformed or unsafe

The suite also verifies permission separation for `read` versus `list`, and
`write` versus `create` or `delete`.

One important Landlock nuance is documented in tests: an existing hard link
inside an allowed tree remains reachable through that allowed path. Rename
semantics around Landlock `REFER` are subtle and remain an open design item in
`TODO.md`.

## Codebase Map

The workspace is split into focused crates.

### `compound-policy`

Shared policy primitives:

- document kinds
- metadata
- include references
- lock source metadata
- digest parsing and verification helpers
- validation report types
- audit configuration types

This crate intentionally knows little about filesystem or TCP semantics. It is
the common vocabulary used by the domain crates.

### `compound-fs`

Filesystem policy and Landlock support:

- `schema.rs`: YAML data model for `fs` and `fs-lock` documents.
- `lock.rs`: include resolution, digest checking, duplicate/conflict handling,
  and lock generation.
- `explain.rs`: human-readable lock summaries.
- `landlock.rs`: compiles lock files into a Landlock plan and applies it on
  Linux.

The Linux implementation uses `O_PATH | O_CLOEXEC` for Landlock rule path file
descriptors, requires Landlock ABI 3 or newer, and handles special creation
rights so symlink, FIFO, socket, block-device, and character-device creation
remain denied by default.

### `compound-runtime`

Execution runtime for `compound exec`:

- reads and validates an `fs-lock`
- compiles a Landlock plan
- fails closed on non-Linux
- sets `no_new_privs`
- sanitizes dangerous dynamic-loading and startup environment variables
- closes inherited file descriptors by default
- applies Landlock before spawning the target process

The runtime does not yet implement UID/GID changes, capability dropping,
seccomp, cgroups, mount isolation, or structured audit logs.

### `compound-tcp`

TCP policy model and gateway logic:

- `schema.rs`: YAML data model for `tcp` and `tcp-lock` documents.
- `lock.rs`: include resolution and lock generation.
- `evaluate.rs`: connection decision engine.
- `explain.rs`: human-readable lock summaries.
- `gateway.rs`: explicit CONNECT-style gateway harness used to test policy,
  DNS resolution, deny decisions, audit events, proxying, and upload limits.
  It also exposes the Linux `SO_ORIGINAL_DST` helper and a raw transparent
  handler for IP/CIDR decisions. Denied transparent HTTP receives a generic
  `503 Service Unavailable`; denied non-HTTP receives no policy-specific bytes.

This crate does not itself create the transparent network boundary. It is the
policy/gateway brain used by `compoundd` and future runtime wiring.

### `compoundd`

Privileged network setup planning:

- reads and validates a `tcp-lock`
- creates an inspectable command plan for:
  - network namespace creation
  - veth pair setup
  - jailed default routing through the host veth
  - host-side nftables prerouting rules
  - UDP, ICMP, DNS, and denied-CIDR drops
  - TCP TPROXY interception to the gateway
  - policy routing for marked transparent proxy traffic
- supports `plan`, `apply --dry-run`, and `cleanup --dry-run`
- derives cleanup commands for policy routes, nftables tables, veth devices,
  and namespaces

This is not yet a full daemon lifecycle. The gateway process manager, privilege
model, idempotent apply/cleanup behavior, and `compound exec --tcp` integration
remain open.

### `compound-cli`

The `compound` binary:

```text
compound fs lock [--policy fs.compound.yaml] [--output fs-lock.compound.yaml] [--check]
compound fs explain [--policy fs-lock.compound.yaml]
compound tcp lock [--policy tcp.compound.yaml] [--output tcp-lock.compound.yaml] [--check]
compound tcp explain [--policy tcp-lock.compound.yaml]
compound exec [--fs-lock fs-lock.compound.yaml] [--workdir PATH] -- <command...>
```

`fs explain` and `tcp explain` validate lock semantics before printing.
`compound exec --tcp` and `--tcp-lock` currently fail with an explicit
unsupported error.

## Tests

Important test surfaces:

- `crates/compound-fs/tests/fs_api.rs`: filesystem schema, validation, lock
  generation, and explain behavior.
- `crates/compound-fs/tests/landlock_plan.rs`: Landlock plan compilation and
  invalid-plan rejection.
- `crates/compound-runtime/tests/exec_runtime.rs`: runtime fail-closed behavior,
  missing command handling, and environment sanitization.
- `crates/compound-cli/tests/cli_integration.rs`: end-to-end CLI behavior for
  lock/check/explain and cross-platform exec behavior.
- `crates/compound-cli/tests/linux_landlock_enforcement.rs`: Linux-only
  adversarial filesystem enforcement tests.
- `crates/compound-tcp/tests/tcp_api.rs`: TCP schema, validation, lock
  generation, explanation, and connection evaluation.
- `crates/compound-tcp/tests/gateway.rs`: explicit gateway proxy/audit/upload
  limit behavior, raw transparent gateway behavior, and Linux
  original-destination recovery smoke coverage. It also covers normalized
  transparent denial responses.
- `crates/compoundd/tests/network_plan.rs`: CI-safe transparent network setup
  plan tests for namespace/veth/nftables/TPROXY invariants.
- `crates/compoundd/tests/tproxy_adversarial.rs`: Linux privileged
  namespace/veth/nftables/TPROXY integration coverage, gated by
  `COMPOUND_RUN_PRIVILEGED_NET_TESTS=1`.

GitHub Actions runs both the normal Rust workspace suite and a Linux enforcement
job that explicitly exercises the Landlock tests.

## Roadmap

The live implementation checklist is in `TODO.md`. The largest remaining work is:

- `compoundd` privileged lifecycle and cleanup
- `compound exec --tcp` integration
- DNS confinement and gateway-controlled resolution
- richer runtime hardening: capabilities, UID/GID, seccomp, cgroups, mount
  isolation
- structured audit logs outside jailed write authority
- deeper filesystem edge-case semantics for rename/link/socket/FIFO/device
  behavior

The longer design lives in `compound-technical-proposal.md`. Future higher-level
runtime/container workflow ideas live in `compound-v1.1-proposal.md`.
