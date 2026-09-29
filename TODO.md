# Compound TODO

This is the working implementation checklist for getting Compound from the
current scaffold to the security claim in `compound-technical-proposal.md`.

## Current Truth

- Filesystem policy/schema/lock/explain APIs exist.
- `compound exec --fs-lock ...` applies Linux Landlock and is validated in CI.
- Linux FS enforcement tests cover several real bypass attempts:
  - reads/writes/creates/deletes outside grants
  - execute without execute grant
  - symlink escape
  - parent traversal escape
  - inherited file descriptor escape through `/proc/self/fd`
  - inherited file descriptor escape through `/dev/fd`
  - workdir outside grants
  - descendant process inheritance
  - `read`/`list` and `write`/`create`/`delete` separation
  - realistic host secret fixture denial
  - malformed lock files fail before target execution
  - several rename/link boundary behaviors
  - existing hard-link reachability is documented as a Landlock path semantics
    limitation
  - rename target-create behavior is documented as a Landlock semantics nuance
- TCP policy/schema/lock/explain/evaluator APIs exist.
- TCP gateway code is currently an explicit CONNECT-style test harness.
- `compoundd` can build and dry-run a namespace/veth/nftables/TPROXY network
  setup plan from a `tcp-lock`.
- `compound exec --tcp` is intentionally rejected until privileged `compoundd`
  lifecycle management and workload launch are wired together.

## Phase 0: Policy And CLI Foundation

- [x] Add integration tests for CLI commands, not just parser unit tests.
  - `compound fs lock`
  - `compound fs lock --check`
  - `compound fs explain`
  - `compound tcp lock`
  - `compound tcp lock --check`
  - `compound tcp explain`
  - invalid policy inputs
  - invalid lock inputs
  - output file is not written on `--check`
  - output file is not updated on validation failure
- [x] Test `compound exec` target exit-code propagation.
- [ ] Add `--root PATH` support for filesystem lock validation, as described in
  the proposal.
- [ ] Add policy validation warnings/errors for paths that do not exist under
  the target root filesystem.
- [ ] Add validation warnings for risky grants:
  - writable executable directories
  - broad write grants to `/`, `/usr`, `/bin`, `/etc`, `/home`
  - executable writable temp/workspace paths
  - runtime paths granted broader access than needed
- [x] Add validation for duplicate TCP allow rule identities.
- [x] Add validation for TCP CIDR allow rules covered by denied CIDRs.
- [ ] Add validation for broader ambiguous or overlapping TCP rules.
- [ ] Add validation for TCP hostname allow rules that resolve to denied CIDRs.
- [x] Validate lock semantics before `fs explain` and `tcp explain`.
- [ ] Improve `fs explain` and `tcp explain`.
  - Show source/include provenance.
  - Show effective lock digest.
  - Show warnings and compatibility notes.
  - Show lower-level Landlock rights or TCP enforcement implications.
- [ ] Decide whether `kind` should be mandatory in source and lock files.
- [ ] Add richer README usage docs and be explicit about what is implemented
  versus planned.

## Phase 1: Landlock Runtime Hardening

- [x] Replace ordinary `File::open` for Landlock rule paths with
  `open(O_PATH | O_CLOEXEC)`.
  - Important: rule setup should not require normal read permission on the path.
  - Important: descriptors used during setup should not leak into the target.
- [x] Implement initial Landlock ABI detection and compatibility negotiation.
  - Compound now requires Landlock ABI 3 or newer.
  - Older ABI versions fail closed.
  - Future work may relax this by mapping policy rights to per-ABI support.
  - Fail closed if a policy requires rights unsupported by the running kernel.
  - Emit a clear compatibility error explaining which right/ABI is missing.
- [x] Review Landlock rights mapping against current kernel ABI.
  - Confirm `read`, `list`, `write`, `create`, `delete`, `rename`, `execute`.
  - Explicitly decide how to handle symlink, FIFO, Unix socket, block device,
    character device, and other make rights.
  - Device/socket creation should remain denied unless there is an explicit
    future grant type.
- [ ] Add UID/GID execution support.
  - CLI proposal includes `--uid` and `--gid`.
  - Drop privileges before target execution.
  - Ensure supplementary groups are handled.
- [ ] Drop Linux capabilities before target execution.
  - Especially deny `CAP_SYS_ADMIN`, `CAP_NET_ADMIN`, `CAP_SYS_PTRACE`,
    `CAP_DAC_OVERRIDE`, `CAP_DAC_READ_SEARCH`, `CAP_BPF`, and similar escape
    relevant capabilities.
- [ ] Add seccomp profile support.
  - Start conservative and configurable.
  - Candidate denied syscall families: mount, namespace creation, ptrace, BPF,
    keyring, raw socket related calls, module loading, privileged device ops.
- [ ] Add cgroups v2 controls.
  - CPU
  - memory
  - PID count
  - I/O
  - wall-clock timeout
- [ ] Add structured local audit logging for `compound exec`.
  - process start
  - policy digest
  - Landlock setup success/failure
  - Landlock ABI version
  - runtime hardening applied
  - target exit status
  - runtime errors
- [ ] Ensure audit sink is outside jailed writable authority.
- [ ] Decide how to handle filesystem denial observability.
  - Landlock does not automatically give high-level path denial events.
  - Consider eBPF/auditd integration later, but do not block v0 on it.
- [ ] Expand environment sanitization.
  - Package manager config/env vars
  - Git config/env vars that redirect credential helpers or hooks
  - SSH agent variables
  - cloud credential env vars
  - language-specific dynamic loading hooks
- [ ] Decide how inherited stdio should be treated.
  - Current FD closing preserves `0`, `1`, and `2`.
  - Important: stdio can still be connected to sensitive host resources if the
    parent launches Compound carelessly.
  - Document this and consider optional stdio replacement.
- [ ] Avoid depending on `/proc/self/fd` for FD closing where possible.
  - Current Linux implementation scans `/proc/self/fd`.
  - This happens before Landlock, which is good.
  - Consider fallback using `close_range` where available.

## Phase 1: Filesystem Adversarial Tests

- [x] Add hard-link escape tests.
  - Hard link inside an allowed directory to data also reachable from a denied
    path.
  - Existing hard links inside an allowed directory are documented as readable
    under Landlock path-reachability semantics.
- [ ] Add/clarify rename/link boundary tests in more combinations.
  - allowed to denied
  - denied to allowed
  - document observed target-create semantics
  - decide whether Compound's high-level `rename` maps cleanly enough to
    Landlock `REFER`, or whether policy semantics need to be renamed/refined
  - hard-link creation across policy boundaries
- [ ] Add Unix socket tests.
  - Can a jailed process create a Unix socket in a writable allowed directory?
  - Can it connect to a host socket if the socket path is visible?
  - Docker socket and SSH agent socket should be explicit denial cases.
- [ ] Add FIFO tests.
  - Creation denied unless explicitly supported in future policy.
  - Reads/writes through FIFOs should not escape intended policy.
- [ ] Add device-node creation tests where permissions allow the attempt.
  - Expected outcome should be denial by default.
- [ ] Add append/truncate tests.
  - Existing file modification with `write`.
  - Truncate without create.
  - Append-only behavior is not currently modeled; document that.
- [x] Add realistic host secret denial fixtures.
  - fake home SSH key
  - fake cloud credentials
  - fake kubeconfig
  - fake Docker config
  - fake browser profile/token file
- [x] Add tests for malformed/insecure locks ensuring target never runs.
  - relative path
  - `default: inherit`
  - empty paths
  - unsupported policy version
  - conflicting duplicate paths
- [ ] Add tests for missing runtime dependencies producing fail-closed behavior
  rather than silently running unrestricted.

## Phase 2: TCP Enforcement

- [x] Design and implement initial `compoundd` network setup planner.
  - privileged setup component
  - creates network namespace
  - creates veth pair
  - configures routes
  - installs nftables/policy routing/TPROXY rules
  - dry-run/apply command runner
- [x] Implement initial `compoundd` cleanup planner.
  - removes policy route and fwmark rule for the jail routing table
  - deletes the jail nftables table
  - deletes the host veth and network namespace
- [ ] Implement full `compoundd` daemon lifecycle.
  - starts or coordinates the trusted gateway
  - makes setup and cleanup idempotent across partial failures
  - owns privilege separation and daemon API
  - exposes inspect/debug output for routes and firewall rules
- [x] Decide initial transparent interception mechanism.
  - TPROXY
  - packet marks
  - policy routing
  - original destination recovery
- [x] Implement low-level Linux original-destination recovery helper.
  - uses `SO_ORIGINAL_DST`
  - fails closed as unsupported on non-Linux hosts
  - has Linux CI smoke coverage on an accepted TCP socket
- [x] Implement initial raw transparent gateway handler.
  - recovers or accepts the original IP/port
  - allows only policy decisions enforceable without a claimed hostname
  - denies hostname-only policy until SNI/or hostname verification exists
- [x] Implement initial normalized transparent denial behavior.
  - cleartext HTTP receives generic `503 Service Unavailable`
  - non-HTTP receives close/reset style failure with no policy detail
  - trusted audit retains the detailed denial reason
- [ ] Prove TPROXY-redirected original destination recovery against the real
  transparent gateway path.
- [ ] Implement per-jail gateway lifecycle.
  - bind listener outside jailed privilege domain
  - associate gateway instance with immutable policy digest
  - prevent jailed process from signalling or reconfiguring gateway
- [ ] Implement real `compound exec --tcp tcp-lock.compound.yaml`.
  - Must fail closed if `compoundd` is unavailable.
  - Must fail closed if namespace setup fails.
  - Must fail closed if direct DNS/UDP/raw/direct TCP cannot be denied.
  - Must run FS and TCP enforcement together for the same process tree.
- [ ] Deny direct TCP outside the transparent gateway.
- [ ] Deny UDP by default.
  - Direct DNS over UDP/53
  - QUIC/HTTP3 over UDP/443
  - arbitrary UDP tunneling
- [ ] Deny raw sockets and packet sockets.
- [ ] Deny direct DNS.
  - UDP/53
  - TCP/53
  - DNS-over-TLS
  - DNS-over-HTTPS unless the DoH endpoint itself is intentionally permitted
    and the risk is documented
- [ ] Deny private, loopback, link-local, multicast, carrier-grade NAT, cloud
  metadata, and configured internal ranges.
- [ ] Gateway-controlled DNS resolution.
  - Resolve only approved hostnames.
  - Validate returned addresses against denied CIDRs.
  - Cache with bounded TTLs.
  - Audit DNS decisions.
  - Defend against rebinding between policy decision and connect.
- [ ] Implement destination identity validation.
  - Hostname allow rule
  - Gateway-resolved IP
  - Original destination IP/port
  - Visible TLS SNI where available
  - Deny missing/mismatched SNI for TLS hostname policies.
- [ ] Explicitly handle encrypted hostname cases.
  - If SNI/ECH makes hostname unverifiable and policy says deny, deny.
  - Do not pretend hostname policy is enforceable when metadata is hidden.
- [ ] Implement connection limits.
  - max connections
  - max upload bytes
  - max download bytes if desired
  - connection duration
  - rate limits
  - idle timeout
- [ ] Implement structured network audit.
  - allow/deny
  - jail id
  - policy digest
  - process metadata if available
  - requested hostname
  - original destination
  - resolved IPs
  - SNI/mismatch state
  - byte counts
  - duration
  - denial reason

## Phase 2: TCP Adversarial Tests

- [ ] Test direct TCP bypass attempts from common tools.
  - `curl`
  - Python socket
  - Node net/http/https
  - Go static binary
  - Rust static-ish test binary
  - netcat if available
- [ ] Test direct IP public destination denial.
- [ ] Test private network denial.
  - RFC1918
  - loopback
  - link-local
  - cloud metadata `169.254.169.254`
  - IPv6 loopback/link-local/ULA
- [ ] Test DNS bypass attempts.
  - UDP/53
  - TCP/53
  - DoT
  - DoH
  - custom resolver IP
- [ ] Test UDP and QUIC denial.
  - UDP/443
  - arbitrary UDP socket
- [ ] Test ICMP/raw socket denial.
- [ ] Test hostname/SNI mismatch denial.
- [ ] Test missing SNI denial for TLS hostname policy.
- [ ] Test DNS rebinding.
  - allowed hostname resolves to allowed IP initially
  - later resolves to denied/private IP
  - gateway must deny the denied resolution
- [ ] Test upload limit enforcement through the real transparent path.
- [ ] Test connection flood/limit enforcement.
- [ ] Test long-lived connection timeout.
- [ ] Test every allowed network path emits trusted audit events.
- [ ] Test denied attempts emit trusted audit events.
- [ ] Test jailed process cannot alter routing/firewall rules.
- [ ] Test jailed process cannot reach gateway management/control interfaces.

## Phase 3: Higher-Level Controls

- [ ] Secret broker design.
  - No broad host credential mounts.
  - Short-lived scoped credentials.
  - Bind credentials to destination/service/policy digest.
- [ ] Optional TLS-terminating application gateway design.
  - This is for semantic HTTP policy or bearer-token injection.
  - It is not the default transparent TCP gateway.
  - Requires explicit policy opt-in.
  - Requires client trust configuration.
  - Must be auditable.
  - Must avoid storing raw bearer tokens in policy files.
- [ ] Approval gates for dangerous allowed SaaS actions.
  - GitHub write operations
  - deployment
  - package/artifact publication
  - external communication
  - destructive cloud operations

## CI And Developer Experience

- [ ] Add a Linux VM/local dev recipe for running enforcement tests outside CI.
  - Lima
  - Multipass
  - Docker with required kernel support where possible
  - Vagrant or cloud devbox
- [ ] Pin or matrix Linux kernel/Ubuntu versions for Landlock ABI coverage.
- [ ] Keep macOS tests useful.
  - schema tests
  - lock generation tests
  - CLI parser/integration tests
  - TCP evaluator tests
  - gateway brain tests
- [ ] Add CI job for `cargo clippy --workspace --all-targets`.
- [ ] Add CI job for minimal supported Rust version if we decide to support one.
- [ ] Add CI job for security-focused Linux integration tests separately from
  normal workspace tests.
- [ ] Consider test binaries for adversarial behavior instead of shell-only tests.
  - direct syscalls
  - custom sockets
  - inherited descriptors
  - path traversal
  - FD passing

## Important Security Notes

- Do not claim full Compound v1 security until TCP namespace/gateway enforcement
  exists and is adversarially tested.
- The current TCP gateway is useful for policy and proxy logic tests, but it is
  not a confinement boundary.
- Application-level cooperation is not a security boundary.
- Environment variables are not a security boundary.
- CLI wrappers are not a security boundary.
- The desired network invariant requires kernel/network-namespace enforcement:
  every outbound connection from the jailed process tree must be blocked or
  forced through the trusted gateway.
- Landlock is meaningful, but it is not a VM boundary.
- Writable allowed directories can still be damaged by the workload.
- Allowed network destinations can still be exfiltration channels.
- Audit logs must be outside the jailed process's write authority.
- Policy lock files should be treated as reviewed deployment artifacts.
- Any unsupported enforcement component must fail closed.
