# Compound: A Portable Process Jail for Agentic and Untrusted Workloads

**Status:** Technical proposal  
**Audience:** Security, platform, infrastructure, developer-tools, and AI-agent engineers  
**Primary platform:** Linux  
**Initial deployment target:** Local Linux command execution

## 1. Executive summary

Compound is a Linux-first process-confinement system for agentic workloads and other untrusted or semi-trusted processes. It enforces a simple security principle:

> A process must be technically unable to exercise capabilities that its policy has not granted, regardless of model behavior, prompt injection, tool misuse, compromised dependencies, or arbitrary child-process execution.

The system combines two independent kernel-enforced boundaries:

1. **Landlock filesystem confinement** for fine-grained, path-based file I/O permissions, including read, write, execute, create, delete, rename, and directory access.
2. **An isolated network namespace plus mandatory transparent TCP gateway** for deny-by-default external network egress. Every TCP connection initiated by the jailed process or any descendant process is forced through a trusted policy-enforcement gateway. Direct Internet, LAN, DNS, cloud-metadata, raw-socket, and UDP access are denied by default.

This design intentionally does not rely on an agent cooperatively using a tool API or obeying shell guidance. Agent processes may run ordinary developer CLIs such as `gh`, Git, package managers, `curl`, language runtimes, custom binaries, and scripts. The enforcement point operates below the application layer, so a CLI cannot bypass the policy by choosing a different library or opening a raw TCP socket.

Compound is useful for coding agents, CI jobs, plugin hosts, data-processing tasks, downloaded utilities, IDE extensions, untrusted build steps, and any workload that needs narrow, auditable authority.

## 2. Goals and non-goals

### 2.1 Goals

- Enforce least-privilege filesystem access for a process tree using Linux Landlock.
- Enforce mandatory, deny-by-default network egress for a process tree.
- Support normal, arbitrary Linux CLIs without requiring their source code to integrate with Compound.
- Express policy in a portable, declarative YAML format.
- Provide native Linux binaries with a clear local runtime model.
- Make denials explainable and provide an auditable event stream.
- Operate safely when the workload is actively adversarial.
- Fail closed when required kernel features or enforcement components are absent.

### 2.2 Non-goals for v1

- Prevent all damage to data the policy intentionally makes writable.
- Provide a hypervisor or VM security boundary.
- Decode or inspect arbitrary encrypted application payloads.
- Support unrestricted UDP, QUIC/HTTP/3, raw IP, multicast, or peer-to-peer protocols.
- Guarantee semantic safety of permitted SaaS actions, such as a destructive API request to an approved service.
- Replace container hardening, Kubernetes policy, cloud IAM, secret management, or secure software supply-chain practices.

## 3. Threat model

### 3.1 In scope

Compound assumes that the jailed workload may:

- Follow malicious instructions introduced through prompt injection or poisoned input.
- Invoke arbitrary shell commands and create arbitrary child processes.
- Execute arbitrary scripts, downloaded binaries, generated code, or dynamically linked applications.
- Attempt to read host files, credentials, configuration, mounted volumes, shell history, source code, and secrets.
- Attempt to bypass application-level tool restrictions using direct syscalls, language libraries, alternate CLIs, or custom networking code.
- Attempt direct DNS, private-network scanning, cloud metadata requests, direct-IP exfiltration, and network tunneling.
- Attempt resource exhaustion through CPU, memory, process creation, storage, or outbound connections.

### 3.2 Trusted computing base

The initial trusted computing base is deliberately small but non-trivial:

- Linux kernel, including Landlock, namespaces, capability checks, and networking stack.
- The host runtime configuration.
- Compound privileged setup component (`compoundd`) and its signed binaries.
- The trusted TCP gateway and its policy implementation.
- Policy source, policy signature or image digest, and audit sink.
- Any explicitly permitted executable, dependency, mount, secret, network destination, and external service.

### 3.3 Out of scope / residual risks

- Kernel vulnerabilities, container escapes, and gateway vulnerabilities can defeat the boundary.
- A writable permitted directory may be deliberately damaged or destroyed by the jailed process.
- An approved network destination can itself be an exfiltration channel.
- A process with permission to send arbitrary content to GitHub, Slack, a package registry, or another approved service can exfiltrate data to that service.
- Network destination policy does not determine whether a permitted API action is business-safe.

These residual risks motivate separate semantic brokers and approval workflows for high-impact actions such as production deployment, release publication, merge-to-main, public artifact upload, payment, or external communications.

## 4. Security model

### 4.1 Ambient authority versus explicit capabilities

Application-level agent tools control **explicit authority**: for example, whether an application exposes `read_file`, `git_commit`, or `send_message` functions. They do not inherently control **ambient authority**: whatever the underlying Unix process can access through files, sockets, credentials, inherited file descriptors, environment variables, or subprocesses.

Compound reduces ambient authority at the operating-system level.

A process granted only `/workspace` write access and network access only to approved GitHub hosts cannot read `~/.ssh/id_ed25519`, inspect a host browser profile, call arbitrary Internet services, or connect to cloud metadata endpoints—even when it runs arbitrary code.

### 4.2 Process-tree inheritance

The jail is applied before the target application executes. The target and every child created with `fork`, `clone`, `posix_spawn`, or `execve` inherit the relevant confinement:

- Landlock restrictions remain effective through descendant execution.
- The agent process tree stays in its assigned network namespace.
- Capabilities are dropped and `no_new_privs` is set before the workload starts.
- Seccomp, cgroup, environment, and file-descriptor controls are inherited as applicable.

The fundamental invariant is:

```text
If a process was launched by the jailed workload, it has no more filesystem
or network authority than the root jailed process.
```

## 5. High-level architecture

```text
                         ┌─────────────────────────────────────┐
                         │ Trusted host runtime                 │
                         │                                     │
                         │  compoundd: privileged setup service │
                         │  - creates namespaces/veth          │
                         │  - installs routing/firewall rules  │
                         │  - launches gateway                  │
                         └────────────────┬────────────────────┘
                                          │
                         ┌────────────────▼────────────────────┐
                         │ Trusted Compound TCP gateway        │
                         │ - transparent TCP interception       │
                         │ - domain/IP policy evaluation        │
                         │ - controlled DNS resolution          │
                         │ - connection/rate/upload controls    │
                         │ - audit events                       │
                         └────────────────┬────────────────────┘
                                          │
                                    Approved Internet
                                          ▲
                                          │
                       only permitted veth / gateway route
                                          │
 ┌────────────────────────────────────────┴────────────────────────────────────┐
 │ Jailed process network namespace                                           │
 │                                                                              │
 │  agent → shell → gh / git / npm / src / Python / generated binary          │
 │                                                                              │
 │  Landlock: path-level file I/O restrictions                                 │
 │  Network: direct TCP blocked/redirected; DNS blocked; UDP blocked           │
 │  Privilege: no CAP_NET_ADMIN; no new privileges                             │
 └──────────────────────────────────────────────────────────────────────────────┘
```

The diagram’s boundary is not a library linked into the agent and not a convention enforced by shell variables. It is a combination of kernel namespaces, routing/firewall controls, and a trusted gateway outside the jailed process’s authority.

## 6. Landlock filesystem enforcement

### 6.1 Why Landlock

Landlock is a Linux security mechanism that enables a process to reduce its own ambient rights. It is well suited to Compound because it can enforce filesystem access controls without requiring the target agent to be modified, and because its restrictions apply to the process after `exec` and to descendants.

Landlock is an additional layer, not a substitute for a minimal container filesystem. Compound uses both:

- A minimal immutable image/root filesystem limits what can physically appear in the process view.
- Landlock expresses what the jailed process may do with the paths it can see.

### 6.2 Policy semantics

A policy grants explicit rights to file hierarchies. The policy surface should expose the user’s intent, rather than raw kernel constants:

| Intent | Typical underlying rights |
|---|---|
| Read a file | Read file content and metadata as needed |
| List a directory | Read directory entries |
| Write a file | Write file, append, truncate |
| Create output | Make regular file / directory |
| Delete or rename | Remove and rename file/directory |
| Execute | Execute a binary or script |
| Create sockets/devices | Denied by default; rarely granted |

Example policy:

```yaml
filesystem:
  default: deny
  paths:
    - path: /workspace
      access: [read, write, create, delete, rename]

    - path: /inputs
      access: [read, list]

    - path: /outputs
      access: [read, write, create, delete, rename]

    - path: /usr
      access: [read, execute]

    - path: /lib
      access: [read, execute]

    - path: /lib64
      access: [read, execute]

    - path: /tmp
      access: [read, write, create, delete, rename]
```

Compound compiles these declarations into Landlock rules that grant only the needed access bits. It should use the newest supported Landlock ABI while producing a clear compatibility report for older kernels.

### 6.3 Required runtime allowances

A policy cannot simply grant execution to `/app` and deny everything else. Dynamically linked executables commonly need access to:

- The executable itself.
- The ELF interpreter/dynamic loader.
- Shared libraries.
- Locale, certificate, resolver, and runtime data where applicable.
- Language runtime files and package metadata.

Compound should provide image-aware policy generation and predefined profiles, such as `node-runtime`, `python-runtime`, `go-static`, and `minimal-shell`. The generated plan must be shown to users before use.

### 6.4 File-system hardening outside Landlock

The launcher also:

- Uses a read-only base image/root filesystem where practical.
- Provides dedicated writable mounts for `/workspace`, `/outputs`, and `/tmp`.
- Avoids mounting the host home directory, SSH directory, cloud credentials, browser profile, Docker socket, Kubernetes service-account token, or host system paths.
- Closes inherited file descriptors except a small documented allowlist.
- Sanitizes environment variables that alter code loading or execution, including `LD_PRELOAD`, `LD_LIBRARY_PATH`, `PYTHONPATH`, `NODE_OPTIONS`, shell startup behavior, and package-manager configuration.
- Sets `PR_SET_NO_NEW_PRIVS` before executing the target.
- Drops Linux capabilities; the workload must not retain `CAP_NET_ADMIN`, `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, or similar escape-relevant privileges.

### 6.5 Fail-closed behavior

Supplying a filesystem policy means filesystem enforcement is required. Compound refuses to run if the kernel lacks the required Landlock ABI or a declared filesystem right cannot be represented safely. It must never silently run an unrestricted process while reporting a policy as active.

## 7. Mandatory network egress enforcement

### 7.1 Design requirement

The network design must enforce this invariant:

> No process in the jail can transmit traffic to an external destination unless the traffic first traverses the trusted Compound gateway and is allowed by policy.

Compound has exactly one network enforcement model: outbound TCP from the jailed namespace is forced through the trusted gateway. Application-controlled configuration is not a security boundary.

### 7.2 Network namespace design

The target runs in a dedicated network namespace created and configured by `compoundd` or an orchestrator integration. The jailed UID has no `CAP_NET_ADMIN` and cannot alter routes, interfaces, nftables/iptables rules, or policy routing.

The namespace is configured with:

- No direct default route to the Internet.
- No route to host interfaces, local networks, or other workload namespaces.
- Explicit denial of loopback abuse except for specifically provisioned local services.
- No access to cloud metadata ranges, including link-local addresses.
- No direct DNS resolver path.
- No raw socket privileges.
- UDP denied by default.
- TCP either blocked or transparently intercepted and sent to the gateway.

A trusted parent namespace owns the veth configuration, routing table, firewall rules, and gateway path. The agent cannot modify any of those elements.

### 7.3 Transparent TCP gateway

The gateway is a trusted connection mediator. Network rules intercept every outbound TCP connection from the jailed namespace and cause it to pass through the gateway.

The gateway receives or reconstructs the original destination, then:

1. Identifies the jail and immutable policy digest.
2. Determines the requested destination IP and port.
3. Associates the destination with a permitted domain policy, using gateway-controlled resolution and protocol identity checks.
4. Rejects private, loopback, link-local, multicast, carrier-grade NAT, and configured internal network ranges.
5. Applies per-jail destination, connection-count, rate, timeout, and upload-volume controls.
6. Opens the upstream connection only if allowed.
7. Emits an allow or deny audit record.

The gateway must be outside the jailed process’s privilege domain. A compromised agent must not be able to edit its policy, flush its routing rules, reconfigure its interface, or signal its enforcement process.

### 7.4 TCP interception implementation

The recommended Linux implementation uses a privileged setup component to create a veth-connected jailed namespace and install nftables policy-routing/interception rules. The exact mechanics may use `TPROXY`, packet marks, a local policy route, and transparent sockets, preserving enough original-destination metadata for the gateway to make a decision.

Implementation details are intentionally abstracted behind `compoundd`; users declare a network policy, not packet-filter rules. A reference implementation should nevertheless make its effective routes, nftables configuration, and gateway listener topology inspectable for debugging and security review.

### 7.5 DNS enforcement

DNS is part of egress enforcement, not a convenience feature.

The jailed namespace has no general access to UDP/TCP port 53, DNS-over-TLS, or DNS-over-HTTPS. The gateway performs resolution for authorized domain requests using trusted resolvers and records the result associated with the policy decision.

The gateway must:

- Resolve only hosts that match an allow rule.
- Validate the returned addresses against prohibited address ranges.
- Maintain bounded, auditable resolution caches.
- Revalidate redirect destinations when the protocol permits redirects.
- Reject direct-IP requests unless an explicit CIDR/IP policy grant exists.

### 7.6 Domain identity and TLS

A hostname allowlist is a user-friendly policy abstraction, but the gateway must be precise about what it can validate.

For ordinary TLS-over-TCP traffic, the gateway can compare the gateway-resolved destination and a visible TLS Server Name Indication (SNI) value. It must deny connections when the hostname is missing, mismatched, or does not match an approved domain rule.

TLS Encrypted Client Hello can hide the hostname metadata that a transparent gateway would otherwise inspect. Therefore strict policies should be explicit:

```yaml
network:
  encrypted_hostname_unverifiable: deny
```

If a workload requires policy by HTTP path, method, header, or body, that is a separate, stronger mode: a deliberately configured TLS-terminating application gateway. It is not required for v1 and should be opt-in because it changes the trust model and can break certificate-pinning workflows.

### 7.7 UDP, QUIC, and unsupported protocols

V1 denies UDP by default. This deliberately blocks QUIC/HTTP/3, arbitrary UDP tunneling, direct DNS, many peer-to-peer protocols, and custom datagram transports.

The policy outcome is simple:

- TCP with verifiable approved destination: allowed through the transparent gateway.
- TCP with unverified or disallowed destination: denied.
- UDP: denied unless a future protocol-specific gateway is configured.
- Raw sockets, ICMP, multicast, and packet sockets: denied.

Safe failure is preferable to claiming egress enforcement while leaving alternate transports open.

## 8. Policy language

Compound separates filesystem and TCP egress policy into source files and generated lock files:

- `fs.compound.yaml`: path grants enforced through Landlock.
- `tcp.compound.yaml`: outbound TCP destinations enforced through the transparent gateway.
- `fs-lock.compound.yaml`: generated filesystem policy after includes are resolved and validated.
- `tcp-lock.compound.yaml`: generated TCP policy after includes are resolved and validated.

The split keeps the policy API aligned with the two enforcement planes. A workload may use filesystem-only enforcement during early local development, but any configured TCP policy uses the gateway model described above.

### 8.1 Filesystem policy

Example `fs.compound.yaml`:

```yaml
version: 1

metadata:
  name: github-coding-agent-fs

include:
  - path: ./policies/proc-minimal.fs.compound.yaml
    digest: sha256:...

policy:
  default: deny

  paths:
    - path: /workspace
      access: [read, list, write, create, delete, rename]

    - path: /inputs
      access: [read, list]

    - path: /outputs
      access: [read, list, write, create, delete, rename]

    - path: /usr
      access: [read, list, execute]

    - path: /lib
      access: [read, list, execute]

    - path: /lib64
      access: [read, list, execute]

  inherited_file_descriptors: deny
```

Supported v1 access values are `read`, `list`, `write`, `create`, `delete`, `rename`, and `execute`. Compound compiles these declarations into Landlock rules that grant only the needed access bits. Unsupported kernel features, invalid policy, or unrepresentable grants fail closed.

Filesystem policies may include reusable fragments. For example, a shared `proc-minimal.fs.compound.yaml` can contain the long, conservative list of `/proc` paths needed by ordinary Linux tools. `compound fs lock` resolves includes, verifies pinned digests, and emits one coalesced policy:

```bash
compound fs lock
```

By default, this reads `fs.compound.yaml` and writes `fs-lock.compound.yaml`. The paths are configurable:

```bash
compound fs lock \
  --policy ./fs.compound.yaml \
  --output ./fs-lock.compound.yaml
```

Use `--check` to perform the same validation and include resolution without writing the lock file.

The lock file is the preferred deployment artifact because it records the exact path policy that was reviewed and enforced.

### 8.2 TCP policy

Example `tcp.compound.yaml`:

```yaml
version: 1

metadata:
  name: github-coding-agent-tcp

include:
  - path: ./policies/github-npm.tcp.compound.yaml
    digest: sha256:...

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
    - 172.16.0.0/12
    - 192.168.0.0/16
    - ::1/128
    - fc00::/7
    - fe80::/10

  allow:
    - host: api.github.com
      ports: [443]
      protocol: tls
      limits:
        max_connections: 20
        max_upload_bytes: 10MiB
```

Reusable TCP fragments can describe common destination sets such as GitHub, npm, package registries, artifact stores, or approved internal services. `compound tcp lock` resolves includes, verifies pinned digests, validates rule semantics, and emits one coalesced policy:

```bash
compound tcp lock
```

By default, this reads `tcp.compound.yaml` and writes `tcp-lock.compound.yaml`. The paths are configurable:

```bash
compound tcp lock \
  --policy ./tcp.compound.yaml \
  --output ./tcp-lock.compound.yaml
```

Supplying a TCP policy or lock file means gateway enforcement is required. Compound refuses to run the workload if it cannot create the gateway path or deny direct DNS, UDP, raw sockets, and direct outbound TCP.

### 8.3 Policy validation

`compound fs lock` and `compound tcp lock` perform static validation, then write lock files only if validation succeeds:

```bash
compound fs lock --policy fs.compound.yaml --root / --check
compound tcp lock --policy tcp.compound.yaml --check
```

Validation reports:

- Kernel Landlock feature and ABI compatibility.
- Paths referenced by filesystem policy that do not exist under the target root filesystem.
- Runtime dependencies that will likely fail due to missing read/execute grants.
- Overly broad writable/executable directories.
- Include digests that do not match their referenced files.
- Overlapping or ambiguous TCP rules.
- Domain entries that resolve to prohibited IP ranges.
- Runtime requirements that need privileged `compoundd` or orchestrator support.

`compound fs explain` and `compound tcp explain` report the compiled kernel-level plan from lock files in human-readable form.

## 9. V1 command API

The v1 CLI surface is deliberately small:

```bash
compound exec [OPTIONS] -- <command...>
compound fs lock [--policy fs.compound.yaml] [--output fs-lock.compound.yaml] [--root PATH] [--check]
compound fs explain [--policy fs-lock.compound.yaml]
compound tcp lock [--policy tcp.compound.yaml] [--output tcp-lock.compound.yaml] [--check]
compound tcp explain [--policy tcp-lock.compound.yaml]
compoundd
```

`compound exec` is the core runtime primitive:

```bash
compound exec \
  --fs-lock fs-lock.compound.yaml \
  --tcp tcp-lock.compound.yaml \
  --workdir /workspace \
  --uid 3000 \
  --gid 3000 \
  -- npm test
```

`--fs-lock` defaults to `fs-lock.compound.yaml`. `--tcp` defaults to `tcp-lock.compound.yaml` when that file exists; if no TCP policy is supplied or found, Compound should run with no external network by default.

`compound fs lock` defaults to `--policy fs.compound.yaml` and `--output fs-lock.compound.yaml`. `compound tcp lock` defaults to `--policy tcp.compound.yaml` and `--output tcp-lock.compound.yaml`. Both commands validate policy, resolve includes, verify pinned digests, and write the exact policy artifact that should be used for execution. If validation fails, they do not create or update the lock file.

OCI, Docker, CI, Kubernetes, and the higher-level `compound run` image workflow are intentionally deferred to the v1.1 proposal.

## 10. Runtime deployment model

### 10.1 Privilege separation

A production deployment should use two components:

- `compoundd`: a small privileged host/node/runtime service that creates network namespaces, interfaces, routes, and transparent interception rules.
- `compound`: an unprivileged launcher that validates policy, sets `no_new_privileges`, applies Landlock, sanitizes the execution environment, and executes the target.

The jailed target never receives host root, `CAP_NET_ADMIN`, container-runtime sockets, or a management API capable of changing its own boundary.

## 11. Gateway policy and auditing

### 11.1 Audit schema

Each event includes a policy digest and workload identity:

```json
{
  "timestamp": "2026-09-26T20:00:00Z",
  "event_type": "network_deny",
  "jail_id": "jail_01J...",
  "policy_digest": "sha256:...",
  "pid": 842,
  "executable": "/usr/local/bin/gh",
  "original_destination": "169.254.169.254:80",
  "requested_hostname": null,
  "decision": "deny",
  "reason": "destination_matches_prohibited_link_local_range"
}
```

Events should include:

- Process start and executable path.
- Effective policy and policy digest.
- Landlock setup success/failure and ABI version.
- Filesystem denials, with enough path detail for debugging while respecting sensitive-data policy.
- DNS lookup decisions and returned address sets.
- TCP connection allows/denials, domain/SNI state, destination IP/port, byte counts, and duration.
- Resource-limit events and process-tree termination.

### 11.2 Audit integrity

The audit sink must be outside the jail’s writable filesystem and network authority. The jailed process may be able to generate noisy events, but must not be able to delete, rewrite, or forge a privileged event stream.

## 12. Defense in depth

Landlock and the network namespace/gateway are the core controls. The following defenses improve resilience:

- **Seccomp:** remove unnecessary syscall surface, especially namespace creation, mount operations, BPF, ptrace, keyring, raw socket, and privileged device operations where compatible.
- **cgroups v2:** enforce CPU, memory, PID, I/O, and execution-time quotas.
- **Read-only root filesystem:** reduce persistence and image tampering.
- **Capability dropping:** deny privilege escalation paths.
- **User namespaces/rootless mode:** reduce impact where compatible with deployment needs.
- **Image signing and SBOM verification:** ensure Compound, its policy, gateway, and runtime dependencies are trusted.
- **Secret broker:** provide narrow, short-lived credentials only for permitted use cases; do not mount broad host credentials.

No defense-in-depth layer substitutes for the mandatory Landlock and gateway controls. Seccomp alone or a Docker non-root user alone is not sufficient.

## 13. Test strategy

### 13.1 Filesystem adversarial tests

- Read `/root`, `/home`, SSH keys, cloud credentials, browser profiles, and host mounts.
- Write outside approved workspace/output/temp directories.
- Create symlinks and attempt traversal outside approved paths.
- Use rename, hardlink, `/proc`, inherited file descriptors, and Unix sockets to escape intended policy.
- Execute files from writable locations where execution is denied.
- Spawn descendants and verify they retain Landlock restrictions.

### 13.2 Network adversarial tests

- Unset environment variables and attempt raw direct TCP connects.
- Use `curl`, Python, Node, Go, Rust, netcat, custom static binaries, and direct system-call implementations.
- Attempt direct-IP connections to public hosts.
- Attempt private-network and cloud-metadata access.
- Attempt UDP/53, TCP/53, DoH, DoT, UDP/443, QUIC, ICMP, raw sockets, and multicast.
- Attempt domain rebinding and IP changes after DNS resolution.
- Attempt hostname/SNI mismatch.
- Attempt connection flooding, oversized uploads, and long-lived exfiltration sessions.
- Verify that every allowed connection is visible in the trusted audit stream.

### 13.3 Required test property

Tests should demonstrate not only that allowed workflows work, but that alternate implementations of the same action fail to bypass policy:

```text
Allowed:  gh pr list → approved GitHub destination via gateway
Denied:   custom Python socket → arbitrary Internet address
Denied:   curl direct IP → public IP not explicitly permitted
Denied:   UDP/443 → QUIC/HTTP3 bypass attempt
Denied:   DNS to arbitrary resolver → direct DNS path unavailable
Denied:   read ~/.ssh/id_ed25519 → Landlock denial
```

## 14. Delivery roadmap

### Phase 0: Specification and reference policy

- Define `fs.compound.yaml`, `tcp.compound.yaml`, and the threat-model document.
- Build `compound fs lock`, `compound fs explain`, `compound tcp lock`, and `compound tcp explain`.
- Publish secure filesystem and TCP policy fragments for coding agents, data analysts, and CI jobs.

### Phase 1: Landlock-first local launcher

- `compound exec --fs-lock fs-lock.compound.yaml -- command`.
- Landlock rules, UID/GID setup, no-new-privileges, capability dropping, environment/file-descriptor hygiene.
- Structured local audit log.
- Fail closed if Landlock is absent or too old for required policy.

### Phase 2: Mandatory transparent TCP egress

- `compound exec --fs-lock fs-lock.compound.yaml --tcp tcp-lock.compound.yaml -- command`.
- `compoundd` setup service for namespace/veth/nftables topology.
- Per-jail transparent TCP gateway.
- Gateway-controlled DNS and domain allowlist evaluation.
- Strict TCP-only mode; UDP and encrypted-hostname-unverifiable traffic denied.
- Per-destination connection, byte, rate, and timeout controls.

### Phase 3: Higher-level capability controls

- Brokered secrets and service-specific credentials.
- Semantic approval gates for GitHub write operations, deployments, artifact publication, and communication tools.
- Optional TLS-terminating policy mode for regulated environments that need method/path/body policy.

OCI/Docker, CI, Kubernetes, and `compound run` are covered by the separate v1.1 proposal.

## 15. Success criteria

The v1 product is successful if it can truthfully make this claim:

> Given a supported Linux host and a policy requiring Landlock and mandatory transparent TCP egress, an arbitrary agent process and all child processes can read, write, execute, and connect only within the explicit policy grants. They cannot access ambient host files or establish a direct network connection outside the trusted gateway, even if they ignore application tools, modify environment variables, execute custom code, or invoke arbitrary approved CLIs.

The product should optimize for a secure default that remains useful in real development workflows: code agents can edit an assigned workspace, run normal build tools, and reach a small allowlisted set of development services, but cannot silently access user credentials, scan the local network, query cloud metadata, or exfiltrate data to arbitrary destinations.

## 16. Open design questions

- What minimum Linux kernel and Landlock ABI version should v1 support?
- Should `compoundd` run as a host daemon, rootless helper, or both?
- What transparent interception mechanism provides the best combination of correctness, observability, and operational simplicity?
- How should the gateway handle certificate validation, SNI absence, ECH, and emerging encrypted transports under strict policies?
- How should policy updates be authorized and bound to image digests?
- What is the least surprising developer experience for denied runtime dependencies and egress attempts?
- Which service profiles should ship first: GitHub, package registries, cloud artifact stores, internal source-control systems, or CI providers?

## 17. Conclusion

Compound addresses agentic-process safety as a systems-security problem rather than a behavioral-prompting problem. Models, tools, and CLIs will sometimes be confused, compromised, or manipulated. The robust answer is to constrain the underlying process so it cannot exceed a deliberately granted capability envelope.

Landlock provides a practical Linux mechanism for granular file I/O confinement. A dedicated network namespace plus mandatory transparent TCP gateway provides an enforceable, CLI-agnostic egress boundary. Combined with immutable policy, privilege separation, auditability, and safe failure for unsupported transports, these controls form a portable process jail suitable for containerized agent deployments and broader untrusted-workload isolation.
