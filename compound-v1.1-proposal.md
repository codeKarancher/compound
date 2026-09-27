# Compound v1.1: Container and Image Workflow Proposal

**Status:** Follow-on proposal  
**Depends on:** Compound v1 filesystem policy, TCP policy, `compound exec`, and `compoundd`  
**Scope:** Docker/OCI packaging, image metadata, CI integration, Kubernetes integration, and `compound run`

## 1. Goal

Compound v1.1 adds a higher-level image workflow on top of the v1 runtime primitives. The v1 product launches local commands with `compound exec`; v1.1 packages those same guarantees into repeatable container, CI, and Kubernetes workflows.

The central addition is:

```bash
compound run [OPTIONS] -- <command...>
```

`compound run` should be a convenience wrapper, not a second enforcement model. It prepares image/container runtime state, verifies policy artifacts, starts the gateway path through `compoundd`, and ultimately launches the workload through the same `compound exec` enforcement path used by v1.

## 2. Local Docker / Developer Mode

Example:

```bash
compound run \
  --fs-lock ./fs-lock.compound.yaml \
  --tcp ./tcp-lock.compound.yaml \
  --image my-agent:latest \
  --workspace "$PWD:/workspace:rw" \
  -- node /app/agent.js
```

`compound run` invokes a trusted local supervisor that:

- Creates the jailed namespace and veth topology.
- Starts the per-jail gateway.
- Mounts approved writable directories.
- Loads immutable filesystem and TCP policies.
- Starts the application through `compound exec`.
- Tears down all network state when the workload exits.

Defaults should mirror v1:

- `--fs-lock` defaults to `fs-lock.compound.yaml`.
- `--tcp` defaults to `tcp-lock.compound.yaml` when present.
- Missing TCP policy means no external network by default.

## 3. OCI and Docker Integration

### 3.1 Principle

A Dockerfile packages the binary and policy artifacts; it does not itself apply Landlock or build the final runtime network topology. Those controls must be applied immediately before the target process starts.

The canonical Docker integration uses a standard OCI entrypoint, preserving portability across Docker, Podman, containerd, Kubernetes, CI systems, and prebuilt images.

### 3.2 Standard Dockerfile Integration

```Dockerfile
FROM node:22-slim

WORKDIR /app

RUN useradd --uid 300 --create-home --shell /usr/sbin/nologin agent

COPY --chown=300:300 . /app
COPY --chown=root:root --chmod=0444 fs-lock.compound.yaml /etc/compound/fs-lock.compound.yaml
COPY --chown=root:root --chmod=0444 tcp-lock.compound.yaml /etc/compound/tcp-lock.compound.yaml
COPY --chmod=0755 compound /usr/local/bin/compound

USER 300:300

ENTRYPOINT ["/usr/local/bin/compound", "exec", "--fs-lock", "/etc/compound/fs-lock.compound.yaml", "--tcp", "/etc/compound/tcp-lock.compound.yaml", "--"]
CMD ["node", "server.js"]
```

Policy files must not be placed in `/tmp`; they should be immutable to the jailed UID, owned by root, and included in the signed image artifact.

### 3.3 OCI Annotations

The entrypoint can be complemented by OCI labels:

```Dockerfile
LABEL io.compound.enabled="true"
LABEL io.compound.fs-lock="/etc/compound/fs-lock.compound.yaml"
LABEL io.compound.tcp-lock="/etc/compound/tcp-lock.compound.yaml"
LABEL io.compound.policy-version="1"
```

A platform admission controller or `compound run` wrapper can require these annotations and verify that the entrypoint, image digest, and policy digests match an approved deployment configuration.

### 3.4 Optional Custom Dockerfile Instruction

A later BuildKit frontend may add syntax sugar:

```Dockerfile
# syntax=ghcr.io/compound/dockerfile-frontend:v1

COPY fs-lock.compound.yaml /etc/compound/fs-lock.compound.yaml
COPY tcp-lock.compound.yaml /etc/compound/tcp-lock.compound.yaml
COMPOUND --user=300 --fs-lock=/etc/compound/fs-lock.compound.yaml --tcp=/etc/compound/tcp-lock.compound.yaml
CMD ["node", "server.js"]
```

The custom `COMPOUND` instruction should compile to the same OCI labels and entrypoint contract. It must not be the only integration surface, because many production image builds do not use a custom Dockerfile frontend.

## 4. Kubernetes Mode

Recommended production architecture:

```text
Kubernetes admission controller / CNI / node agent
    ├── verifies image and policy digests
    ├── creates or assigns gateway-only egress path
    └── denies direct pod egress

Agent container
    ├── Compound entrypoint applies Landlock and process controls
    └── application runs unprivileged

Gateway sidecar or node-level gateway
    ├── evaluates domain policy
    ├── resolves permitted domains
    └── emits audit records
```

The network-enforcement component must remain outside the agent container’s effective privileges. A sidecar is acceptable only if the agent cannot alter its configuration, send it administrative commands, or acquire the credentials used to manage traffic rules.

## 5. Potential Future Application Gateway

The v1 transparent TCP gateway can enforce destination policy, but it cannot inspect or modify encrypted HTTPS request paths, headers, or bodies. A future v1.1+ mode may add an opt-in HTTP application gateway for use cases that need semantic request handling, such as injecting an `Authorization: Bearer ...` header for approved API origins.

For HTTPS, this would require deliberate TLS termination and re-origination by Compound. That changes the trust model, requires client trust configuration, can break certificate pinning, and must remain separate from the default transparent TCP gateway. Any such mode should be explicit in policy, auditable, and backed by a secret broker rather than storing bearer tokens directly in policy files.

## 6. Open Questions

- Should `compound run` manage Docker/Podman directly or operate through a lower-level OCI runtime interface?
- Which image metadata should be required before a platform admission controller accepts a workload?
- How should policy digests be bound to image digests and release signatures?
- Should Kubernetes use a node-level gateway, hardened sidecar, CNI integration, or a combination?
- What is the migration path from local `compound run` to CI and Kubernetes deployment?
- Should Compound offer an opt-in TLS-terminating HTTP gateway for semantic request policy and header/token injection, and how should clients trust its certificate authority?
