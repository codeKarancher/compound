# Network Containment Observability Limits

Compound can aim to make denied network egress fail safely and consistently, but
it cannot guarantee that an arbitrary inner process is unable to infer that it is
running inside a constrained environment.

## Why Perfect Non-Detection Is Not Achievable

An adversarial process can observe many signals that are outside the TCP gateway
policy decision itself:

- network interface names, addresses, routes, and namespace-specific `/proc`
  views
- DNS behavior, resolver configuration, and missing UDP behavior
- TCP error shape, timeout duration, reset behavior, and ICMP behavior
- TTLs, MSS/MTU, ephemeral port behavior, and packet timing
- absence of expected LAN, multicast, metadata, or loopback services
- differences between direct kernel denial, gateway denial, upstream denial, and
  ordinary Internet failure

Even if Compound normalizes one failure mode, such as returning a TCP reset for a
denied connection, the process can compare timing and behavior across many
destinations and protocols. It can also inspect its local environment unless
additional filesystem, procfs, mount, and syscall restrictions are applied.

## Practical Security Goal

The enforceable v0 goal should be:

> A denied network action must not transmit useful data outside the policy, and
> denial behavior should be boring, consistent, auditable, and difficult to use
> as a high-bandwidth oracle.

This is different from promising that the process cannot learn that it is
contained.

## Recommended Denial Semantics

Compound should still avoid obvious policy leaks where practical:

- Prefer a small set of normalized denial outcomes.
- Avoid returning policy-specific error strings to the inner process.
- Make hostname, CIDR, DNS, UDP, and raw-socket denials look as similar as the
  kernel allows.
- Bound denial latency so policy checks do not create a rich timing oracle.
- Record detailed denial reasons only in the trusted audit sink, not inside the
  jailed process.

For transparent TCP, useful options are:

- return `HTTP/1.1 503 Service Unavailable` for denied cleartext HTTP
  requests
- close the accepted transparent connection without forwarding payload
- inject a TCP reset where the kernel setup supports doing so consistently
- blackhole until a short fixed timeout for selected denial classes

Each option leaks something. The implementation should choose predictable,
operationally debuggable behavior rather than claim invisibility.

For TLS, HTTPS, and arbitrary TCP, Compound should not inject plaintext HTTP into
the stream. Without TLS termination, the best normalized response is a boring
transport-level failure such as close, reset, or a short timeout.

## Implications For Tests

Adversarial tests should verify:

- denied egress sends no payload to the upstream destination
- the inner process receives only normalized failure classes
- trusted audit logs retain the precise policy reason
- direct DNS, UDP, raw socket, private IP, and metadata attempts fail closed
- denial behavior does not vary by policy reason more than intentionally allowed

Tests should not assert that the process cannot detect containment. That claim is
too strong for a Linux namespace plus gateway architecture.
