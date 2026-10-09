# Security Policy

## Reporting a vulnerability

Use GitHub **Private vulnerability reporting** (Security → Report a vulnerability)
— do not open public issues for security reports.

## Scope

- `cmd/`, `internal/` (config generation, deploy, registry), `worker/` (subscription server), `deploy/macos/` (killswitch daemon).
- Out of scope: the user's own registry data files (kept outside this repo), third-party client applications.

## Design invariants

- Fail-closed: the last hop of a failover chain is `block`, never `direct`.
- DNS resolvers of generated configs are DoH-by-IP; plain-IP forwarders are rejected by validation.
- No secrets belong in this repository: registry data (hosts, UUIDs, tokens) lives in the user's private storage.
