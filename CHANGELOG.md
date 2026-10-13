# Changelog

## 0.1.1 — 2026-10-13

### Fixed
- **Double payment of an approved request.** If two processes handled the same journal (e.g. the
  watcher and an MCP server), both could pay an approved request. A request is now claimed atomically
  in the journal before it is paid, and the MCP server no longer runs approvals and reconciliation by
  default (`SPEND_GUARD_BACKGROUND=1` enables them when no watcher runs).
- **Wallet password on the command line.** `keosd` is now unlocked with the password on standard
  input, so it no longer appears in the process list.
- **Reconciler.**
  - It looks for an interrupted payment by the authorization nonce of each attempt (exact).
    Matching by amount and payee is now only a fallback for older journals.
  - It no longer scans the public chain from block 0 when no payment was started.
  - It stops retrying a settlement that the contract refuses permanently. The request is marked
    `needs_attention` instead, unless the chain shows it was already recorded with the same transaction.
- Explorer links follow the configured network instead of an environment variable read at import.
- Request nonces include a random part, so two processes acting for one agent cannot collide.

### Added
- Tests for the atomic claim, concurrent watchers, and the reconciler. CI (ruff + pytest).
- Package metadata: project URLs, keywords and classifiers. `mcp` is pinned to 2.x.

## 0.1.0 — 2026-10-09

First release: `agentgov` contract, gateway, MCP server, watcher, keyless auditor with on-chain
attestations, example vendor and agent.
