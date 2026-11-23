# Changelog

## Unreleased

### Fixed
- **`scripts/setup_agent.sh` failed on public API endpoints.** It sent each step right after the
  previous one, and a load-balanced endpoint could check the next step on a node that had not yet
  applied the last transaction ("Permission Query Exception" when linking the `gw` permission). Each
  step now waits until the previous one is visible. Found while deploying on Jungle4.
- **A paid purchase could be reported to the agent as an error.** After paying, the gateway waits
  to see its `settle` transaction in a block. One failed read during that wait (a timeout, a rate
  limit, or a node that did not have the block yet) raised an exception: the agent got "Error
  executing tool" although it had paid, and the journal stayed at `paying`. Failed reads are now
  retried until the deadline, and a settlement counts as recorded only once it is seen in a block;
  otherwise the request is left as `paid_not_recorded` and the reconciler finishes it. Found during
  a demo rehearsal on Jungle4; three regression tests cover it.

### Added
- **Live demo on the public Jungle4 testnet** (contract `spendguard11`), with notes on deploying
  there: accounts and CPU through PowerUp, and the RAM the contract needs.

## 0.1.1 — 2026-10-13

### Fixed
- **Watcher crash after paying an approved request.** A watcher that had not served a direct
  purchase since it started failed right after the payment (timing data was not set up). The
  payment went through, but its settlement was left to the reconciler and the vendor's content was
  lost. Found in a live test; a regression test covers it.
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
