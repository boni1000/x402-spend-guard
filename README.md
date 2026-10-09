# x402-spend-guard

**Spending limits, human approval and a two-way audit for AI agents that pay with [x402](https://x402.org), enforced by an Antelope smart contract.**

AI agents can now pay for web resources inside an HTTP request (x402: HTTP 402 + a signed stablecoin
payment). Rules written into an agent's prompt do not stop a misled or faulty agent from overspending.
x402-spend-guard moves the rules out of the agent:

- an **Antelope smart contract** (`agentgov`) holds each agent's limits, a vendor whitelist, approvals,
  revocation and a record of every payment;
- a **gateway**, exposed to agents as an [MCP](https://modelcontextprotocol.io) server, asks the
  contract for authorization **before** each payment, pays **exactly** what was authorized, verifies the
  public transfer and records it;
- a **keyless auditor** checks every record against a real transfer and every transfer against a record.

The agent never holds a key. The gateway's key on the Antelope chain is restricted at protocol level
(`linkauth`) to four contract actions; it cannot move tokens, approve payments or change rules.

> **Status: research prototype, testnet only.** Tested end to end on a five-producer private Antelope
> network (Spring 1.2.2) with payments on the Base Sepolia testnet and local open-weight LLM agents.
> See [docs/results.md](docs/results.md). Do not use with real funds.

## How it works

```
LLM agent ──MCP (stdio)──► gateway ─1. quote (HTTP 402)──────────► vendor
 (no keys)                  │  ─2. agentgov::authorize ──────────► Antelope chain  (limits, whitelist,
                            │       wait until in a block                           approval, revocation)
                            │  ─3. pay exactly the authorized ───► public network  (x402 / USDC)
                            │       amount, verify the transfer
                            └  ─4. agentgov::settle (tx hash) ───► Antelope chain
approver / admin ── approve · reject · revoke (own wallet) ──────► Antelope chain
auditor (no keys) ── read records + transfers, publish logaudit ─► both chains
```

- **Per-payment and daily limits** and a **vendor whitelist** are checked by the contract.
- Payments **above a threshold wait for a human approval** and are paid only after that approval is
  irreversible.
- **Revocation** (kill switch) takes effect for the agent's next payment.
- A refused payment is **retried safely**: only after checking, by its ERC-3009 authorization nonce,
  that it was not executed after all.
- The **auditor** finds payments that bypassed the gateway, and can publish signed attestations
  (Merkle root of verified records) with `agentgov::logaudit`.

## Repository

| Path | Content |
|---|---|
| `contract/agentgov.cpp` | The Antelope contract (C++, CDT 4.1) |
| `spend_guard/gateway.py` | Gateway core: quote → authorize → pay → verify → settle / fail |
| `spend_guard/mcp_server.py` | MCP server over stdio: `paid_fetch`, `get_budget`, `payment_status` |
| `spend_guard/watcher.py` | Always-on: completes approved payments, expires stale requests, reconciles |
| `spend_guard/auditor.py` | Keyless two-way audit; `--anchor` publishes attestations |
| `spend_guard/spring.py` | Antelope client: HTTP reads, signing via `cleos` + `keosd` (keys never enter Python) |
| `spend_guard/payments.py` | x402 payer with explicit control; transfer verification on the public chain |
| `examples/vendor.py` | Example x402 vendor (FastAPI) with several price levels |
| `examples/agent_ollama.py` | Example agent: an Ollama model using the gateway over MCP |
| `scripts/setup_agent.sh` | Register an agent and give its gateway a scoped key |
| `scripts/propose_upgrade.sh` | Propose a contract upgrade through `eosio.msig` |
| `docs/` | Architecture, threat model, results, lessons learned |

## Requirements

- An Antelope chain with a reachable API node (tested with **Spring 1.2.2**; the contract uses action
  return values, `linkauth` and, for attestations, nothing beyond standard features).
- `cleos` and `keosd` on the gateway machine (the gateway signs through `keosd`).
- Python ≥ 3.10; Antelope CDT 4.1 to build the contract.
- For multi-signature control of the contract: a **current** `eosio.msig` (older versions execute
  approved proposals as deferred transactions, which Spring nodes no longer run).

## Quick start

1. **Build and deploy the contract** on an account you control (e.g. `agentgov`):
   ```bash
   ./contract/build.sh
   cleos -u $CHAIN_URL set contract agentgov contract agentgov.wasm agentgov.abi -p agentgov@active
   # admin, budget day (s), approval window (s), authorization validity (s)
   cleos -u $CHAIN_URL push action agentgov init '["myadmin",86400,600,300]' -p agentgov@active
   ```
2. **Whitelist a vendor** (its payee address on the public network):
   ```bash
   cleos -u $CHAIN_URL push action agentgov addvendor '["eip155:84532","0xVendorAddress","example vendor"]' -p myadmin@active
   ```
3. **Register an agent** and give the gateway a scoped key (create the key in a `keosd` wallet on the
   gateway machine first). Amounts are micro-USDC:
   ```bash
   CHAIN_URL=... CONTRACT=agentgov ADMIN=myadmin \
   ./scripts/setup_agent.sh agent1 EOS6...gatewaykey 2000000 3000000 1000000 myapprover
   ```
4. **Configure the gateway**: copy `gateway.env.example` → `gateway.env` and `keys.env.example` →
   `keys.env` (a **testnet** payer wallet; fund it with test USDC, e.g. from https://faucet.circle.com).
5. **Install** and run the tests:
   ```bash
   pip install -e ".[examples,test]"
   pytest
   ```
6. **Try it** with the example vendor and agent:
   ```bash
   VENDOR_ADDRESS=0xVendorAddress python examples/vendor.py &
   python examples/agent_ollama.py run --agent agent1 \
     --task "Buy the summary at http://localhost:8601/v1/summary?topic=soil (0.01 USDC) and tell me the key point."
   ```
7. **Use it from any MCP client**, e.g.:
   ```json
   { "mcpServers": { "spend-guard": {
       "command": "spend-guard-mcp",
       "env": { "SPEND_GUARD_ENV": "/path/gateway.env,/path/keys.env", "AGENT": "agent1" } } } }
   ```
8. **Run the watcher** (approvals, expiry, reconciliation) and, on another machine, **the auditor**:
   ```bash
   spend-guard-watcher
   spend-guard-audit --anchor --incremental     # with audit.env, see audit.env.example
   ```

## Contract actions

| Action | Signed by | Purpose |
|---|---|---|
| `init` | contract | admin, budget-day length, approval window, authorization validity |
| `regagent`, `setpolicy`, `addvendor`, `rmvendor` | admin | configuration |
| `revoke`, `reinstate` | admin | kill switch |
| `authorize` | agent's `gw` key | admit a payment (limits, whitelist, nonce); returns id and status |
| `approve`, `reject` | policy approver | decide on payments above the threshold |
| `settle`, `fail` | agent's `gw` key | record the public payment / release the budget |
| `expire` | anyone (gateway) | close requests whose validity has passed |
| `getbudget` | read-only | limits and remaining budget |
| `logaudit` | any account | publish an audit attestation signed with its own key |

## Security

Read [SECURITY.md](SECURITY.md) and [docs/threat-model.md](docs/threat-model.md). In short: the
contract bounds what the gateway's chain key can authorize, but the gateway machine also holds the
payer wallet — a compromised gateway can pay around the contract. The auditor's reverse check detects
this afterwards; it does not prevent it. Keep only a small float in the payer wallet.

## Lessons learned

Integrating a permissioned Antelope chain, x402 and local LLM agents surfaced several non-obvious
issues (advisory API responses, RAM-payer rules, deferred transactions in old `eosio.msig`, a hidden
default spending cap in the x402 SDK, stale public RPC reads). They are described in
[docs/lessons.md](docs/lessons.md).

## License

MIT — see [LICENSE](LICENSE).
