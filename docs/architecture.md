# Architecture

## Roles and keys

| Role | Holds | Can do |
|---|---|---|
| Agent (LLM) | nothing | call the gateway's MCP tools |
| Gateway | the agent's `gw` key (Antelope) and a testnet payer wallet | `authorize`, `settle`, `fail`, `expire`; sign x402 payments |
| Approver | own account key (e.g. in Anchor) | `approve`, `reject` for agents whose policy names it |
| Admin | own account key | agents, policies, vendors, revoke / reinstate |
| Auditor | own account key, only for attestations | read everything; publish `logaudit` |
| Contract owner | multi-signature authority (recommended) | upgrade code, change `init` settings |

## Payment flow (`paid_fetch`)

1. Unpaid request → HTTP 402 with the vendor's requirements.
2. Local checks: price ≤ the agent's `max_price`; payee on the on-chain whitelist.
3. `authorize` with a fresh nonce and a 15 s transaction expiry. The gateway waits until the
   transaction is in a block and reads the request **by nonce** from the table; the API node's
   immediate answer is only advisory.
4. If PENDING (above the approval threshold): return "pending approval". The watcher pays after the
   approval has become irreversible.
5. If AUTHORIZED: build the x402 payment for the single authorized requirement only (the SDK's
   automatic mode is not used), with the SDK's own cap set from the on-chain per-payment limit.
6. Verify the transfer in the receipt at an explicit block (payer, payee, exact amount); then `settle`.
   If the vendor does not deliver, `fail` releases the budget.
7. Refused by the facilitator: retry up to 3 attempts, each only after checking that the previous
   signed authorization was not executed (`AuthorizationUsed` event). Every attempt is journaled.

## Recovery (watcher)

The gateway keeps a local journal (SQLite) of every request and the phase it reached. The watcher,
one per agent, works through it every few seconds:

- **Approved requests**: the watcher first claims the request in the journal
  (`pending_approval` → `authorized`, one atomic update). Only the process whose claim succeeded pays.
- **Interrupted payments** (`authorized`, `paying`, `payment_unknown`) are left alone until the x402
  payment window has passed, so a signed payment that may still settle is never declared failed early.
  After that, the watcher looks for the payment on the public chain by the authorization nonce of each
  attempt. A verified transfer is recorded with `settle`. If no transfer is found, `fail` releases the
  budget. If no payment was started, the public chain is not searched.
- **Paid but not recorded**: `settle` is retried. If the contract refuses it permanently (e.g. the
  request expired meanwhile), the request is marked `needs_attention` for a person to resolve.
- **Unapproved requests** past the approval window are closed with `expire`.

## Audit

- **Check A:** every SETTLED record → its public transaction succeeded and transferred exactly the
  authorized amount from the payer to the whitelisted payee, after the request was created.
- **Check B:** every transfer out of the payer wallet → a SETTLED record with that transaction.
- A Merkle root over the verified records can be published with `logaudit`; anyone can recompute it
  from the contract's tables.
