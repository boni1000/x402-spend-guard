# Security

**This is a research prototype intended for testnets.** Do not use it with real funds.

## Reporting a vulnerability

Please report security issues privately to the maintainers through GitHub's
"Report a vulnerability" (Security tab) rather than in a public issue.

## What the design protects against, and what it does not

- **A misled, faulty or compromised agent** cannot exceed its limits, pay a vendor that is not
  whitelisted, bypass approval or keep paying after revocation: these are enforced by the contract.
- **The gateway's chain key** can only call `authorize`, `requestsig`, `settle`, `fail` and `expire`
  (protocol-level `linkauth`); it cannot move tokens, approve payments or change rules.
- **A compromised gateway machine** depends on who signs payments (`PAYER_MODE`):
  - `key` (default): the machine holds the payer wallet and can pay *around* the contract. The
    auditor's reverse check detects such payments afterwards; it does not prevent them. Keep only a
    small float in the payer wallet.
  - `mpc` (experimental): the machine holds no payer key. agentgov builds every authorization from
    its own tables, and the MPC network signs only what agentgov asks for, so the gateway can get a
    signature only for an authorized request, for the whitelisted vendor and amount. It cannot free
    the budget of a signed request either: `fail` and `expire` refuse it.
- **Contract upgrades**: put the contract account under a multi-signature authority whose keys are held
  by different people on different devices.

### MPC mode moves the trust

With `PAYER_MODE=mpc` the payer addresses belong to the MPC network's keys for (agentgov, agent).
Whatever can make that network sign for agentgov controls everything those addresses hold:

- **The agentgov account.** The MPC contract accepts a request with agentgov's authority, and that
  authority is met by agentgov's *account keys* as well as by its code. Whoever holds those keys can
  have anything signed for any agent, bypassing every limit. Set agentgov's `active` permission to
  `agentgov@eosio.code` plus a multi-signature authority, never a single key, and keep `owner` under a
  multi-signature authority too. Upgrading the contract code is the same power, so the same multi-signature applies.
- **The MPC network.** A threshold of its operators acting together can sign anything for any payer
  address. Their independence is what protects the funds. On Alcor's testnet all nodes are run by
  Alcor (5 nodes, threshold 3); independent operators are planned for mainnet. Keep only a float in
  the payer addresses.
- **The attester** (`setmpc`) is the only account that can release the budget of a signed request,
  and only after its `validBefore` has passed. One that lies about an executed authorization lets the
  agent spend that amount again on the same day. Use an account that is not an agent and not run on
  the gateway machine. The auditor does not yet check the attester's reports against USDC's
  `authorizationState`.
- **Signatures are public** once the MPC network answers. Anyone can submit one to USDC before its
  `validBefore`, but it pays only the whitelisted vendor and only the authorized amount. The budget
  already counts it as spent. Keep `sig_ttl_sec` short (about 120 s; the facilitator needs at least
  6 s left, and signing takes a few seconds).

MPC mode is tested against a mock of Alcor's announced interface (`tests/chain/mockmpc`), not yet
against their network, whose interface is not final.

See [docs/threat-model.md](docs/threat-model.md) for the full analysis.

## Handling keys

- Never commit `keys.env`, wallet files or password files (they are in `.gitignore`).
- The gateway signs through `keosd`; Antelope private keys never enter the Python process.
- The `keosd` wallet password is passed to `cleos` on standard input, never as an argument. Keep the
  password file readable only by the gateway's user (`chmod 600`).
- Generate keys on the machine that uses them; do not copy them between machines.
- In MPC mode there is no payer key: leave `PAYER_PRIVATE_KEY` unset.
