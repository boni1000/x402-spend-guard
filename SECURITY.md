# Security

**This is a research prototype intended for testnets.** Do not use it with real funds.

## Reporting a vulnerability

Please report security issues privately to the maintainers through GitHub's
"Report a vulnerability" (Security tab) rather than in a public issue.

## What the design protects against, and what it does not

- **A misled, faulty or compromised agent** cannot exceed its limits, pay a vendor that is not
  whitelisted, bypass approval or keep paying after revocation: these are enforced by the contract.
- **The gateway's chain key** can only call `authorize`, `settle`, `fail` and `expire` (protocol-level
  `linkauth`); it cannot move tokens, approve payments or change rules.
- **A compromised gateway machine** holds the payer wallet and can pay *around* the contract. The
  auditor's reverse check detects such payments afterwards; it does not prevent them. Keep only a small
  float in the payer wallet.
- **Contract upgrades**: put the contract account under a multi-signature authority whose keys are held
  by different people on different devices.

See [docs/threat-model.md](docs/threat-model.md) for the full analysis.

## Handling keys

- Never commit `keys.env`, wallet files or password files (they are in `.gitignore`).
- The gateway signs through `keosd`; Antelope private keys never enter the Python process.
- The `keosd` wallet password is passed to `cleos` on standard input, never as an argument. Keep the
  password file readable only by the gateway's user (`chmod 600`).
- Generate keys on the machine that uses them; do not copy them between machines.
