# Threat model

| Compromised component | Can do | Cannot do | Detection / recovery |
|---|---|---|---|
| The AI agent | Ask for any purchase | Exceed limits; pay unlisted vendors; skip approval; act after revocation | Refusals in the gateway log; revoke |
| The gateway machine | Pay from the payer wallet around the contract; use its four linked actions | Change policies, approve, add vendors, unrevoke, move chain tokens | Auditor reverse check; revoke agents, rotate `gw` keys, empty the payer wallet |
| The payer wallet key alone | Spend its balance | Create records on chain | Auditor reverse check; small float only |
| One block producer (of n) | Withhold transactions while producing | Forge or reverse final records (needs ⅔+1 for finality) | Others continue; with too few producers, finality stops and the gateway refuses approval-gated payments |
| The approver's account | Approve within limits | Raise limits; exceed per-payment or daily limits | `approved_by` in every record |
| The admin account | Change policies and whitelist; revoke | Change the contract code; rewrite past records | Every change is a signed action on chain; separate admin and approver |
| One holder of a multi-sig key | Propose and approve | Change code or configuration alone | Proposals and approvals on chain; compare the proposed code's SHA-256 with your build |
| Public RPC / facilitator | Stale data; refuse or delay payments | Make the gateway accept a fake transfer (receipt and Transfer event are verified) | Reconciler; auditor; retry |

Residual risks: a single organisation running all producers; multi-sig keys held by one person; the
payer wallet on the gateway machine; testnet facilitators.
