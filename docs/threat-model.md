# Threat model

| Compromised component | Can do | Cannot do | Detection / recovery |
|---|---|---|---|
| The AI agent | Ask for any purchase | Exceed limits; pay unlisted vendors; skip approval; act after revocation | Refusals in the gateway log; revoke |
| The gateway machine, key mode | Pay from the payer wallet around the contract; use its linked actions | Change policies, approve, add vendors, unrevoke, move chain tokens | Auditor reverse check; revoke agents, rotate `gw` keys, empty the payer wallet |
| The gateway machine, MPC mode | Request signatures for its agent's authorized requests; withhold or delay delivering them, leaving the amount reserved | Get a signature for any other payer, vendor or amount; pay around the contract; release the budget of a signed request | Unpaid signed requests stay visible in `sigreqs`; revoke agents, rotate `gw` keys |
| The payer wallet key alone (key mode) | Spend its balance | Create records on chain | Auditor reverse check; small float only |
| The agentgov account keys (MPC mode) | Ask the MPC network directly for any signature for any agent, bypassing every limit; upgrade the code | Sign without the MPC network | `active` = `eosio.code` + multi-sig, `owner` multi-sig; every request is on chain in the MPC contract |
| A threshold of MPC operators | Sign anything for any payer address | Change agentgov's records | Auditor reverse check (all payer addresses) finds transfers without records; float only. Alcor's testnet: all 5 nodes run by Alcor |
| Fewer than the threshold, or the MPC network offline | Delay or refuse signatures | Sign anything | Payments fail after the gateway's timeout; signed amounts stay reserved until `validBefore`, then the attester releases them |
| The attester (MPC mode) | Release the budget of a signed request after its `validBefore`, also one that was executed, so the agent can spend that amount again that day | Release before `validBefore`; obtain signatures; move funds | Auditor check C compares each release with USDC's `authorizationState`; keep the attester off the gateway machine |
| Anyone reading the chain (MPC mode) | Submit a published signature to USDC before its `validBefore` | Change its recipient or amount; reuse it (the nonce is per request) | The budget already counts it as spent; short `sig_ttl_sec` |
| One block producer (of n) | Withhold transactions while producing | Forge or reverse final records (needs ⅔+1 for finality) | Others continue; with too few producers, finality stops and the gateway refuses approval-gated payments. The MPC network signs only irreversible requests, so a fork cannot leave a signature for a request that was undone |
| The approver's account | Approve within limits | Raise limits; exceed per-payment or daily limits | `approved_by` in every record |
| The admin account | Change policies, whitelist, payer addresses and the MPC settings; revoke | Change the contract code; rewrite past records; obtain a signature itself | Every change is a signed action on chain; separate admin and approver. A wrong payer address cannot pay: the signature would not belong to it |
| One holder of a multi-sig key | Propose and approve | Change code or configuration alone | Proposals and approvals on chain; compare the proposed code's SHA-256 with your build |
| Public RPC / facilitator | Stale data; refuse or delay payments | Make the gateway accept a fake transfer (receipt and Transfer event are verified) | Reconciler; auditor; retry |

Residual risks: a single organisation running all producers; multi-sig keys held by one person; the
payer wallet on the gateway machine (key mode); testnet facilitators. In MPC mode: a single
organisation running all MPC nodes (Alcor's testnet today); agentgov's account keys if not under a
multi-sig; an attester that is not independent of the gateway; the MPC interface, which is not final
(tested against a mock).
