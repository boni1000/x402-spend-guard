# Test results (October 2026)

Setting: five-producer private Antelope network (Spring 1.2.2, pre-Savanna consensus); payments on
Base Sepolia (test USDC, public x402.org facilitator); agents on Ollama 0.24 (V100 32 GB).

| Test | Result |
|---|---|
| Contract test suite on chain | 65/65 (twice): limits at the boundary, replay, whitelist, approval, key misuse, revocation, expiry, rollover |
| Tool calling with the gateway's tools (17 tasks) | qwen3.6:35b 17/17, qwen2.5:7b-instruct 17/17, gemma4:31b 16/17, mistral-nemo:12b 13/17, llama3.1:8b 7/17 |
| Agent scenarios (qwen2.5:7b-instruct) | normal purchase, daily limit refused by the chain, human approval, compromised agent refused (unlisted vendor), kill switch — all passed; 33/33 checks over three rounds for the automated ones |
| Two-way audit | clean on all governed payments; found all 25 payments deliberately made around the gateway |
| Latency (median, 30 runs each) | x402 alone 1.52 s; governed 3.00 s → **≈1.5 s overhead**; approval irreversibility ≈36 s on pre-Savanna consensus |
| Facilitator refusals | 9/60 (15%), equally with and without governance; all governed cases recorded as failed with no money moved |

## Public testnet: Jungle4 (November 2026)

Same contract binary (code hash `28c1ed27…`) on the public Jungle4 testnet (Spring 1.2.2 with Savanna
consensus, finality about 1 s), installed from this repository into a fresh environment. Agent
qwen2.5:7b-instruct; payments on Base Sepolia.

| Test | Result |
|---|---|
| Normal purchase (0.01 USDC) | paid and settled; authorization in a block about 1.5 s after the quote (single run) |
| Over the per-payment limit (1.50 USDC) | refused by the contract |
| Unlisted vendor (0.05 USDC) | refused by the contract |
| Two-way audit | clean: 1 of 1 records verified, 1 of 1 transfers recorded |
| `setup_agent.sh` on a public endpoint | failed before the fix (step checked on a node that had not applied the previous one); passes after it, 7 transactions in about 9 s |
