# Lessons learned

1. **An Antelope API node's response is advisory.** It evaluates a transaction against its head block,
   and producers may include relayed transactions later and in a different order. Confirm block
   inclusion, read the resulting state from the table, and use short transaction expiries.
2. **RAM payer rules.** A row paid for by one account cannot grow in an action that account did not
   sign. Re-bill admin-changed rows to the signing admin; keep free-text reasons in the action data.
3. **Old `eosio.msig` versions** execute approved proposals as deferred transactions, which Spring
   nodes no longer run. Use the current eos-system-contracts version, which executes inline.
4. **The x402 SDK has its own default spending cap** (USD 1 per payment). Set it explicitly.
5. **Public RPC endpoints can serve stale "latest" state and reject large log queries.** Read at explicit
   blocks and query logs in small ranges.
6. **Verify payments by event, not by balance difference**: check the Transfer event in the receipt;
   identify one specific signed payment by its ERC-3009 `AuthorizationUsed` nonce.
7. **Small models mistype IP addresses** in tool calls; give them host names.
8. **PID files, not `pkill -f`,** for processes started over SSH: the pattern also matches the remote
   shell's own command line.
