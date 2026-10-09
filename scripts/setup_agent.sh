#!/usr/bin/env bash
# Register an agent and give its gateway a scoped key.
#
#   CHAIN_URL=https://... CONTRACT=myagentgov ADMIN=myadmin \
#   ./scripts/setup_agent.sh <agent> <gateway public key> <per_tx_max> <daily_max> <approval_threshold> <approver>
#
# Amounts are in micro-USDC (1000000 = 1 USDC). Needs, in an unlocked keosd wallet: the agent's
# active key (to create the gw permission and link it) and the admin's key (regagent, setpolicy).
# The gw permission can then call only authorize, settle, fail and expire on the contract.
set -euo pipefail
AGENT="$1"; GWKEY="$2"; PER_TX="$3"; DAILY="$4"; THRESHOLD="$5"; APPROVER="$6"
: "${CHAIN_URL:?set CHAIN_URL}" "${CONTRACT:?set CONTRACT}" "${ADMIN:?set ADMIN}"
CL="cleos -u $CHAIN_URL"
$CL set account permission "$AGENT" gw "$GWKEY" active -p "$AGENT@active"
for action in authorize settle fail expire; do
  $CL set action permission "$AGENT" "$CONTRACT" "$action" gw -p "$AGENT@active"
done
ZERO=0000000000000000000000000000000000000000000000000000000000000000
$CL push action "$CONTRACT" regagent "[\"$AGENT\",\"$ADMIN\",\"$ZERO\",\"$AGENT\"]" -p "$ADMIN@active"
$CL push action "$CONTRACT" setpolicy "[\"$AGENT\",$PER_TX,$DAILY,$THRESHOLD,\"$APPROVER\"]" -p "$ADMIN@active"
$CL get account "$AGENT" | sed -n '/permissions/,/memory/p'
