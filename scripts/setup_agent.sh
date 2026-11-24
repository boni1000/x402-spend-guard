#!/usr/bin/env bash
# Register an agent and give its gateway a scoped key.
#
#   CHAIN_URL=https://... CONTRACT=myagentgov ADMIN=myadmin \
#   ./scripts/setup_agent.sh <agent> <gateway public key> <per_tx_max> <daily_max> <approval_threshold> <approver>
#
# Amounts are in micro-USDC (1000000 = 1 USDC). Needs, in an unlocked keosd wallet: the agent's
# active key (to create the gw permission and link it) and the admin's key (regagent, setpolicy).
# The gw permission can then call only authorize, requestsig, settle, fail and expire on the contract.
#
# Each step waits until the API node shows the previous one: a public endpoint may route the next
# request to a node that has not applied the last transaction yet ("Permission Query Exception").
set -euo pipefail
AGENT="$1"; GWKEY="$2"; PER_TX="$3"; DAILY="$4"; THRESHOLD="$5"; APPROVER="$6"
: "${CHAIN_URL:?set CHAIN_URL}" "${CONTRACT:?set CONTRACT}" "${ADMIN:?set ADMIN}"
CL="cleos -u $CHAIN_URL"

# wait_for <description> <command that succeeds once the change is visible>
wait_for() {
  local what="$1"; shift
  for _ in $(seq 1 30); do
    if "$@" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  echo "timed out waiting for: $what" >&2
  exit 1
}
has_permission() { $CL get account "$AGENT" -j | grep -q "\"perm_name\": *\"$1\""; }
has_link() { $CL get account "$AGENT" -j | grep -q "\"action\": *\"$1\""; }
has_agent_row() { $CL get table "$CONTRACT" "$CONTRACT" agents -L "$AGENT" -U "$AGENT" | grep -q "\"agent\": *\"$AGENT\""; }

$CL set account permission "$AGENT" gw "$GWKEY" active -p "$AGENT@active"
wait_for "gw permission on $AGENT" has_permission gw
for action in authorize requestsig settle fail expire; do
  $CL set action permission "$AGENT" "$CONTRACT" "$action" gw -p "$AGENT@active"
  wait_for "link $CONTRACT::$action to $AGENT@gw" has_link "$action"
done
ZERO=0000000000000000000000000000000000000000000000000000000000000000
$CL push action "$CONTRACT" regagent "[\"$AGENT\",\"$ADMIN\",\"$ZERO\",\"$AGENT\"]" -p "$ADMIN@active"
wait_for "agent row for $AGENT" has_agent_row
$CL push action "$CONTRACT" setpolicy "[\"$AGENT\",$PER_TX,$DAILY,$THRESHOLD,\"$APPROVER\"]" -p "$ADMIN@active"
$CL get account "$AGENT" | sed -n '/permissions/,/memory/p'
