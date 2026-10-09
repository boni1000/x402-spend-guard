#!/usr/bin/env bash
# Propose a contract upgrade (setcode + setabi) through eosio.msig, for a contract account whose
# permissions are held by several approvers.
#
#   CHAIN_URL=https://... CONTRACT=myagentgov PROPOSER=myaccount \
#   APPROVERS='[{"actor":"alice","permission":"owner"},{"actor":"bob","permission":"owner"}]' \
#   ./scripts/propose_upgrade.sh <proposal_name> <dir with agentgov.wasm and agentgov.abi>
#
# Approvers should compare the proposed code's SHA-256 with their own build before approving.
# Requires an eosio.msig that executes inline (current eos-system-contracts); older versions
# schedule deferred transactions, which Spring nodes no longer execute.
set -euo pipefail
NAME="$1"; DIR="$2"
: "${CHAIN_URL:?set CHAIN_URL}" "${CONTRACT:?set CONTRACT}" "${PROPOSER:?set PROPOSER}" "${APPROVERS:?set APPROVERS (JSON list)}"
FILE="${FILE:-agentgov}"
CL="cleos -u $CHAIN_URL"
$CL set contract "$CONTRACT" "$DIR" "$FILE.wasm" "$FILE.abi" -p "$CONTRACT@active" -s -d -j -x 604800 > /tmp/upgrade_trx.json
grep -q '"actions"' /tmp/upgrade_trx.json || { echo "Nothing to propose: the code is identical to the deployed code."; exit 1; }
$CL multisig propose_trx "$NAME" "$APPROVERS" /tmp/upgrade_trx.json "$PROPOSER" -p "$PROPOSER@active"
echo "Proposed $NAME. Proposed code sha256: $(sha256sum "$DIR/$FILE.wasm" 2>/dev/null || shasum -a 256 "$DIR/$FILE.wasm")"
