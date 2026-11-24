#!/usr/bin/env bash
# A throwaway single-producer Spring chain for testing agentgov with what Jungle4 or a mainnet
# have and an old local nodeos lacks: keccak (CRYPTO_PRIMITIVES) and action return values.
# Runs on a Linux host with Spring (or a fork of it) built:
#
#   SPRING_BIN=~/spring/build/bin BOOT_DIR=~/spring/unittests/contracts/eosio.boot \
#   CONTRACT_DIR=~/agentgov-build ./devchain.sh start      # fresh chain + agentgov deployed
#   ./devchain.sh stop
#
# Everything lives in $DEVCHAIN_DIR (default ~/agentgov-devchain): its own data, nodeos on
# 127.0.0.1:18888 (p2p 19876, no peers) and its own keosd on 127.0.0.1:18900. It uses the
# well-known development key, so it must never be connected to another network. Processes are
# stopped by their pid files only, never by name, so other nodeos on the host are left alone.
set -euo pipefail
DIR="${DEVCHAIN_DIR:-$HOME/agentgov-devchain}"
URL=http://127.0.0.1:18888
WALLET=http://127.0.0.1:18900
PUB=EOS6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV
PRIV=5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3
ACCOUNTS="agentgov admin1 agent1 agent2 approver1 attester1 mpc1"

stop() {
  for p in nodeos keosd; do
    if [ -f "$DIR/$p.pid" ]; then kill "$(cat "$DIR/$p.pid")" 2>/dev/null || true; rm -f "$DIR/$p.pid"; fi
  done
}

wait_http() {
  for _ in $(seq 1 60); do curl -sf "$1" -X POST >/dev/null 2>&1 && return 0; sleep 0.5; done
  echo "no answer from $1" >&2; exit 1
}

start() {
  : "${SPRING_BIN:?set SPRING_BIN}" "${BOOT_DIR:?set BOOT_DIR}" "${CONTRACT_DIR:?set CONTRACT_DIR}"
  local cl="$SPRING_BIN/cleos -u $URL --wallet-url $WALLET"
  if [ -e "$DIR" ]; then
    [ -f "$DIR/.agentgov-devchain" ] || { echo "$DIR exists and is not a dev chain; not touching it" >&2; exit 1; }
    stop; sleep 1; rm -rf "$DIR"
  fi
  mkdir -p "$DIR" && touch "$DIR/.agentgov-devchain"

  nohup "$SPRING_BIN/keosd" --data-dir "$DIR/keosd" --wallet-dir "$DIR/wallet" \
    --http-server-address 127.0.0.1:18900 --unix-socket-path "$DIR/keosd.sock" \
    --http-validate-host false >"$DIR/keosd.log" 2>&1 &
  echo $! >"$DIR/keosd.pid"
  nohup "$SPRING_BIN/nodeos" --data-dir "$DIR/data" --config-dir "$DIR/config" -e -p eosio \
    --signature-provider "$PUB=KEY:$PRIV" \
    --plugin eosio::chain_api_plugin --plugin eosio::producer_api_plugin \
    --http-server-address 127.0.0.1:18888 --http-validate-host false \
    --p2p-listen-endpoint 127.0.0.1:19876 --contracts-console \
    --max-transaction-time 1000 --abi-serializer-max-time-ms 1000 >"$DIR/nodeos.log" 2>&1 &
  echo $! >"$DIR/nodeos.pid"
  wait_http "$URL/v1/chain/get_info"
  wait_http "$WALLET/v1/wallet/list_wallets"

  $cl wallet create -n dev --file "$DIR/wallet-password.txt" >/dev/null
  $cl wallet import -n dev --private-key "$PRIV" >/dev/null

  # PREACTIVATE_FEATURE, then the boot contract activates every other supported feature.
  curl -sf -X POST "$URL/v1/producer/schedule_protocol_feature_activations" \
    -d '{"protocol_features_to_activate":["0ec7e080177b2c02b278d5088611686b49d739925a92d9bfcacd7fc6b74053bd"]}' >/dev/null
  sleep 2
  $cl set contract eosio "$BOOT_DIR" eosio.boot.wasm eosio.boot.abi -p eosio@active >/dev/null
  local features
  features=$(curl -sf -X POST "$URL/v1/producer/get_supported_protocol_features" | python3 -c '
import json, sys
for f in json.load(sys.stdin):
    if f["specification"][0]["value"] != "PREACTIVATE_FEATURE": print(f["feature_digest"])')
  for _ in 1 2 3; do   # a feature activates only after its dependencies: repeat until all are in
    for d in $features; do $cl push action eosio activate "[\"$d\"]" -p eosio@active >/dev/null 2>&1 || true; done
    sleep 1
  done

  for a in $ACCOUNTS; do $cl create account eosio "$a" "$PUB" "$PUB" >/dev/null; done
  sleep 1
  $cl set contract agentgov "$CONTRACT_DIR" agentgov.wasm agentgov.abi -p agentgov@active >/dev/null
  echo "dev chain ready at $URL (wallet $WALLET); accounts: $ACCOUNTS"
}

case "${1:-}" in
  start) start ;;
  stop) stop ;;
  *) echo "usage: $0 start|stop" >&2; exit 2 ;;
esac
