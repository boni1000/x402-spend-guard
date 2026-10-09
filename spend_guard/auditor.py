#!/usr/bin/env python3
"""Independent two-way audit of agent payments. Needs no keys: anyone with read access can run it.

  A. Every SETTLED agentgov record (from --from-id) matches a real payment: the Base Sepolia
     transaction succeeded and contains a USDC transfer from the payer to the vendor's
     whitelisted address of exactly the authorized amount, made after the request was created.
  B. Every USDC transfer out of the payer (from --from-block) has a SETTLED record with that tx.
     This catches payments that bypassed the governance gateway.

Prints a report and a Merkle root over the audited records. With --anchor the result is published
on chain with agentgov::logaudit, signed by the auditor's own account (run it on a machine other
than the gateway server). --incremental audits only what is new since this auditor's last
published audit.
"""
import argparse
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timezone

from .gateway import load_env
from .payments import BaseVerifier
from .spring import Spring


def all_rows(spring, table, from_id=0):
    rows, lower = [], from_id
    while True:
        r = spring._post("/v1/chain/get_table_rows", {"code": spring.contract, "scope": spring.contract,
                                                      "table": table, "json": True, "limit": 200,
                                                      "lower_bound": str(lower)})
        rows += r["rows"]
        if not r.get("more"):
            return rows
        lower = r["next_key"]


def merkle_root(leaves):
    level = [bytes.fromhex(h) for h in leaves] or [b"\0" * 32]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [hashlib.sha256(level[i] + level[i + 1]).digest() for i in range(0, len(level), 2)]
    return level[0].hex()


def main():
    for f in ("audit.env", "gateway.env", "keys.env"):
        load_env(f)
    ap = argparse.ArgumentParser()
    ap.add_argument("--payer", default=os.environ.get("PAYER_ADDRESS"), help="payer address (public)")
    ap.add_argument("--from-id", type=int, default=0, help="first agentgov request to audit")
    ap.add_argument("--from-block", type=int, default=int(os.environ.get("AUDIT_FROM_BLOCK", "0")) or None,
                    help="first public-chain block to scan (default: about one day back)")
    ap.add_argument("--incremental", action="store_true", help="continue after this auditor's last audit")
    ap.add_argument("--anchor", action="store_true", help="publish the result with agentgov::logaudit")
    ap.add_argument("--auditor", default=os.environ.get("AUDITOR"))
    a = ap.parse_args()

    spring = Spring(os.environ["CHAIN_URL"], os.environ["CONTRACT"])
    base = BaseVerifier(os.environ.get("RPC", "https://sepolia.base.org"),
                        os.environ.get("USDC", "0x036CbD53842c5426634e7929541eC2318f3dCF7e"))
    if not a.payer:
        sys.exit("set PAYER_ADDRESS or --payer")
    if a.from_block is None:
        a.from_block = max(0, base.block_number() - 43200)   # ~1 day of 2-second blocks
    payer = a.payer.lower()
    if a.incremental:
        mine = [x for x in all_rows(spring, "audits") if x["auditor"] == a.auditor]
        if mine:
            last = mine[-1]
            a.from_id = int(last["to_id"]) + 1
            since = time.time() - datetime.fromisoformat(last["created"]).replace(tzinfo=timezone.utc).timestamp()
            a.from_block = max(a.from_block, base.block_number() - int(since / 2) - 300)   # ~2 s blocks, margin
            print(f"incremental: continuing after audit {last['id']} (requests > {last['to_id']}, "
                  f"blocks >= {a.from_block})")
    vendors = {v["id"]: v for v in all_rows(spring, "vendors")}
    reqs = all_rows(spring, "payreqs", a.from_id)
    settled = [r for r in reqs if r["status"] == 5]
    print(f"Audit of {spring.contract} requests >= {a.from_id}: {len(reqs)} records, {len(settled)} settled; "
          f"payer {a.payer}")

    problems, leaves, total = [], [], 0
    print("\nA. Every settled record matches a real payment")
    for r in settled:
        tx, v = r["ext_txid"], vendors[r["vendor_id"]]
        try:
            rcpt = base.w3.eth.get_transaction_receipt(tx)
        except Exception as e:  # noqa: BLE001
            problems.append(f"request {r['id']}: tx {tx} not found on Base Sepolia ({e.__class__.__name__})")
            continue
        transfers = [lg for lg in rcpt.logs if base._matches(lg, payer, v["pay_to"], r["amount"])]
        block_time = datetime.fromtimestamp(base.w3.eth.get_block(rcpt.blockNumber)["timestamp"], timezone.utc)
        created = datetime.fromisoformat(r["created"]).replace(tzinfo=timezone.utc)
        if rcpt.status != 1:
            problems.append(f"request {r['id']}: tx {tx} failed on chain")
        elif not transfers:
            problems.append(f"request {r['id']}: tx {tx} has no transfer of {r['amount']} to {v['pay_to']}")
        elif block_time < created:
            problems.append(f"request {r['id']}: payment at {block_time} precedes the authorization at {created}")
        else:
            total += r["amount"]
            leaf = json.dumps({k: r[k] for k in ("id", "agent", "vendor_id", "amount", "params_hash", "nonce",
                                                  "ext_network", "ext_txid", "created")}, sort_keys=True)
            leaves.append(hashlib.sha256(leaf.encode()).hexdigest())
    print(f"   {len(leaves)} of {len(settled)} settled records verified, total {total / 1e6:.2f} USDC")

    print("\nB. Every payment out of the payer has a settled record")
    transfers = base.transfers(payer, a.from_block)
    recorded = {r["ext_txid"].lower() for r in settled}
    unrecorded = {tx: t for tx, t in transfers.items() if tx not in recorded}
    for tx, (to, value, blk) in unrecorded.items():
        problems.append(f"transfer {tx} ({value / 1e6:.2f} USDC to {to}, block {blk}) has no settled record")
    print(f"   {len(transfers) - len(unrecorded)} of {len(transfers)} transfers since block {a.from_block} "
          f"are recorded on agentgov")

    print("\nResult:", "CLEAN" if not problems else f"{len(problems)} PROBLEM(S)")
    for p in problems:
        print("  -", p)
    root = merkle_root(sorted(leaves))
    print(f"Merkle root of the {len(leaves)} verified records: {root}")
    if a.anchor and reqs:
        to_id = max(int(r["id"]) for r in reqs)
        signer = Spring(os.environ["CHAIN_URL"], os.environ["CONTRACT"], os.environ["AUDIT_WALLET"],
                        os.environ["AUDIT_WALLET_PW_FILE"])
        note = f"two-way audit; {len(transfers)} transfers since block {a.from_block}"
        res = signer.push("logaudit", [a.auditor, root, a.from_id, to_id, len(leaves), total, len(problems), note],
                          a.auditor, "active")
        if res["ok"] and signer.wait_included(res["trx_id"], res["block_num"]):
            print(f"Anchored on chain: audit {res['return']} by {a.auditor}, requests {a.from_id}-{to_id}, "
                  f"tx {res['trx_id']}")
        else:
            print("Anchoring failed:", res.get("error", "not included in a block"))
    elif a.anchor:
        print("Nothing new to audit; no anchor published.")
    sys.exit(1 if problems else 0)


if __name__ == "__main__":
    main()
