"""Minimal Spring (Antelope) client for the governance gateway.

Reads go to the chain HTTP API. Signed pushes go through cleos + keosd, so private keys stay
in the wallet and never enter this process.

Lessons from phase 2, applied here:
- the API node evaluates a transaction against the head block, and producers may include a
  relayed transaction later and in their own order, so a push response is only advisory;
- the source of truth is the contract table after the transaction is in a block;
- transactions use a short expiry, so a refused request cannot be included much later.
"""
import json
import re
import subprocess
import time

import httpx

_CHARS = ".12345abcdefghijklmnopqrstuvwxyz"


def name_to_u64(name: str) -> int:
    value = 0
    for i in range(13):
        c = _CHARS.index(name[i]) if i < len(name) else 0
        value |= (c & 0x1F) << (64 - 5 * (i + 1)) if i < 12 else (c & 0x0F)
    return value


class Spring:
    def __init__(self, url, contract, wallet=None, wallet_pw_file=None, expiration=15):
        self.url = url.rstrip("/")
        self.contract = contract
        self.wallet = wallet
        self.wallet_pw_file = wallet_pw_file
        self.expiration = expiration
        self.http = httpx.Client(timeout=15)

    # ------------------------------------------------------------------ reads
    def _post(self, path, body=None):
        r = self.http.post(self.url + path, json=body or {})
        r.raise_for_status()
        return r.json()

    def info(self):
        return self._post("/v1/chain/get_info")

    def table(self, table, scope=None, lower=None, upper=None, index=None, key_type=None, limit=100):
        body = {"code": self.contract, "scope": scope or self.contract, "table": table, "json": True,
                "limit": limit}
        if lower is not None:
            body["lower_bound"] = str(lower)
        if upper is not None:
            body["upper_bound"] = str(upper)
        if index is not None:
            body["index_position"] = str(index)
            body["key_type"] = key_type
        return self._post("/v1/chain/get_table_rows", body)["rows"]

    def req_by_id(self, req_id):
        rows = self.table("payreqs", lower=req_id, upper=req_id, limit=1)
        return rows[0] if rows else None

    def req_by_nonce(self, agent, nonce):
        key = (name_to_u64(agent) << 64) | int(nonce)
        rows = self.table("payreqs", lower=key, upper=key, index=3, key_type="i128", limit=1)
        return rows[0] if rows else None

    # ------------------------------------------------------------------ writes
    def unlock(self):
        if self.wallet and self.wallet_pw_file:
            with open(self.wallet_pw_file) as f:
                pw = f.read().strip()
            # Password via stdin, not as an argument: arguments are visible in the process list.
            subprocess.run(["cleos", "wallet", "unlock", "-n", self.wallet], input=pw + "\n",
                           capture_output=True, text=True, timeout=30)

    def push(self, action, data, actor, permission):
        """Push one action. Returns {"ok", "trx_id", "block_num", "return"} or {"ok": False, "error"}."""
        self.unlock()
        cmd = ["cleos", "-u", self.url, "push", "action", self.contract, action, json.dumps(data),
               "-p", f"{actor}@{permission}", "-x", str(self.expiration), "-j"]
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        doc = None
        if "{" in p.stdout:
            try:
                doc = json.loads(p.stdout[p.stdout.index("{"):])
            except ValueError:
                doc = None
        if p.returncode == 0 and doc and not doc["processed"].get("except"):
            trace = doc["processed"]["action_traces"][0]
            return {"ok": True, "trx_id": doc["transaction_id"], "block_num": doc["processed"]["block_num"],
                    "return": trace.get("return_value_data")}
        return {"ok": False, "error": self._error_text(doc, p.stderr)}

    @staticmethod
    def _error_text(doc, stderr):
        if doc:
            exc = doc.get("processed", {}).get("except") or {}
            for s in exc.get("stack", []):
                data = s.get("data", {})
                text = re.sub(r"\$\{(\w+)\}", lambda m, d=data: str(d.get(m.group(1), m.group(0))), s.get("format", ""))
                m = re.search(r"assertion failure with message: (.*)", text)
                if m:
                    return m.group(1)
                if "authority" in text.lower():
                    return text
            if exc:
                return exc.get("message", "transaction failed")
        m = re.search(r"Error \d+: [^\n]*", re.sub(r"\x1b\[[0-9;]*m", "", stderr or ""))
        return m.group(0) if m else (stderr or "transaction failed").strip()[:200]

    # ------------------------------------------------------------------ inclusion
    def wait_included(self, trx_id, start_block, timeout=None):
        """Return the block number containing trx_id, or None if it was not included in time."""
        deadline = time.time() + (timeout or self.expiration + 5)
        n = max(1, int(start_block) - 2)
        while time.time() < deadline:
            head = self.info()["head_block_num"]
            while n <= head:
                block = self._post("/v1/chain/get_block", {"block_num_or_id": n})
                for t in block.get("transactions", []):
                    trx = t.get("trx")
                    if (trx.get("id") if isinstance(trx, dict) else trx) == trx_id:
                        return n
                n += 1
            time.sleep(0.3)
        return None

    def wait_irreversible(self, block_num, timeout=120):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.info()["last_irreversible_block_num"] >= block_num:
                return True
            time.sleep(1)
        return False
