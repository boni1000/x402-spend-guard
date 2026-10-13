"""Agent spend governance gateway: authorize on Spring, pay via x402, record the settlement.

Flow of paid_fetch(url, max_price):
  1. unpaid request -> HTTP 402 with the vendor's price and recipient
  2. local checks: price <= max_price, vendor on the on-chain whitelist
  3. agentgov::authorize (signed with the agent's scoped gw key), confirmed in a block, then
     read back from the table by nonce (the table is the source of truth)
  4. PENDING  -> return "pending_approval"; the watcher pays after an irreversible approval
     AUTHORIZED -> pay exactly the authorized requirement
  5. verify the USDC transfer on Base Sepolia, then agentgov::settle with its tx hash;
     if the vendor did not deliver, agentgov::fail releases the budget.
"""
import asyncio
import hashlib
import json
import logging
import os
import secrets
import time
from dataclasses import dataclass

from .journal import Journal
from .payments import BaseVerifier, PaymentNotSent, X402Payer, same_requirement
from .spring import Spring

log = logging.getLogger("gateway")

RETRYABLE = {"invalid_exact_evm_transaction_failed"}   # facilitator could not execute the transfer
MAX_ATTEMPTS = 3
STATUS = {1: "authorized", 2: "pending_approval", 3: "approved", 4: "rejected",
          5: "settled", 6: "failed", 7: "expired"}
# agentgov::settle errors that retrying cannot fix
SETTLE_PERMANENT = ("unknown request", "not your request", "not authorized for payment",
                    "invalid transaction id", "network does not match vendor", "transaction already recorded")

# Block explorer for transaction links, by CAIP-2 network (override with EXPLORER_TX_URL).
EXPLORERS = {"eip155:84532": "https://sepolia.basescan.org/tx/", "eip155:8453": "https://basescan.org/tx/"}


def load_env(path):
    if path and os.path.exists(path):
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    os.environ.setdefault(k, v)


@dataclass
class Config:
    chain_url: str
    contract: str
    agent: str
    permission: str
    wallet: str
    wallet_pw_file: str
    network: str
    rpc: str
    usdc: str
    payer_key: str
    journal_path: str

    @classmethod
    def from_env(cls, files=None):
        # Settings come from the environment; files (default: gateway.env and keys.env in the
        # working directory, or SPEND_GUARD_ENV="a.env,b.env") only fill in what is not set.
        files = files or os.environ.get("SPEND_GUARD_ENV", "gateway.env,keys.env").split(",")
        for f in files:
            load_env(f)
        e = os.environ
        return cls(e["CHAIN_URL"], e["CONTRACT"], e["AGENT"], e.get("PERMISSION", "gw"), e["GW_WALLET"],
                   e["GW_WALLET_PW_FILE"], e.get("NETWORK", "eip155:84532"), e.get("RPC", "https://sepolia.base.org"),
                   e.get("USDC", "0x036CbD53842c5426634e7929541eC2318f3dCF7e"), e["PAYER_PRIVATE_KEY"],
                   e.get("JOURNAL", f"journal-{e['AGENT']}.sqlite"))


def usdc(micro):
    return round(int(micro) / 1e6, 6)


class Gateway:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.spring = Spring(cfg.chain_url, cfg.contract, cfg.wallet, cfg.wallet_pw_file)
        self.payer = X402Payer(cfg.payer_key, cfg.network)
        self.base = BaseVerifier(cfg.rpc, cfg.usdc)
        self.journal = Journal(cfg.journal_path)
        pol = self.spring.table("policies", lower=cfg.agent, upper=cfg.agent, limit=1)
        self.payer.set_cap(int(pol[0]["per_tx_max"]) / 1e6 if pol else 0.0)

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _nonce():
        # Microseconds plus a random part: unique across processes acting for the same agent.
        return int(time.time() * 1_000_000) * 1000 + secrets.randbelow(1000)

    def _explorer(self, tx):
        base = os.environ.get("EXPLORER_TX_URL") or EXPLORERS.get(self.cfg.network, "")
        return base + tx if base else tx

    def _push(self, action, data):
        return self.spring.push(action, data, self.cfg.agent, self.cfg.permission)

    async def _push_confirmed(self, action, data):
        res = await asyncio.to_thread(self._push, action, data)
        if res["ok"]:
            res["block"] = await asyncio.to_thread(self.spring.wait_included, res["trx_id"], res["block_num"])
        return res

    def _vendor(self, network, pay_to):
        for v in self.spring.table("vendors", limit=1000):
            if v["network"] == network.lower() and v["pay_to"] == pay_to.lower():
                return v
        return None

    def _seconds_left(self, row):
        """Validity left on an authorization, measured with the chain's clock."""
        from datetime import datetime
        head = datetime.fromisoformat(self.spring.info()["head_block_time"][:19])
        return (datetime.fromisoformat(row["expires"][:19]) - head).total_seconds()

    @staticmethod
    def _params_hash(url, acc):
        doc = {"url": url, "scheme": acc.scheme, "network": acc.network, "asset": acc.asset.lower(),
               "amount": str(acc.amount), "pay_to": acc.pay_to.lower()}
        return hashlib.sha256(json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    # ------------------------------------------------------------------ tools
    async def paid_fetch(self, url: str, max_price: float):
        self._t = {"start": time.time()}
        try:
            pr, resp = await self.payer.quote(url)
        except Exception as e:  # noqa: BLE001 - reported to the agent
            return {"status": "error", "reason": f"cannot reach {url}: {e}"}
        if pr is None:
            return {"status": "free", "http_status": resp.status_code, "content": resp.text[:4000]}
        acc = self.payer.choose(pr)
        if acc is None:
            return {"status": "refused", "reason": f"vendor offers no payment option on {self.cfg.network}"}
        amount = int(acc.amount)
        if max_price is not None and amount > round(float(max_price) * 1e6):
            return {"status": "refused", "price": usdc(amount),
                    "reason": f"price {usdc(amount)} USDC is above your max_price {max_price}"}
        vendor = self._vendor(acc.network, acc.pay_to)
        if not vendor or not vendor["active"]:
            log.warning("refused: vendor %s not whitelisted (%s)", acc.pay_to, url)
            return {"status": "refused", "price": usdc(amount), "pay_to": acc.pay_to,
                    "reason": "vendor is not on the whitelist"}

        self._t["quoted"] = time.time()
        nonce = self._nonce()
        self.journal.insert(nonce, self.cfg.agent, url, acc.model_dump(mode="json", by_alias=True), amount,
                            vendor["id"], "authorizing")
        res = await self._push_confirmed("authorize", [self.cfg.agent, vendor["id"], amount,
                                                        self._params_hash(url, acc), nonce])
        if not res["ok"]:
            self.journal.update(nonce, phase="refused", error=res["error"])
            return {"status": "refused", "price": usdc(amount), "reason": res["error"]}
        row = await asyncio.to_thread(self.spring.req_by_nonce, self.cfg.agent, nonce)
        self._t["authorized"] = time.time()
        if row is None:
            self.journal.update(nonce, phase="refused", error="authorization not included in a block")
            return {"status": "refused", "price": usdc(amount), "reason": "authorization was not confirmed on chain"}
        self.journal.update(nonce, req_id=row["id"])
        if row["status"] == 2:
            self.journal.update(nonce, phase="pending_approval")
            return {"status": "pending_approval", "request_id": row["id"], "price": usdc(amount),
                    "message": "Above the approval threshold: waiting for the approver. "
                               "Check payment_status(request_id) later."}
        if row["status"] != 1:
            self.journal.update(nonce, phase=STATUS.get(row["status"], "failed"))
            return {"status": "refused", "reason": f"unexpected request status {STATUS.get(row['status'])}"}
        self.journal.update(nonce, phase="authorized")
        return await self._pay(nonce, row, url, pr, acc)

    async def _pay(self, nonce, row, url, pr, acc):
        req_id, amount = row["id"], int(acc.amount)
        if await asyncio.to_thread(self._seconds_left, row) < 20:
            # Never start a payment on an authorization that is about to expire; the
            # reconciler expires it on chain and releases the budget.
            self.journal.update(nonce, phase="authorized", error="authorization expiring; payment not started")
            return {"status": "failed", "request_id": req_id, "reason": "authorization expired before payment"}
        base_block = await asyncio.to_thread(self.base.block_number)
        self.journal.update(nonce, phase="paying", base_block=base_block)
        attempts, found_tx = [], None
        for attempt in range(1, MAX_ATTEMPTS + 1):
            try:
                r, settle, auth_nonce = await self.payer.pay(url, pr, acc)
            except PaymentNotSent as e:
                if attempts:   # an earlier attempt was sent: let the reconciler resolve it
                    self.journal.update(nonce, phase="payment_unknown", error=str(e)[:500])
                    return {"status": "unknown", "request_id": req_id, "reason": "retry could not be created"}
                reason = f"payment not sent: {e}"[:120]
                await self._push_confirmed("fail", [self.cfg.agent, req_id, reason])
                self.journal.update(nonce, phase="failed", error=str(e)[:500])
                return {"status": "failed", "request_id": req_id, "reason": reason}
            except Exception as e:  # noqa: BLE001 - outcome unknown; the reconciler resolves it
                self.journal.update(nonce, phase="payment_unknown", error=str(e)[:500])
                return {"status": "unknown", "request_id": req_id,
                        "reason": "payment outcome unknown; it will be reconciled automatically"}
            attempts.append(auth_nonce)
            self.journal.update(nonce, attempts=json.dumps(attempts))
            if r.status_code == 200 and settle and settle.success:
                break
            retryable = settle is not None and not settle.success and (settle.error_reason or "") in RETRYABLE
            if not retryable or attempt == MAX_ATTEMPTS:
                break
            # Retry only if this exact signed payment was NOT executed after all.
            found_tx = await asyncio.to_thread(self.base.authorization_used, self.payer.address, auth_nonce,
                                               base_block)
            if found_tx or await asyncio.to_thread(self._seconds_left, row) < 20:
                break
            log.warning("request %s: facilitator refused attempt %s (%s); retrying", req_id, attempt,
                        settle.error_reason)
            await asyncio.sleep(2 * attempt)
        if found_tx:   # paid after all, but the vendor did not deliver the content in that response
            ok, _ = await asyncio.to_thread(self.base.verify, found_tx, self.payer.address, acc.pay_to, amount)
            if ok:
                res = await self._push_confirmed("settle", [self.cfg.agent, req_id, acc.network, found_tx])
                self.journal.update(nonce, ext_tx=found_tx, phase="settled" if res["ok"] else "paid_not_recorded")
                return {"status": "paid", "request_id": req_id, "price": usdc(amount), "tx": found_tx,
                        "explorer": self._explorer(found_tx), "content": "",
                        "warning": "paid, but the vendor reported a failure and delivered no content"}
        self._t["paid"] = time.time()
        if r.status_code == 200 and settle and settle.success:
            tx = settle.transaction
            ok, _ = await asyncio.to_thread(self.base.verify, tx, self.payer.address, acc.pay_to, amount)
            if not ok:
                self.journal.update(nonce, phase="payment_unknown", ext_tx=tx, error="transfer not verified on chain")
                return {"status": "unknown", "request_id": req_id, "tx": tx,
                        "reason": "vendor reported a payment that could not be verified"}
            self._t["verified"] = time.time()
            self.journal.update(nonce, ext_tx=tx, content=r.text[:20000])
            res = await self._push_confirmed("settle", [self.cfg.agent, req_id, acc.network, tx])
            self._t["settled"] = time.time()
            self.journal.update(nonce, phase="settled" if res["ok"] else "paid_not_recorded",
                                error=None if res["ok"] else res["error"])
            out = {"status": "paid", "request_id": req_id, "price": usdc(amount), "tx": tx,
                   "explorer": self._explorer(tx), "content": r.text[:4000], "timing": self._timing(),
                   "attempts": len(attempts)}
            if not res["ok"]:
                out["warning"] = "paid, but not yet recorded on chain; the reconciler will retry"
            return out
        reason = f"vendor returned HTTP {r.status_code}"
        if settle and not settle.success:
            reason += f": {settle.error_reason or settle.error_message}"
        if len(attempts) > 1:
            reason += f" (after {len(attempts)} attempts)"
        await self._push_confirmed("fail", [self.cfg.agent, req_id, reason[:120]])
        self.journal.update(nonce, phase="failed", error=reason)
        return {"status": "failed", "request_id": req_id, "reason": reason}

    def _timing(self):
        """Seconds per step of the last paid_fetch (for the latency measurements)."""
        t = getattr(self, "_t", {})
        steps = [("quote", "start", "quoted"), ("authorize_on_chain", "quoted", "authorized"),
                 ("pay_and_settle_x402", "authorized", "paid"), ("verify_on_base", "paid", "verified"),
                 ("record_settlement", "verified", "settled"), ("total", "start", "settled")]
        return {k: round(t[b] - t[a], 3) for k, a, b in steps if a in t and b in t}

    def get_budget(self):
        cfg = self.spring.table("config", limit=1)[0]
        pol = self.spring.table("policies", lower=self.cfg.agent, upper=self.cfg.agent, limit=1)
        if not pol:
            return {"error": "agent has no policy"}
        pol = pol[0]
        day = int(time.time()) // int(cfg["day_sec"])
        spend = self.spring.table("spend", scope=self.cfg.agent, lower=day, upper=day, limit=1)
        committed = int(spend[0]["committed"]) if spend else 0
        return {"agent": self.cfg.agent, "per_payment_limit": usdc(pol["per_tx_max"]),
                "daily_limit": usdc(pol["daily_max"]), "approval_above": usdc(pol["approval_threshold"]),
                "committed_today": usdc(committed),
                "remaining_today": usdc(max(0, int(pol["daily_max"]) - committed)), "currency": "USDC"}

    def payment_status(self, request_id: int):
        row = self.spring.req_by_id(int(request_id))
        if not row or row["agent"] != self.cfg.agent:
            return {"error": "unknown request"}
        j = self.journal.by_req_id(int(request_id)) or {}
        out = {"request_id": row["id"], "status": STATUS.get(row["status"], "?"), "price": usdc(row["amount"]),
               "url": j.get("url")}
        if row["ext_txid"]:
            out["tx"] = row["ext_txid"]
            out["explorer"] = self._explorer(row["ext_txid"])
        if row["status"] == 5 and j.get("content"):
            out["content"] = j["content"][:4000]
        return out

    # ------------------------------------------------------------------ background work
    async def process_approved(self):
        """Pay requests that the approver approved. Large payments act only on an irreversible approval."""
        from x402.schemas import PaymentRequirements
        for j in self.journal.by_phase("pending_approval"):
            row = await asyncio.to_thread(self.spring.req_by_id, j["req_id"])
            if row is None:
                continue
            if row["status"] in (4, 6, 7):
                self.journal.update(j["nonce"], phase=STATUS[row["status"]])
                continue
            if row["status"] == 2:
                # Nobody approved in time: expire on chain, which releases the reserved budget.
                if await asyncio.to_thread(self._seconds_left, row) < 0:
                    res = await self._push_confirmed("expire", [row["id"]])
                    if res["ok"]:
                        self.journal.update(j["nonce"], phase="expired")
                        log.info("request %s expired without approval", row["id"])
                continue
            if row["status"] != 3:
                continue
            head = (await asyncio.to_thread(self.spring.info))["head_block_num"]
            await asyncio.to_thread(self.spring.wait_irreversible, head)
            row = await asyncio.to_thread(self.spring.req_by_id, j["req_id"])
            if row["status"] != 3:
                continue
            # Claim the request first: if another process (e.g. a second watcher or an MCP server)
            # handles the same journal, only one of them may pay.
            if not self.journal.claim(j["nonce"], "pending_approval", "authorized"):
                continue
            authorized = PaymentRequirements.model_validate(json.loads(j["accepted"]))
            pr, _ = await self.payer.quote(j["url"])
            acc = self.payer.choose(pr) if pr else None
            if acc is None or not same_requirement(acc, authorized):
                await self._push_confirmed("fail", [self.cfg.agent, row["id"], "vendor price or terms changed"])
                self.journal.update(j["nonce"], phase="failed", error="vendor price or terms changed")
                continue
            result = await self._pay(j["nonce"], row, j["url"], pr, acc)
            log.info("approved request %s: %s", row["id"], result["status"])

    async def reconcile(self):
        """Resolve interrupted payments (test T11) and expire stale requests."""
        for j in self.journal.by_phase("paid_not_recorded"):
            acc = json.loads(j["accepted"])
            res = await self._push_confirmed("settle", [self.cfg.agent, j["req_id"], acc["network"], j["ext_tx"]])
            if res["ok"]:
                self.journal.update(j["nonce"], phase="settled", error=None)
                continue
            row = await asyncio.to_thread(self.spring.req_by_id, j["req_id"])
            if row and row["status"] == 5 and row["ext_txid"].lower() == j["ext_tx"].lower():
                # Already recorded (e.g. by another process): nothing is wrong.
                self.journal.update(j["nonce"], phase="settled", error=None)
            elif any(m in res["error"] for m in SETTLE_PERMANENT):
                # The chain will never accept this settlement: stop retrying and flag it for a person.
                self.journal.update(j["nonce"], phase="needs_attention", error=res["error"])
                log.error("request %s: settlement refused permanently: %s", j["req_id"], res["error"])
        now = time.time()
        for j in self.journal.by_phase("payment_unknown", "paying", "authorized"):
            acc = json.loads(j["accepted"])
            # A signed x402 payment can still settle until maxTimeoutSeconds has passed, so a
            # payment in flight is never declared failed before then.
            if now - j["updated"] < int(acc.get("maxTimeoutSeconds", 300)) + 60:
                continue
            tx = j["ext_tx"]
            if not tx and j["base_block"]:   # a payment was started: look for it on the public chain
                # Exact: by the authorization nonce of each attempt. Fallback (journals written before
                # attempts were recorded): by amount and payee.
                for auth_nonce in json.loads(j.get("attempts") or "[]"):
                    tx = await asyncio.to_thread(self.base.authorization_used, self.payer.address, auth_nonce,
                                                 j["base_block"])
                    if tx:
                        break
                if not tx and not j.get("attempts"):
                    tx = await asyncio.to_thread(self.base.find_transfer, self.payer.address, acc["payTo"],
                                                 j["amount"], j["base_block"])
            if tx:
                ok, _ = await asyncio.to_thread(self.base.verify, tx, self.payer.address, acc["payTo"],
                                                j["amount"])
                if ok:
                    res = await self._push_confirmed("settle", [self.cfg.agent, j["req_id"], acc["network"], tx])
                    self.journal.update(j["nonce"], ext_tx=tx,
                                        phase="settled" if res["ok"] else "paid_not_recorded")
                    continue
            row = await asyncio.to_thread(self.spring.req_by_id, j["req_id"])
            if row and row["status"] in (1, 3):
                res = await self._push_confirmed("fail", [self.cfg.agent, j["req_id"], "no payment found"])
                self.journal.update(j["nonce"], phase="failed" if res["ok"] else j["phase"],
                                    error="no payment found on chain")
            elif row:
                self.journal.update(j["nonce"], phase=STATUS.get(row["status"], j["phase"]))
