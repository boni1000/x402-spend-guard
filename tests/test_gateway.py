"""Gateway logic tests with a simulated chain and payer (no network, no keys)."""
import asyncio
import json
from types import SimpleNamespace

from spend_guard.gateway import Gateway, Config
from spend_guard.journal import Journal
from spend_guard.payments import PaymentNotSent, same_requirement
from x402.schemas import PaymentRequired, PaymentRequirements

VENDOR = "0x00000000000000000000000000000000000000A1"
OTHER = "0x00000000000000000000000000000000000000B2"
USDC = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
NET = "eip155:84532"


def req(amount, pay_to=VENDOR):
    return PaymentRequirements(scheme="exact", network=NET, asset=USDC, amount=str(amount), pay_to=pay_to,
                               max_timeout_seconds=300, extra={})


class FakeChain:
    """Minimal agentgov: per-payment/daily limits, approval threshold, whitelist, nonces."""

    def __init__(self, per_tx=2_000_000, daily=3_000_000, threshold=1_000_000):
        self.policy = {"agent": "agent1", "per_tx_max": per_tx, "daily_max": daily,
                       "approval_threshold": threshold, "approver": "alice"}
        self.vendors = [{"id": 0, "network": NET.lower(), "pay_to": VENDOR.lower(), "active": 1}]
        self.reqs, self.committed, self.pushes = [], 0, []

    def table(self, name, **kw):
        return {"vendors": self.vendors, "policies": [self.policy],
                "config": [{"day_sec": 86400}], "spend": [{"committed": self.committed}]}[name]

    def push(self, action, data, actor, permission):
        self.pushes.append((action, data))
        if action == "authorize":
            agent, vendor_id, amount, _, nonce = data
            if amount > self.policy["per_tx_max"]:
                return {"ok": False, "error": "amount exceeds per-payment limit"}
            if self.committed + amount > self.policy["daily_max"]:
                return {"ok": False, "error": "daily limit exceeded"}
            self.committed += amount
            status = 2 if amount > self.policy["approval_threshold"] else 1
            self.reqs.append({"id": len(self.reqs), "agent": agent, "amount": amount, "nonce": nonce,
                              "status": status, "expires": "2099-01-01T00:00:00", "ext_txid": ""})
        elif action == "settle":
            r = self.reqs[data[1]]
            r["status"], r["ext_txid"] = 5, data[3].lower()
        elif action == "fail":
            r = self.reqs[data[1]]
            r["status"] = 6
            self.committed -= r["amount"]
        return {"ok": True, "trx_id": f"trx{len(self.pushes)}", "block_num": 1, "return": None}

    def wait_included(self, trx_id, start_block, timeout=None):
        return 1

    def wait_irreversible(self, block_num, timeout=None):
        return True

    def req_by_nonce(self, agent, nonce):
        return next((r for r in self.reqs if r["nonce"] == nonce), None)

    def req_by_id(self, i):
        return self.reqs[i] if i < len(self.reqs) else None

    def info(self):
        return {"head_block_time": "2026-01-01T00:00:00.000", "head_block_num": 1, "last_irreversible_block_num": 1}


class FakePayer:
    address = "0x00000000000000000000000000000000000000C3"

    def __init__(self, price, pay_to=VENDOR, outcomes=None):
        self.price, self.pay_to = price, pay_to
        self.outcomes = list(outcomes or ["ok"])
        self.paid = []

    async def quote(self, url):
        if url.endswith("/free"):
            return None, SimpleNamespace(status_code=200, text="free content")
        return PaymentRequired(x402_version=2, accepts=[req(self.price, self.pay_to)]), None

    def choose(self, pr):
        return pr.accepts[0]

    async def pay(self, url, pr, acc):
        outcome = self.outcomes.pop(0) if self.outcomes else "ok"
        nonce = "0x" + f"{len(self.paid):064x}"
        self.paid.append(outcome)
        if outcome == "not_sent":
            raise PaymentNotSent("simulated")
        if outcome == "refused":
            return (SimpleNamespace(status_code=402, text=""),
                    SimpleNamespace(success=False, error_reason="invalid_exact_evm_transaction_failed",
                                    error_message="", transaction=""), nonce)
        return (SimpleNamespace(status_code=200, text="paid content"),
                SimpleNamespace(success=True, transaction="0x" + "ab" * 32, error_reason=None), nonce)


class FakeBase:
    def __init__(self, verified=True, used=None):
        self.verified, self.used, self.searched = verified, used or {}, []

    def block_number(self):
        return 100

    def verify(self, tx, payer, pay_to, amount):
        return self.verified, 101

    def authorization_used(self, authorizer, nonce, from_block):
        self.searched.append(("nonce", nonce, from_block))
        return self.used.get(nonce)

    def find_transfer(self, payer, pay_to, amount, from_block):
        self.searched.append(("transfer", amount, from_block))
        return None


def make_gateway(tmp_path, chain, payer, base=None):
    gw = Gateway.__new__(Gateway)
    gw.cfg = Config("http://chain", "agentgov", "agent1", "gw", "w", "pw", NET, "http://rpc", USDC, "0x0",
                    str(tmp_path / "journal.sqlite"))
    gw.spring, gw.payer, gw.base = chain, payer, base or FakeBase()
    gw.journal = Journal(gw.cfg.journal_path)
    return gw


async def test_normal_payment_is_authorized_paid_and_settled(tmp_path):
    chain = FakeChain()
    gw = make_gateway(tmp_path, chain, FakePayer(10_000))
    res = await gw.paid_fetch("http://vendor/item", 0.05)
    assert res["status"] == "paid" and res["content"] == "paid content"
    assert [a for a, _ in chain.pushes] == ["authorize", "settle"]
    assert chain.reqs[0]["status"] == 5 and chain.reqs[0]["ext_txid"] == "0x" + "ab" * 32


async def test_price_above_max_price_is_refused_without_touching_the_chain(tmp_path):
    chain = FakeChain()
    res = await make_gateway(tmp_path, chain, FakePayer(10_000)).paid_fetch("http://vendor/item", 0.005)
    assert res["status"] == "refused" and chain.pushes == []


async def test_vendor_not_on_whitelist_is_refused(tmp_path):
    chain = FakeChain()
    res = await make_gateway(tmp_path, chain, FakePayer(10_000, pay_to=OTHER)).paid_fetch("http://vendor/x", 1)
    assert res["status"] == "refused" and "whitelist" in res["reason"] and chain.pushes == []


async def test_chain_refusal_is_reported(tmp_path):
    chain = FakeChain(per_tx=2_000_000)
    res = await make_gateway(tmp_path, chain, FakePayer(2_500_000)).paid_fetch("http://vendor/item", 5)
    assert res["status"] == "refused" and "per-payment limit" in res["reason"]


async def test_daily_limit_stops_further_purchases(tmp_path):
    chain = FakeChain(per_tx=500_000, daily=1_000_000, threshold=400_000)
    gw = make_gateway(tmp_path, chain, FakePayer(300_000))
    results = [await gw.paid_fetch("http://vendor/item", 0.3) for _ in range(4)]
    assert [r["status"] for r in results] == ["paid", "paid", "paid", "refused"]
    assert "daily limit" in results[3]["reason"]


async def test_payment_above_threshold_waits_for_approval(tmp_path):
    chain = FakeChain()
    payer = FakePayer(1_500_000)
    res = await make_gateway(tmp_path, chain, payer).paid_fetch("http://vendor/report", 2)
    assert res["status"] == "pending_approval" and payer.paid == []


async def test_refused_payment_is_retried_after_checking_it_was_not_executed(tmp_path):
    chain = FakeChain()
    payer = FakePayer(10_000, outcomes=["refused", "ok"])
    res = await make_gateway(tmp_path, chain, payer).paid_fetch("http://vendor/item", 0.05)
    assert res["status"] == "paid" and res["attempts"] == 2


async def test_payment_not_sent_fails_the_request_and_releases_budget(tmp_path):
    chain = FakeChain()
    res = await make_gateway(tmp_path, chain, FakePayer(10_000, outcomes=["not_sent"])).paid_fetch("http://v/i", 1)
    assert res["status"] == "failed" and chain.reqs[0]["status"] == 6 and chain.committed == 0


async def test_unverifiable_transfer_is_not_recorded_as_settled(tmp_path):
    chain = FakeChain()
    gw = make_gateway(tmp_path, chain, FakePayer(10_000), base=FakeBase(verified=False))
    res = await gw.paid_fetch("http://vendor/item", 0.05)
    assert res["status"] == "unknown" and all(a != "settle" for a, _ in chain.pushes)


async def test_free_resource_needs_no_payment(tmp_path):
    chain = FakeChain()
    res = await make_gateway(tmp_path, chain, FakePayer(10_000)).paid_fetch("http://vendor/free", 1)
    assert res["status"] == "free" and chain.pushes == []


def test_same_requirement_ignores_address_case():
    a = req(10_000, VENDOR)
    b = req(10_000, VENDOR.lower())
    assert same_requirement(a, b) and not same_requirement(a, req(20_000))


def test_journal_keeps_attempt_nonces(tmp_path):
    j = Journal(str(tmp_path / "j.sqlite"))
    j.insert(1, "agent1", "http://x", {"a": 1}, 10, 0, "authorizing")
    j.update(1, attempts=json.dumps(["0x1", "0x2"]))
    assert json.loads(j.get(1)["attempts"]) == ["0x1", "0x2"]


def test_journal_claim_succeeds_only_once(tmp_path):
    path = str(tmp_path / "j.sqlite")
    a, b = Journal(path), Journal(path)   # two processes sharing one journal
    a.insert(1, "agent1", "http://x", {}, 10, 0, "pending_approval")
    assert a.claim(1, "pending_approval", "authorized") is True
    assert b.claim(1, "pending_approval", "authorized") is False
    assert b.get(1)["phase"] == "authorized"


async def test_approved_payment_is_paid_once_by_two_watchers(tmp_path):
    chain = FakeChain()
    payer = FakePayer(1_500_000)
    gw1 = make_gateway(tmp_path, chain, payer)
    res = await gw1.paid_fetch("http://vendor/report", 2)
    assert res["status"] == "pending_approval"
    chain.reqs[0]["status"] = 3                      # approved
    gw2 = make_gateway(tmp_path, chain, payer)       # second process, same journal
    await asyncio.gather(gw1.process_approved(), gw2.process_approved())   # both see the approval
    assert payer.paid == ["ok"] and chain.reqs[0]["status"] == 5


def _stale(gw, nonce, **fields):
    """Make a journal entry look older than the x402 payment window."""
    gw.journal.update(nonce, **fields)
    gw.journal.db.execute("update requests set updated = updated - 1000 where nonce = ?", (nonce,))
    gw.journal.db.commit()


async def test_reconciler_settles_an_interrupted_payment_found_by_its_nonce(tmp_path):
    chain = FakeChain()
    tx = "0x" + "cd" * 32
    base = FakeBase(used={"0xaa": tx})
    gw = make_gateway(tmp_path, chain, FakePayer(10_000), base=base)
    chain.push("authorize", ["agent1", 0, 10_000, "", 7], "agent1", "gw")
    gw.journal.insert(7, "agent1", "http://vendor/item", req(10_000).model_dump(mode="json", by_alias=True),
                      10_000, 0, "authorizing")
    _stale(gw, 7, req_id=0, phase="payment_unknown", base_block=100, attempts=json.dumps(["0xaa"]))
    await gw.reconcile()
    assert gw.journal.get(7)["phase"] == "settled" and chain.reqs[0]["ext_txid"] == tx
    assert ("nonce", "0xaa", 100) in base.searched and not any(s[0] == "transfer" for s in base.searched)


async def test_reconciler_does_not_search_the_chain_when_no_payment_was_started(tmp_path):
    chain = FakeChain()
    base = FakeBase()
    gw = make_gateway(tmp_path, chain, FakePayer(10_000), base=base)
    chain.push("authorize", ["agent1", 0, 10_000, "", 8], "agent1", "gw")
    gw.journal.insert(8, "agent1", "http://vendor/item", req(10_000).model_dump(mode="json", by_alias=True),
                      10_000, 0, "authorizing")
    _stale(gw, 8, req_id=0, phase="authorized")      # claimed, but the process stopped before paying
    await gw.reconcile()
    assert base.searched == [] and gw.journal.get(8)["phase"] == "failed" and chain.committed == 0


async def test_permanent_settle_error_stops_retries(tmp_path):
    chain = FakeChain()
    gw = make_gateway(tmp_path, chain, FakePayer(10_000))
    gw.journal.insert(9, "agent1", "http://vendor/item", req(10_000).model_dump(mode="json", by_alias=True),
                      10_000, 0, "authorizing")
    gw.journal.update(9, req_id=0, phase="paid_not_recorded", ext_tx="0x" + "ef" * 32)

    async def refuse(action, data):
        return {"ok": False, "error": "assertion failure with message: transaction already recorded"}
    gw._push_confirmed = refuse
    await gw.reconcile()
    assert gw.journal.get(9)["phase"] == "needs_attention"


async def test_settlement_recorded_by_another_process_is_not_flagged(tmp_path):
    chain = FakeChain()
    tx = "0x" + "ef" * 32
    gw = make_gateway(tmp_path, chain, FakePayer(10_000))
    chain.push("authorize", ["agent1", 0, 10_000, "", 10], "agent1", "gw")
    chain.push("settle", ["agent1", 0, NET, tx], "agent1", "gw")    # the other process was faster
    gw.journal.insert(10, "agent1", "http://vendor/item", req(10_000).model_dump(mode="json", by_alias=True),
                      10_000, 0, "authorizing")
    gw.journal.update(10, req_id=0, phase="paid_not_recorded", ext_tx=tx)

    async def refuse(action, data):
        return {"ok": False, "error": "assertion failure with message: request is not authorized for payment"}
    gw._push_confirmed = refuse
    await gw.reconcile()
    assert gw.journal.get(10)["phase"] == "settled"
