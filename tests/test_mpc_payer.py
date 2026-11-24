"""Gateway with PAYER_MODE=mpc: no payer key; agentgov builds the authorization, an MPC network signs
it. Simulated chain, signer and vendor (no network). The MPC network is stood in for by a local key."""
import time
from types import SimpleNamespace

from eth_account import Account
from eth_utils import keccak
from x402.http import decode_payment_signature_header, encode_payment_signature_header
from x402.schemas import PaymentRequired

from spend_guard.mpc import TableSignatures
from spend_guard.payments import MpcPayer, authorization_digest
from spend_guard.spring import name_to_u64
from test_gateway import NET, USDC, VENDOR, FakeBase, FakeChain, make_gateway, req
from x402.mechanisms.evm.types import ExactEIP3009Authorization

MPC_KEY = Account.from_key(keccak(b"stand-in for the MPC network"))
OTHER_KEY = Account.from_key(keccak(b"someone else"))
EVMNET = {"chain_id": 84532, "network": NET, "token": USDC.lower(), "token_name": "USDC", "token_version": "2"}


class MpcChain(FakeChain):
    """FakeChain plus agentgov's MPC tables and requestsig, built the way the contract builds it."""

    def __init__(self, **kw):
        super().__init__(**kw)
        self.payers = [{"agent": "agent1", "address": MPC_KEY.address.lower()}]
        self.evmnets = [EVMNET]
        self.sigreqs = []

    def table(self, name, lower=None, **kw):
        key = {"payers": "agent", "evmnets": "chain_id", "sigreqs": "id"}.get(name)
        if key is None:
            return super().table(name, **kw)
        rows = getattr(self, name)
        return [r for r in rows if lower is None or r[key] == lower]

    def push(self, action, data, actor, permission):
        if action != "requestsig":
            return super().push(action, data, actor, permission)
        self.pushes.append((action, data))
        r = self.reqs[data[1]]
        if r["status"] not in (1, 3):
            return {"ok": False, "error": "request is not authorized for payment"}
        nonce = keccak(b"x402-spend-guard/eip3009-nonce/v1" + name_to_u64("agentgov").to_bytes(8, "big")
                       + r["id"].to_bytes(8, "big"))
        valid_before = int(time.time()) + 120
        auth = ExactEIP3009Authorization(from_address=MPC_KEY.address, to=VENDOR, value=str(r["amount"]),
                                         valid_after="0", valid_before=str(valid_before), nonce="0x" + nonce.hex())
        _, digest = authorization_digest(EVMNET, auth)
        self.sigreqs.append({"id": r["id"], "network": NET, "payer": MPC_KEY.address.lower(),
                             "pay_to": VENDOR.lower(), "value": r["amount"], "valid_before": valid_before,
                             "nonce": nonce.hex(), "digest": digest.hex().removeprefix("0x")})
        r["status"] = 8
        return {"ok": True, "trx_id": "sig", "block_num": 1, "return": None}


class StandInMpc:
    """Signs whatever digest it is asked for, as the MPC network does for agentgov's requests."""

    def __init__(self, key=MPC_KEY):
        self.key, self.asked = key, []

    async def wait(self, request_id, digest, timeout):
        self.asked.append(request_id)
        return "0x" + bytes(self.key.unsafe_sign_hash(bytes.fromhex(digest)).signature).hex()


class VendorMpcPayer(MpcPayer):
    """MpcPayer with a simulated vendor: a 402 quote, then the outcomes in order."""

    def __init__(self, chain, price, signatures=None, outcomes=None, asset=USDC):
        super().__init__(chain, "agent1", "gw", NET, signatures or StandInMpc())
        self.price, self.asset, self.outcomes, self.sent = price, asset, list(outcomes or ["ok"]), []

    async def quote(self, url):
        acc = req(self.price).model_copy(update={"asset": self.asset, "extra": {"name": "USDC", "version": "2"}})
        return PaymentRequired(x402_version=2, accepts=[acc]), None

    async def _send(self, url, payload):
        # Round trip through the real header encoding, as the vendor would receive it.
        self.sent.append(decode_payment_signature_header(encode_payment_signature_header(payload)))
        if (self.outcomes.pop(0) if self.outcomes else "ok") == "refused":
            return (SimpleNamespace(status_code=402, text=""),
                    SimpleNamespace(success=False, error_reason="invalid_exact_evm_transaction_failed",
                                    error_message="", transaction=""))
        return (SimpleNamespace(status_code=200, text="paid content"),
                SimpleNamespace(success=True, transaction="0x" + "ab" * 32, error_reason=None))


def actions(chain):
    return [a for a, _ in chain.pushes]


async def test_mpc_payment_sends_the_contract_built_authorization_signed_for_the_payer(tmp_path):
    chain = MpcChain()
    payer = VendorMpcPayer(chain, 10_000)
    res = await make_gateway(tmp_path, chain, payer).paid_fetch("http://vendor/item", 0.05)
    assert res["status"] == "paid"
    assert actions(chain) == ["authorize", "requestsig", "settle"]
    sent, row = payer.sent[0], chain.sigreqs[0]
    auth = sent.payload["authorization"]
    assert (auth["from"], auth["to"].lower(), auth["value"]) == (MPC_KEY.address, VENDOR.lower(), "10000")
    assert (auth["validAfter"], auth["validBefore"], auth["nonce"]) == ("0", str(row["valid_before"]),
                                                                       "0x" + row["nonce"])
    msg, _ = authorization_digest(EVMNET, ExactEIP3009Authorization(
        from_address=auth["from"], to=auth["to"], value=auth["value"], valid_after=auth["validAfter"],
        valid_before=auth["validBefore"], nonce=auth["nonce"]))
    assert Account.recover_message(msg, signature=bytes.fromhex(sent.payload["signature"][2:])) == MPC_KEY.address


async def test_refused_payment_is_not_failed_once_signed(tmp_path):
    chain = MpcChain()
    gw = make_gateway(tmp_path, chain, VendorMpcPayer(chain, 10_000, outcomes=["refused"] * 3))
    res = await gw.paid_fetch("http://vendor/item", 0.05)
    assert res["status"] == "failed" and "stays reserved" in res["reason"]
    assert "fail" not in actions(chain) and chain.reqs[0]["status"] == 8
    assert gw.journal.by_req_id(0)["phase"] == "payment_unknown"


async def test_retry_resends_the_same_signed_authorization(tmp_path):
    chain = MpcChain()
    payer = VendorMpcPayer(chain, 10_000, outcomes=["refused", "ok"])
    res = await make_gateway(tmp_path, chain, payer).paid_fetch("http://vendor/item", 0.05)
    assert res["status"] == "paid" and res["attempts"] == 2
    assert actions(chain).count("requestsig") == 1
    assert payer.sent[0].payload == payer.sent[1].payload


async def test_other_token_is_refused_before_anything_is_signed(tmp_path):
    chain = MpcChain()
    payer = VendorMpcPayer(chain, 10_000, asset="0x" + "22" * 20)
    res = await make_gateway(tmp_path, chain, payer).paid_fetch("http://vendor/item", 0.05)
    assert res["status"] == "failed" and "token" in res["reason"]
    assert actions(chain) == ["authorize", "fail"] and chain.committed == 0 and payer.sent == []


async def test_signature_from_another_key_is_never_sent(tmp_path):
    chain = MpcChain()
    payer = VendorMpcPayer(chain, 10_000, signatures=StandInMpc(OTHER_KEY))
    res = await make_gateway(tmp_path, chain, payer).paid_fetch("http://vendor/item", 0.05)
    assert res["status"] == "unknown" and payer.sent == [] and "fail" not in actions(chain)


async def test_digest_that_differs_from_the_authorization_is_never_signed(tmp_path):
    chain = MpcChain()
    payer = VendorMpcPayer(chain, 10_000)
    original = chain.push

    def tampered(action, data, actor, permission):
        out = original(action, data, actor, permission)
        if action == "requestsig":
            chain.sigreqs[-1]["digest"] = "00" * 32
        return out
    chain.push = tampered
    res = await make_gateway(tmp_path, chain, payer).paid_fetch("http://vendor/item", 0.05)
    assert res["status"] == "unknown" and payer.signatures.asked == [] and payer.sent == []


async def test_reconciler_waits_for_valid_before_then_settles_or_leaves_it_to_the_attester(tmp_path):
    for used in (True, False):
        chain = MpcChain()
        payer = VendorMpcPayer(chain, 10_000, outcomes=["refused"] * 3)
        base = FakeBase()
        (tmp_path / str(used)).mkdir()
        gw = make_gateway(tmp_path / str(used), chain, payer, base=base)
        await gw.paid_fetch("http://vendor/item", 0.05)
        row = chain.sigreqs[0]
        if used:
            base.used["0x" + row["nonce"]] = "0x" + "cd" * 32
        await gw.reconcile()   # still valid: nothing is decided yet
        assert gw.journal.by_req_id(0)["phase"] == "payment_unknown" and actions(chain)[-1] == "requestsig"
        row["valid_before"] = int(time.time()) - 60
        await gw.reconcile()
        phase = gw.journal.by_req_id(0)["phase"]
        if used:
            assert phase == "settled" and actions(chain)[-1] == "settle"
        else:
            assert phase == "signed_unused" and "fail" not in actions(chain)


class SignaturesTable:
    def __init__(self, rows):
        self.rows, self.calls = rows, []

    def table(self, name, lower=None, upper=None, index=None, key_type=None, limit=100):
        self.calls.append((name, index, key_type))
        return [r for r in self.rows if r["payload"] >= lower][:limit]


async def test_table_signatures_finds_the_signature_by_its_payload():
    digest = "ab" * 32
    table = SignaturesTable([{"id": 7, "payload": digest, "r": "11" * 32, "s": "22" * 32, "v": 28}])
    sig = await TableSignatures(table).wait(3, digest, timeout=1)
    assert sig == "0x" + "11" * 32 + "22" * 32 + "1c"
    assert table.calls[0] == ("signatures", 2, "sha256")


async def test_table_signatures_ignores_a_neighbouring_payload_and_times_out():
    table = SignaturesTable([{"id": 7, "payload": "ac" * 32, "r": "11" * 32, "s": "22" * 32, "v": 27}])
    try:
        await TableSignatures(table, poll=0.05).wait(3, "ab" * 32, timeout=0.2)
    except TimeoutError:
        return
    raise AssertionError("expected TimeoutError")
