"""The whole keyless path on the dev chain: agentgov::requestsig -> inline mockmpc::sign -> the mock MPC
node signs once the block is irreversible -> mockmpc::respond (checked on chain) -> the gateway's
MpcPayer reads the signature with TableSignatures and builds the x402 payment.

Skipped unless AGENTGOV_CLEOS is set (see devclient.py). With AGENTGOV_FACILITATOR=1 the payment is
also checked by the x402.org facilitator (no money moves; the stand-in payer holds no USDC).
"""
import asyncio
import os
import random
import threading
import time

import pytest
from x402.schemas import PaymentRequired, PaymentRequirements, ResourceInfo

from devclient import CLEOS, ChainError, DevClient, cleos
from mock_mpc_node import MPC, MockMpcNode, key_for
from spend_guard.mpc import TableSignatures
from spend_guard.payments import MpcPayer

pytestmark = pytest.mark.skipif(not CLEOS, reason="set AGENTGOV_CLEOS to run against a dev chain")

ADMIN, ATTESTER, APPROVER = "admin1", "attester1", "approver1"
NET, USDC = "eip155:84532", "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
VENDOR = "0x2222222222222222222222222222222222222222"
DEV_KEY = "EOS6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV"


@pytest.fixture(scope="module")
def setup():
    gov = DevClient("agentgov")
    assert gov.push("setmpc", [MPC, 120, ATTESTER], ADMIN)["ok"]
    assert gov.push("setevmnet", [NET, USDC, "USDC", "2"], ADMIN)["ok"]
    res = gov.push("addvendor", [NET, VENDOR, "e2e vendor"], ADMIN)
    assert res["ok"] or "already registered" in res["error"]
    vendor = next(v["id"] for v in gov.table("vendors", limit=1000) if v["pay_to"] == VENDOR.lower())
    node = MockMpcNode()
    stop = threading.Event()
    thread = threading.Thread(target=node.run, args=(stop,), daemon=True)
    thread.start()
    yield {"gov": gov, "node": node, "vendor": vendor}
    stop.set()
    thread.join(timeout=5)


def new_agent(setup):
    """A fresh agent with its MPC address registered as agentgov's payer for it."""
    agent = "e" + "".join(random.choice("abcdefghijklmnopqrstuvwxyz12345") for _ in range(11))
    cleos("create", "account", "eosio", agent, DEV_KEY, DEV_KEY)
    gov = setup["gov"]
    assert gov.push("regagent", [agent, ADMIN, "00" * 32, agent], ADMIN)["ok"]
    assert gov.push("setpolicy", [agent, 1_000_000, 50_000_000, 500_000, APPROVER], ADMIN)["ok"]
    address = setup["node"].register("agentgov", agent)
    assert gov.push("setpayer", [agent, address], ADMIN)["ok"]
    return agent, address


def requirement(amount):
    acc = PaymentRequirements(scheme="exact", network=NET, asset=USDC, amount=str(amount), pay_to=VENDOR,
                              max_timeout_seconds=300, extra={"name": "USDC", "version": "2"})
    return PaymentRequired(x402_version=2, accepts=[acc], resource=ResourceInfo(url="https://example.com/x")), acc


def test_keyless_payment_signed_by_the_mpc_stand_in(setup):
    agent, address = new_agent(setup)
    gov = setup["gov"]
    res = gov.push("authorize", [agent, setup["vendor"], 10_000, "00" * 32, random.getrandbits(63)], agent)
    req_id = res["return"]["id"]
    payer = MpcPayer(gov, agent, "active", NET, TableSignatures(DevClient(MPC)), timeout=30)
    assert payer.address == address
    pr, acc = requirement(10_000)
    t0 = time.monotonic()
    payload = asyncio.run(payer._signed_payload(pr, acc, req_id))   # checks the signature against the payer
    took = time.monotonic() - t0
    auth = payload.payload["authorization"]
    assert (auth["from"], auth["to"], auth["value"]) == (address, VENDOR, "10000")
    request = next(q for q in DevClient(MPC).table("requests", limit=1000)
                   if q["payload"] == gov.table("sigreqs", lower=req_id, upper=req_id)[0]["digest"])
    assert (request["requester"], request["path"]) == ("agentgov", agent)
    print(f"\nrequestsig -> MPC signature -> payload: {took:.1f} s")

    if os.environ.get("AGENTGOV_FACILITATOR"):
        from x402.http import FacilitatorConfig, HTTPFacilitatorClient
        facilitator = HTTPFacilitatorClient(FacilitatorConfig(url="https://x402.org/facilitator"))
        v = asyncio.run(facilitator.verify(payload, acc))
        assert v.invalid_reason == "invalid_exact_evm_insufficient_balance", v


def test_mpc_contract_refuses_a_signature_from_another_key(setup):
    agent, _ = new_agent(setup)
    other, _ = new_agent(setup)
    mpc = DevClient(MPC)
    res = mpc.push("sign", ["agentgov", agent, "ab" * 32, 0], "agentgov")
    assert res["ok"], res
    sig = key_for("agentgov", other).unsafe_sign_hash(bytes.fromhex("ab" * 32))
    with pytest.raises(ChainError, match="does not match the derived key"):
        cleos("push", "action", MPC, "respond", f'[{res["return"]},"{sig.r:064x}","{sig.s:064x}",{sig.v}]',
              "-p", f"{MPC}@active", "-j")


def test_only_the_requester_can_ask_for_its_signatures(setup):
    agent, _ = new_agent(setup)
    res = DevClient(MPC).push("sign", ["agentgov", agent, "cd" * 32, 0], agent)
    assert not res["ok"] and "missing authority of agentgov" in res["error"]


def test_agentgov_account_key_can_also_request_signatures(setup):
    """Documents the point made to Alcor: require_auth(requester) is met by agentgov's own account
    key as well as by its code, so on a mainnet agentgov@active must be eosio.code plus a multisig."""
    agent, _ = new_agent(setup)
    assert DevClient(MPC).push("sign", ["agentgov", agent, "ef" * 32, 0], "agentgov")["ok"]
