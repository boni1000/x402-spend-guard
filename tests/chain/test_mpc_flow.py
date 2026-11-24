"""agentgov's MPC signing flow on a live dev chain (tests/chain/devchain.sh).

Skipped unless AGENTGOV_CLEOS is set, e.g.
    AGENTGOV_SSH=myhost AGENTGOV_CLEOS="~/spring/bin/cleos -u http://127.0.0.1:18888 --wallet-url http://127.0.0.1:18900"
The requestsig digest is compared with eth_account's EIP-712 hash, so a digest that differs from
what an EVM wallet signs fails here, not on Base.
"""
import json
import os
import random
import shlex
import subprocess
import time
from pathlib import Path

import pytest
from eth_account import Account
from eth_account.messages import encode_typed_data
from eth_utils import keccak

from spend_guard.spring import name_to_u64

CLEOS = os.environ.get("AGENTGOV_CLEOS")
SSH = os.environ.get("AGENTGOV_SSH")
pytestmark = pytest.mark.skipif(not CLEOS, reason="set AGENTGOV_CLEOS to run against a dev chain")

CONTRACT, ADMIN, APPROVER, ATTESTER = "agentgov", "admin1", "approver1", "attester1"
NETWORK, USDC, TOKEN_NAME = "eip155:84532", "0x036CbD53842c5426634e7929541eC2318f3dCF7e", "USDC"
VENDOR = "0x1111111111111111111111111111111111111111"
PAYER = Account.from_key(keccak(b"agentgov devchain payer"))   # stands in for the MPC-derived key
SIG_TTL = 10
DEV_KEY = "EOS6MRyAjQq8ud7hVNYcfnVPJqcVpscN5So8BhtHuGYqET5GDW5CV"   # devchain.sh's well-known key
AUTHORIZED, PENDING, APPROVED, SETTLED, FAILED, SIGNED = 1, 2, 3, 5, 6, 8


class ChainError(Exception):
    pass


def cleos(*args):
    line = CLEOS + " " + " ".join(shlex.quote(str(a)) for a in args)
    if SSH:
        cmd = ["ssh", "-o", "ControlMaster=auto", "-o", f"ControlPath={Path.home()}/.ssh/agentgov-%C",
               "-o", "ControlPersist=120", SSH, line]
    else:
        cmd = ["bash", "-c", line]
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode != 0:
        try:   # with -j a refused transaction comes back as JSON on stdout
            stack = json.loads(p.stdout)["processed"]["except"]["stack"]
            raise ChainError(" | ".join(str(s.get("data", {}).get("s") or s.get("format", "")) for s in stack))
        except (ValueError, KeyError, TypeError):
            raise ChainError(p.stderr or p.stdout) from None
    return p.stdout


def push(action, data, actor):
    out = json.loads(cleos("push", "action", CONTRACT, action, json.dumps(data), "-p", f"{actor}@active", "-j"))
    return out["processed"]["action_traces"][0].get("return_value_data")


def refused(action, data, actor):
    with pytest.raises(ChainError) as e:
        push(action, data, actor)
    return str(e.value)


def rows(table, scope=CONTRACT, lower=None):
    args = ["get", "table", CONTRACT, scope, table, "-l", "1000"]
    if lower is not None:
        args += ["-L", lower, "-U", lower]
    return json.loads(cleos(*args))["rows"]


def payreq(i):
    return rows("payreqs", lower=i)[0]


def committed(agent):
    days = rows("spend", scope=agent)
    return max(days, key=lambda d: d["day"])["committed"] if days else 0


def authorize(agent, amount, vendor_id):
    res = push("authorize", [agent, vendor_id, amount, "00" * 32, random.getrandbits(63)], agent)
    return res["id"], res["status"]


def vendor_id(network, pay_to):
    return next(v["id"] for v in rows("vendors") if v["network"] == network and v["pay_to"] == pay_to.lower())


@pytest.fixture(scope="module")
def chain():
    push("init", [ADMIN, 86400, 300, 300], CONTRACT)
    for agent in ("agent1", "agent2"):
        push("regagent", [agent, ADMIN, "00" * 32, agent], ADMIN)
        push("setpolicy", [agent, 1_000_000, 50_000_000, 500_000, APPROVER], ADMIN)
    for network in (NETWORK, "eip155:1"):
        try:
            push("addvendor", [network, VENDOR, "test vendor"], ADMIN)
        except ChainError as e:
            assert "already registered" in str(e)
    push("setevmnet", [NETWORK, USDC, TOKEN_NAME, "2"], ADMIN)
    push("setmpc", ["", SIG_TTL, ATTESTER], ADMIN)
    push("setpayer", ["agent1", PAYER.address], ADMIN)
    return {"vendor": vendor_id(NETWORK, VENDOR), "mainnet_vendor": vendor_id("eip155:1", VENDOR)}


@pytest.fixture
def fresh_agent():
    """A new agent account with a policy but no payer address, so each run starts clean."""
    agent = "t" + "".join(random.choice("abcdefghijklmnopqrstuvwxyz12345") for _ in range(11))
    cleos("create", "account", "eosio", agent, DEV_KEY, DEV_KEY)
    push("regagent", [agent, ADMIN, "00" * 32, agent], ADMIN)
    push("setpolicy", [agent, 1_000_000, 50_000_000, 500_000, APPROVER], ADMIN)
    return agent


def expected_digest(value, valid_before, nonce):
    msg = encode_typed_data(full_message={
        "types": {
            "EIP712Domain": [{"name": "name", "type": "string"}, {"name": "version", "type": "string"},
                             {"name": "chainId", "type": "uint256"},
                             {"name": "verifyingContract", "type": "address"}],
            "TransferWithAuthorization": [
                {"name": "from", "type": "address"}, {"name": "to", "type": "address"},
                {"name": "value", "type": "uint256"}, {"name": "validAfter", "type": "uint256"},
                {"name": "validBefore", "type": "uint256"}, {"name": "nonce", "type": "bytes32"}],
        },
        "primaryType": "TransferWithAuthorization",
        "domain": {"name": TOKEN_NAME, "version": "2", "chainId": 84532, "verifyingContract": USDC},
        "message": {"from": PAYER.address, "to": VENDOR, "value": value, "validAfter": 0,
                    "validBefore": valid_before, "nonce": nonce},
    })
    return msg, keccak(b"\x19" + msg.version + msg.header + msg.body)


def test_requestsig_builds_what_an_evm_wallet_signs(chain):
    req_id, status = authorize("agent1", 10_000, chain["vendor"])
    assert status == AUTHORIZED
    res = push("requestsig", ["agent1", req_id], "agent1")
    nonce = keccak(b"x402-spend-guard/eip3009-nonce/v1" + name_to_u64(CONTRACT).to_bytes(8, "big") +
                   req_id.to_bytes(8, "big"))
    assert res["nonce"] == nonce.hex()
    msg, digest = expected_digest(10_000, res["valid_before"], nonce)
    assert res["digest"] == digest.hex()
    # A signature by the payer's key over this digest is what USDC accepts.
    assert Account.recover_message(msg, signature=Account.sign_message(msg, PAYER.key).signature) == PAYER.address
    s = rows("sigreqs", lower=req_id)[0]
    assert (s["network"], s["payer"], s["pay_to"], s["value"]) == (NETWORK, PAYER.address.lower(), VENDOR, 10_000)
    assert (s["digest"], s["valid_before"]) == (res["digest"], res["valid_before"])
    assert payreq(req_id)["status"] == SIGNED


def test_signed_request_keeps_its_budget_until_the_attester_reports_it_unused(chain):
    before = committed("agent1")
    req_id, _ = authorize("agent1", 20_000, chain["vendor"])
    res = push("requestsig", ["agent1", req_id], "agent1")
    assert committed("agent1") == before + 20_000
    assert "cannot be failed" in refused("fail", ["agent1", req_id, "gave up"], "agent1")
    assert "cannot expire" in refused("expire", [req_id], "agent1")
    assert "not authorized for payment" in refused("requestsig", ["agent1", req_id], "agent1")
    assert "not the attester" in refused("sigunused", ["agent1", req_id], "agent1")
    assert "still valid" in refused("sigunused", [ATTESTER, req_id], ATTESTER)
    time.sleep(max(0, res["valid_before"] - time.time()) + 2)
    push("sigunused", [ATTESTER, req_id], ATTESTER)
    assert payreq(req_id)["status"] == FAILED
    assert committed("agent1") == before


def test_signed_request_can_be_settled(chain):
    req_id, _ = authorize("agent1", 30_000, chain["vendor"])
    push("requestsig", ["agent1", req_id], "agent1")
    push("settle", ["agent1", req_id, NETWORK, "0x" + random.randbytes(32).hex()], "agent1")
    assert payreq(req_id)["status"] == SETTLED
    assert "not signed" in refused("sigunused", [ATTESTER, req_id], ATTESTER)


def test_pending_request_is_signed_only_after_approval(chain):
    req_id, status = authorize("agent1", 600_000, chain["vendor"])
    assert status == PENDING
    assert "not authorized for payment" in refused("requestsig", ["agent1", req_id], "agent1")
    push("approve", [APPROVER, req_id], APPROVER)
    push("requestsig", ["agent1", req_id], "agent1")
    assert payreq(req_id)["status"] == SIGNED


def test_requestsig_refusals(chain, fresh_agent):
    agent = fresh_agent
    req_id, _ = authorize(agent, 1_000, chain["vendor"])
    assert "not your request" in refused("requestsig", ["agent1", req_id], "agent1")
    assert "no payer address" in refused("requestsig", [agent, req_id], agent)
    push("setpayer", [agent, PAYER.address], ADMIN)
    push("revoke", [agent, "test"], ADMIN)
    try:
        assert "revoked" in refused("requestsig", [agent, req_id], agent)
    finally:
        push("reinstate", [agent], ADMIN)
    push("rmvendor", [chain["vendor"]], ADMIN)
    try:
        assert "not whitelisted" in refused("requestsig", [agent, req_id], agent)
    finally:
        push("addvendor", [NETWORK, VENDOR, "test vendor"], ADMIN)
    other, _ = authorize(agent, 1_000, chain["mainnet_vendor"])
    assert "network not configured" in refused("requestsig", [agent, other], agent)
    push("requestsig", [agent, req_id], agent)


def test_configuration_checks(chain):
    assert "agent cannot be the attester" in refused("setmpc", ["", SIG_TTL, "agent1"], ADMIN)
    assert "not an EVM network" in refused("setevmnet", ["base-sepolia", USDC, "USDC", "2"], ADMIN)
    assert "invalid EVM address" in refused("setpayer", ["agent1", "0x1234"], ADMIN)
    assert "authority" in refused("setpayer", ["agent1", PAYER.address], "agent1").lower()


def test_without_mpc_the_old_flow_is_unchanged(chain):
    before = committed("agent1")
    req_id, _ = authorize("agent1", 5_000, chain["vendor"])
    push("fail", ["agent1", req_id, "vendor down"], "agent1")
    assert payreq(req_id)["status"] == FAILED
    assert committed("agent1") == before
