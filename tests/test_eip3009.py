"""contract/eip3009.hpp, compiled natively, checked against eth_account and the USDC contracts.

If agentgov's digest differs from what an EVM wallet signs by a single bit, the MPC signature is
useless, so every digest is compared with eth_account's own EIP-712 hash, and the domain separators
with the values the USDC contracts return on chain.
"""
import random
import shutil
import subprocess
from pathlib import Path

import pytest
from eth_account import Account
from eth_utils import keccak

ROOT = Path(__file__).resolve().parents[1]
CXX = shutil.which("c++") or shutil.which("clang++") or shutil.which("g++")

# name(), version() and DOMAIN_SEPARATOR() read from the USDC contracts (eth_call, 2026-11-24).
USDC = {
    84532: ("USDC", "2", "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
            "71f17a3b2ff373b803d70a5a07c046c1a2bc8e89c09ef722fcb047abe94c9818"),   # Base Sepolia
    8453: ("USD Coin", "2", "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
           "02fa7265e7c5d81118673727957699e4d68f74cd74b7db77da710fe8a2c7834f"),    # Base
}
NONCE_TAG = b"x402-spend-guard/eip3009-nonce/v1"


@pytest.fixture(scope="module")
def run(tmp_path_factory):
    if CXX is None:
        pytest.skip("no C++ compiler")
    exe = tmp_path_factory.mktemp("eip3009") / "eip3009_cli"
    subprocess.run([CXX, "-std=c++17", "-O1", "-Wall", "-Werror", f"-I{ROOT / 'contract'}",
                    str(ROOT / "tests/native/eip3009_cli.cpp"), "-o", str(exe)], check=True)

    def call(*lines):
        out = subprocess.run([str(exe)], input="".join("\t".join(map(str, ln)) + "\n" for ln in lines),
                             capture_output=True, text=True, check=True).stdout
        return out.splitlines()
    return call


def typed_data(chain_id, a):
    name, version, token, _ = USDC[chain_id]
    return {
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
        "domain": {"name": name, "version": version, "chainId": chain_id, "verifyingContract": token},
        "message": a,
    }


def test_keccak_reference_matches_ethereum(run):
    rnd = random.Random(1)
    blobs = [b"", b"abc"] + [rnd.randbytes(n) for n in (1, 31, 32, 135, 136, 137, 271, 272, 500)]
    assert run(*[("keccak", b.hex()) for b in blobs]) == [keccak(b).hex() for b in blobs]
    assert run(("keccak", ""))[0] == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"


@pytest.mark.parametrize("chain_id", sorted(USDC))
def test_digest_equals_what_an_evm_wallet_signs(run, chain_id):
    name, version, token, onchain_separator = USDC[chain_id]
    rnd = random.Random(chain_id)
    cases, lines = [], []
    for i in range(25):
        payer = Account.create(extra_entropy=str(rnd.random()))
        a = {"from": payer.address, "to": Account.create(extra_entropy=str(rnd.random())).address,
             "value": [0, 1, 10_000, rnd.randrange(2**64)][i % 4],
             "validAfter": rnd.randrange(2**32), "validBefore": [0, 2**64 - 1, rnd.randrange(2**40)][i % 3],
             "nonce": rnd.randbytes(32)}
        cases.append((payer, a))
        lines.append(("digest", name, version, chain_id, token, a["from"], a["to"], a["value"],
                      a["validAfter"], a["validBefore"], a["nonce"].hex()))
    for (payer, a), out in zip(cases, run(*lines), strict=True):
        separator, digest = out.split()
        assert separator == onchain_separator
        signed = Account.sign_typed_data(payer.key, full_message=typed_data(chain_id, a))
        assert digest == signed.message_hash.hex()


def test_request_nonce_is_keccak_of_tag_contract_and_id(run):
    pairs = [(0, 0), (1, 2), (6138663577826885632, 2**64 - 1), (6138663577826885632, 7)]
    got = run(*[("nonce", c, i) for c, i in pairs])
    assert got == [keccak(NONCE_TAG + c.to_bytes(8, "big") + i.to_bytes(8, "big")).hex() for c, i in pairs]
    assert len(set(got)) == len(got)


def test_address_parsing(run):
    ok = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"
    bad = [ok[:-1], ok + "0", ok.replace("0x", "1x"), ok[:-1] + "g", "", ok[2:] + "00"]
    assert run(("address", ok), ("address", "0X" + ok[2:].lower()), *[("address", b) for b in bad]) == \
        [ok[2:].lower()] * 2 + ["invalid"] * len(bad)
