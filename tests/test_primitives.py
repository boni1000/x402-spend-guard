"""Name encoding and Merkle root, checked against known values."""
import hashlib

from spend_guard.auditor import merkle_root
from spend_guard.spring import name_to_u64


def test_antelope_name_encoding_matches_known_values():
    assert name_to_u64("eosio") == 6138663577826885632
    assert name_to_u64("eosio.token") == 6138663591592764928


def test_merkle_root_of_one_and_two_leaves():
    a, b = hashlib.sha256(b"a").hexdigest(), hashlib.sha256(b"b").hexdigest()
    assert merkle_root([a]) == a
    assert merkle_root([a, b]) == hashlib.sha256(bytes.fromhex(a) + bytes.fromhex(b)).hexdigest()


def test_merkle_root_duplicates_the_last_leaf_of_an_odd_level():
    leaves = [hashlib.sha256(x).hexdigest() for x in (b"a", b"b", b"c")]
    assert merkle_root(leaves) == merkle_root(leaves + [leaves[-1]])


def test_wait_included_retries_a_failed_read():
    import httpx
    from spend_guard.spring import Spring

    s = Spring("http://chain", "agentgov")
    calls = {"n": 0}

    def info():
        return {"head_block_num": 10}

    def post(path, body=None):
        calls["n"] += 1
        if calls["n"] == 1:   # a node that does not have the block yet, or a rate limit
            raise httpx.HTTPStatusError("429", request=httpx.Request("POST", "http://chain"),
                                        response=httpx.Response(429))
        return {"transactions": [{"trx": {"id": "abc"}}]} if body["block_num_or_id"] == 9 else {}

    s.info, s._post = info, post
    assert s.wait_included("abc", 9, timeout=5) == 9
