"""Stand-in for the MPC network on the dev chain: one key per (requester, path), derived from a fixed
test secret, instead of key shares. Like the real nodes it signs a request only once the block that
recorded it is irreversible, and answers with mockmpc::respond.

    python tests/chain/mock_mpc_node.py                      # sign requests until stopped
    python tests/chain/mock_mpc_node.py address agentgov agent1   # register a key, print its address
(uses AGENTGOV_CLEOS / AGENTGOV_SSH, see devclient.py)
"""
import sys
import threading
import time

from eth_account import Account
from eth_utils import keccak

from devclient import DevClient

MPC = "mpc1"
SECRET = b"mock-mpc/v1/not-a-secret"


def key_for(requester, path):
    return Account.from_key(keccak(SECRET + requester.encode() + b"/" + path.encode()))


class MockMpcNode:
    def __init__(self, account=MPC):
        self.chain = DevClient(account)
        self.account = account

    def register(self, requester, path):
        """Publishes the address of (requester, path) on chain, as the real network's lookup would."""
        address = key_for(requester, path).address
        res = self.chain.push("setkey", [requester, path, address[2:].lower()], self.account)
        assert res["ok"], res
        return address

    def step(self):
        """Signs every irreversible, unanswered request once. Returns the ids it answered."""
        lib = self.chain.info()["last_irreversible_block_num"]
        done = {s["id"] for s in self.chain.table("signatures", limit=1000)}
        answered = []
        for q in self.chain.table("requests", limit=1000):
            if q["id"] in done or q["block"] > lib:
                continue
            sig = key_for(q["requester"], q["path"]).unsafe_sign_hash(bytes.fromhex(q["payload"]))
            res = self.chain.push("respond", [q["id"], f"{sig.r:064x}", f"{sig.s:064x}", sig.v], self.account)
            if res["ok"]:
                answered.append(q["id"])
        return answered

    def run(self, stop: threading.Event, poll=0.3):
        while not stop.is_set():
            self.step()
            time.sleep(poll)


if __name__ == "__main__":
    node = MockMpcNode()
    if sys.argv[1:2] == ["address"]:
        print(node.register(sys.argv[2], sys.argv[3]))
    else:
        node.run(threading.Event())
