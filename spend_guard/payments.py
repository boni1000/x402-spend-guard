"""x402 payments with explicit control, and verification of transfers on Base Sepolia.

The gateway must never pay before the chain has authorized the exact amount and recipient,
so it does not use the x402 client's automatic "on 402, pay" mode. It reads the price,
gets an authorization, then builds a payment for exactly the authorized requirement.

Two payers: X402Payer signs with a key held by the gateway; MpcPayer holds no key and sends an
authorization that agentgov built and the MPC network signed.
"""
import asyncio
from typing import Protocol

import httpx
from eth_account import Account
from eth_account.messages import encode_typed_data
from web3 import Web3

from x402 import x402Client
from x402.http import (decode_payment_required_header, decode_payment_response_header,
                       encode_payment_signature_header)
from x402.mechanisms.evm.exact.register import register_exact_evm_client
from x402.mechanisms.evm.types import ExactEIP3009Authorization, ExactEIP3009Payload
from x402.schemas import PaymentPayload

TRANSFER_TOPIC = Web3.keccak(text="Transfer(address,address,uint256)")
AUTH_USED_TOPIC = Web3.keccak(text="AuthorizationUsed(address,bytes32)")   # EIP-3009, emitted by USDC


def _pad(address):
    """32-byte topic encoding of an address, for log filters."""
    return "0x" + "0" * 24 + address.lower()[2:]


class PaymentNotSent(Exception):
    """The payment could not be created or signed, so nothing was sent to the vendor."""


def same_requirement(a, b):
    return (str(a.amount), a.pay_to.lower(), a.network.lower(), a.asset.lower(), a.scheme) == \
           (str(b.amount), b.pay_to.lower(), b.network.lower(), b.asset.lower(), b.scheme)


class _Quoting:
    network: str

    async def quote(self, url):
        """Unpaid request. Returns (PaymentRequired or None, response)."""
        async with httpx.AsyncClient(timeout=30) as c:
            r = await c.get(url)
        if r.status_code != 402:
            return None, r
        header = r.headers.get("PAYMENT-REQUIRED")
        if not header:
            raise ValueError("HTTP 402 without a PAYMENT-REQUIRED header")
        return decode_payment_required_header(header), r

    def choose(self, payment_required):
        for acc in payment_required.accepts:
            if acc.scheme == "exact" and acc.network == self.network:
                return acc
        return None

    @staticmethod
    async def _send(url, payload):
        async with httpx.AsyncClient(timeout=120) as c:
            r = await c.get(url, headers={"PAYMENT-SIGNATURE": encode_payment_signature_header(payload)})
        header = r.headers.get("PAYMENT-RESPONSE")
        return r, (decode_payment_response_header(header) if header else None)


class X402Payer(_Quoting):
    signs_on_chain = False

    def __init__(self, private_key, network):
        self.account = Account.from_key(private_key)
        self.network = network
        self.client = register_exact_evm_client(x402Client(), self.account, networks=network)

    def set_cap(self, max_usdc):
        """Local cap in the signing library (the x402 SDK defaults to $1 per payment). Set from the
        agent's on-chain per-payment limit: a second, independent layer under the chain policy."""
        self.client.set_spend_controls({"max_amount_per_payment": f"${max_usdc:.6f}"})

    @property
    def address(self):
        return self.account.address

    async def pay(self, url, payment_required, accepted, req_id=None):
        """Pay exactly `accepted` (already authorized on chain).
        Returns (response, settlement, authorization nonce of this attempt)."""
        only = payment_required.model_copy(update={"accepts": [accepted]})
        try:
            payload = await self.client.create_payment_payload(only)
        except Exception as e:  # noqa: BLE001 - nothing has been signed or sent
            raise PaymentNotSent(str(e)) from e
        if not same_requirement(payload.accepted, accepted):
            raise PaymentNotSent("payment payload does not match the authorized requirement")
        auth_nonce = (payload.payload.get("authorization") or {}).get("nonce")
        r, settle = await self._send(url, payload)
        return r, settle, auth_nonce


class Signatures(Protocol):
    async def wait(self, request_id: int, digest: str, timeout: float) -> str:
        """The MPC signature of `digest` (hex) as 0x-hex r || s || v; raises TimeoutError."""


def authorization_digest(net, auth):
    """EIP-712 digest of an EIP-3009 authorization in the token domain of an agentgov evmnets row,
    as (SignableMessage, digest bytes)."""
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
        "domain": {"name": net["token_name"], "version": net["token_version"], "chainId": int(net["chain_id"]),
                   "verifyingContract": Web3.to_checksum_address(net["token"])},
        "message": {"from": auth.from_address, "to": auth.to, "value": int(auth.value),
                    "validAfter": int(auth.valid_after), "validBefore": int(auth.valid_before),
                    "nonce": bytes.fromhex(auth.nonce.removeprefix("0x"))},
    })
    return msg, Web3.keccak(b"\x19" + msg.version + msg.header + msg.body)


class MpcPayer(_Quoting):
    """Pays with an authorization that agentgov builds and the MPC network signs; holds no key.

    agentgov::requestsig fixes payer, recipient, amount, validBefore and nonce from the contract's own
    tables. This class checks that what was signed is what the vendor asked for, waits for the
    signature, checks it, and sends it. Once requestsig has run the signature is a payment, whether or
    not it is ever delivered, so no later error is reported as PaymentNotSent.
    """
    signs_on_chain = True

    def __init__(self, spring, agent, permission, network, signatures: Signatures, timeout=60):
        self.spring, self.agent, self.permission, self.network = spring, agent, permission, network
        self.signatures, self.timeout = signatures, timeout
        rows = spring.table("payers", lower=agent, upper=agent, limit=1)
        if not rows:
            raise ValueError(f"agentgov has no payer address for {agent} (setpayer)")
        self.address = Web3.to_checksum_address(rows[0]["address"])
        self._signed = {}   # request id -> PaymentPayload: a retry resends the same authorization

    def set_cap(self, max_usdc):
        """Nothing to set: the contract builds every authorization, so its limits are the cap."""

    def _evmnet(self, network):
        if not network.startswith("eip155:"):
            return None
        chain_id = int(network.split(":", 1)[1])
        rows = self.spring.table("evmnets", lower=chain_id, upper=chain_id, limit=1)
        return rows[0] if rows else None

    def _sigreq(self, req_id):
        rows = self.spring.table("sigreqs", lower=req_id, upper=req_id, limit=1)
        return rows[0] if rows else None

    async def _signed_payload(self, payment_required, accepted, req_id):
        if payment_required.x402_version != 2:
            raise PaymentNotSent("MPC signing supports x402 version 2 only")
        net = await asyncio.to_thread(self._evmnet, accepted.network)
        extra = accepted.extra or {}
        if net is None:
            raise PaymentNotSent(f"agentgov does not sign for {accepted.network}")
        if (accepted.asset.lower() != net["token"] or extra.get("name", net["token_name"]) != net["token_name"]
                or extra.get("version", net["token_version"]) != net["token_version"]):
            raise PaymentNotSent("the vendor asks for a token other than the one agentgov signs for")

        row = await asyncio.to_thread(self._sigreq, req_id)
        if row is None:
            res = await asyncio.to_thread(self.spring.push, "requestsig", [self.agent, req_id], self.agent,
                                          self.permission)
            if res["ok"]:
                await asyncio.to_thread(self.spring.wait_included, res["trx_id"], res["block_num"])
            row = await asyncio.to_thread(self._sigreq, req_id)   # the table decides, not the push result
            if row is None:
                if not res["ok"]:
                    raise PaymentNotSent(f"signature not requested: {res['error']}")
                raise RuntimeError("signature requested but not visible on chain yet")

        if (row["payer"] != self.address.lower() or row["pay_to"] != accepted.pay_to.lower()
                or int(row["value"]) != int(accepted.amount) or row["network"] != accepted.network.lower()):
            raise RuntimeError("agentgov signed an authorization that differs from the vendor's requirement")
        auth = ExactEIP3009Authorization(from_address=self.address, to=accepted.pay_to, value=str(row["value"]),
                                         valid_after="0", valid_before=str(row["valid_before"]),
                                         nonce="0x" + row["nonce"])
        msg, digest = authorization_digest(net, auth)
        if digest.hex().removeprefix("0x") != row["digest"]:
            raise RuntimeError("agentgov's digest differs from the EIP-712 digest of its own authorization")

        sig = bytes.fromhex((await self.signatures.wait(req_id, row["digest"], self.timeout)).removeprefix("0x"))
        if len(sig) != 65:
            raise RuntimeError("signature is not 65 bytes")
        if sig[64] < 27:   # USDC's ecrecover wants v = 27 or 28
            sig = sig[:64] + bytes([sig[64] + 27])
        if Account.recover_message(msg, signature=sig) != self.address:
            raise RuntimeError("the signature does not belong to the payer address")
        inner = ExactEIP3009Payload(authorization=auth, signature="0x" + sig.hex()).to_dict()
        return PaymentPayload(x402_version=2, payload=inner, accepted=accepted, resource=payment_required.resource)

    async def pay(self, url, payment_required, accepted, req_id=None):
        """Request (once) and send the MPC-signed authorization for request `req_id`.
        Returns (response, settlement, authorization nonce)."""
        if req_id not in self._signed:
            self._signed[req_id] = await self._signed_payload(payment_required, accepted, req_id)
        payload = self._signed[req_id]
        r, settle = await self._send(url, payload)
        return r, settle, payload.payload["authorization"]["nonce"]


class BaseVerifier:
    """Checks USDC transfers on the public chain. Reads at explicit blocks: the public RPC is
    load-balanced and "latest" can be stale (Spike A lesson)."""

    def __init__(self, rpc, usdc):
        self.w3 = Web3(Web3.HTTPProvider(rpc, request_kwargs={"timeout": 30}))
        self.usdc = Web3.to_checksum_address(usdc)

    def block_number(self):
        return self.w3.eth.block_number

    def _matches(self, log, payer, pay_to, amount):
        return (log["address"].lower() == self.usdc.lower() and len(log["topics"]) == 3
                and log["topics"][0] == TRANSFER_TOPIC
                and "0x" + log["topics"][1].hex()[-40:] == payer.lower()
                and "0x" + log["topics"][2].hex()[-40:] == pay_to.lower()
                and int(log["data"].hex(), 16) == int(amount))

    def verify(self, tx_hash, payer, pay_to, amount):
        """True if tx succeeded and contains a USDC transfer payer -> pay_to of exactly amount."""
        rcpt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
        if rcpt.status != 1:
            return False, rcpt.blockNumber
        return any(self._matches(lg, payer, pay_to, amount) for lg in rcpt.logs), rcpt.blockNumber

    def transfers(self, payer, from_block, to_block=None, pay_to=None, chunk=50):
        """USDC transfers out of `payer` (optionally to `pay_to`) as {tx_hash: (to, amount, block)}.
        Queried in small block ranges: the public RPC refuses large log queries (HTTP 413)."""
        topics = [TRANSFER_TOPIC, _pad(payer)] + ([_pad(pay_to)] if pay_to else [])
        to_block = to_block or self.block_number()
        out = {}
        for start in range(int(from_block), int(to_block) + 1, chunk):
            for lg in self.w3.eth.get_logs({"address": self.usdc, "fromBlock": start,
                                            "toBlock": min(start + chunk - 1, int(to_block)), "topics": topics}):
                tx = "0x" + lg["transactionHash"].hex().removeprefix("0x").lower()
                out[tx] = ("0x" + lg["topics"][2].hex()[-40:], int(lg["data"].hex(), 16), lg["blockNumber"])
        return out

    def authorization_used(self, authorizer, nonce, from_block, chunk=50):
        """Tx hash in which this EIP-3009 authorization was executed, or None. Exact: identifies one
        specific signed payment, unlike matching on amount and recipient."""
        latest = self.block_number()
        for start in range(int(from_block), latest + 1, chunk):
            for lg in self.w3.eth.get_logs({"address": self.usdc, "fromBlock": start,
                                            "toBlock": min(start + chunk - 1, latest),
                                            "topics": [AUTH_USED_TOPIC, _pad(authorizer), nonce]}):
                return "0x" + lg["transactionHash"].hex().removeprefix("0x").lower()
        return None

    def find_transfer(self, payer, pay_to, amount, from_block):
        """Find a matching transfer since from_block (used by the reconciler)."""
        for tx, (_, value, _) in self.transfers(payer, from_block, pay_to=pay_to).items():
            if value == int(amount):
                return tx
        return None
