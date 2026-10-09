"""x402 payments with explicit control, and verification of transfers on Base Sepolia.

The gateway must never pay before the chain has authorized the exact amount and recipient,
so it does not use the x402 client's automatic "on 402, pay" mode. It reads the price,
gets an authorization, then builds a payment for exactly the authorized requirement.
"""
import httpx
from eth_account import Account
from web3 import Web3

from x402 import x402Client
from x402.http import (decode_payment_required_header, decode_payment_response_header,
                       encode_payment_signature_header)
from x402.mechanisms.evm.exact.register import register_exact_evm_client

TRANSFER_TOPIC = Web3.keccak(text="Transfer(address,address,uint256)")
AUTH_USED_TOPIC = Web3.keccak(text="AuthorizationUsed(address,bytes32)")   # EIP-3009, emitted by USDC


class PaymentNotSent(Exception):
    """The payment could not be created or signed, so nothing was sent to the vendor."""


def same_requirement(a, b):
    return (str(a.amount), a.pay_to.lower(), a.network.lower(), a.asset.lower(), a.scheme) == \
           (str(b.amount), b.pay_to.lower(), b.network.lower(), b.asset.lower(), b.scheme)


class X402Payer:
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

    async def pay(self, url, payment_required, accepted):
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
        async with httpx.AsyncClient(timeout=120) as c:
            r = await c.get(url, headers={"PAYMENT-SIGNATURE": encode_payment_signature_header(payload)})
        header = r.headers.get("PAYMENT-RESPONSE")
        return r, (decode_payment_response_header(header) if header else None), auth_nonce


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
        pad = lambda a: "0x" + "0" * 24 + a.lower()[2:]
        topics = [TRANSFER_TOPIC, pad(payer)] + ([pad(pay_to)] if pay_to else [])
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
        pad = lambda a: "0x" + "0" * 24 + a.lower()[2:]
        latest = self.block_number()
        for start in range(int(from_block), latest + 1, chunk):
            for lg in self.w3.eth.get_logs({"address": self.usdc, "fromBlock": start,
                                            "toBlock": min(start + chunk - 1, latest),
                                            "topics": [AUTH_USED_TOPIC, pad(authorizer), nonce]}):
                return "0x" + lg["transactionHash"].hex().removeprefix("0x").lower()
        return None

    def find_transfer(self, payer, pay_to, amount, from_block):
        """Find a matching transfer since from_block (used by the reconciler)."""
        for tx, (_, value, _) in self.transfers(payer, from_block, pay_to=pay_to).items():
            if value == int(amount):
                return tx
        return None
