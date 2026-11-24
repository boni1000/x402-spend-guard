"""Where PAYER_MODE=mpc gets its signatures: the MPC contract's signatures table.

Layout as Alcor announced it (2026-11-24): one row per answered request with r, s, v, looked up here
by the signed payload (secondary index 2), so the gateway needs neither the request id nor the
transaction trace. This is the one place to adapt when their contract is final.
"""
import asyncio
import time


class TableSignatures:
    def __init__(self, chain, poll=0.5):
        """chain: a table reader on the MPC contract (spend_guard.spring.Spring or alike)."""
        self.chain, self.poll = chain, poll

    def _lookup(self, digest):
        rows = self.chain.table("signatures", lower=digest, upper=digest, index=2, key_type="sha256", limit=1)
        return rows[0] if rows and rows[0]["payload"] == digest else None

    async def wait(self, request_id, digest, timeout):
        deadline = time.monotonic() + timeout
        while True:
            row = await asyncio.to_thread(self._lookup, digest)
            if row:
                return "0x" + row["r"] + row["s"] + f"{int(row['v']):02x}"
            if time.monotonic() > deadline:
                raise TimeoutError(f"no MPC signature for request {request_id} after {timeout:.0f} s")
            await asyncio.sleep(self.poll)
