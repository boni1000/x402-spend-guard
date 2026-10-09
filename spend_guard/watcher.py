#!/usr/bin/env python3
"""Always-on companion of the gateway: completes approved payments, resolves interrupted ones
and expires requests that nobody approved in time. One watcher per agent (same gateway.env)."""
import asyncio
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
for noisy in ("httpx", "web3", "urllib3"):
    logging.getLogger(noisy).setLevel(logging.WARNING)

from .gateway import Config, Gateway  # noqa: E402


async def run():
    gw = Gateway(Config.from_env())
    logging.getLogger("gateway").info("watcher started for %s", gw.cfg.agent)
    while True:
        try:
            await gw.process_approved()
            await gw.reconcile()
        except Exception:  # noqa: BLE001 - keep running
            logging.getLogger("gateway").exception("watcher step failed")
        await asyncio.sleep(5)


def main():
    asyncio.run(run())


if __name__ == "__main__":
    main()
