#!/usr/bin/env python3
"""MCP server exposing the governance gateway to an AI agent over stdio.

The agent starts this as a subprocess; it opens no network port. Logging goes to stderr only,
because stdout carries the MCP protocol.
"""
import asyncio
import logging
import sys
from contextlib import asynccontextmanager

logging.basicConfig(stream=sys.stderr, level=logging.INFO, format="%(asctime)s %(name)s %(message)s")

from mcp.server.mcpserver import MCPServer  # noqa: E402

from .gateway import Config, Gateway  # noqa: E402

gw = None


def gateway():
    global gw
    if gw is None:
        gw = Gateway(Config.from_env())
    return gw


async def background():
    while True:
        try:
            await gateway().process_approved()
            await gateway().reconcile()
        except Exception:  # noqa: BLE001 - keep the watcher alive
            logging.getLogger("gateway").exception("background step failed")
        await asyncio.sleep(5)


@asynccontextmanager
async def lifespan(_server):
    task = asyncio.create_task(background())
    try:
        yield {}
    finally:
        task.cancel()


mcp = MCPServer(
    "agent-spend-gateway",
    instructions="Pay for web resources within the limits set on the governance chain. "
                 "Every payment is authorized and recorded on chain before and after it happens.",
    lifespan=lifespan,
)


@mcp.tool()
async def paid_fetch(url: str, max_price: float) -> dict:
    """Buy and download a paid web resource via an x402 payment. max_price is the most you are
    willing to pay, in USDC. Returns the content when paid, or the reason it was refused, or a
    request_id when the payment waits for human approval."""
    return await gateway().paid_fetch(url, max_price)


@mcp.tool()
async def get_budget() -> dict:
    """Return today's spending limits and the remaining budget in USDC."""
    return await asyncio.to_thread(gateway().get_budget)


@mcp.tool()
async def payment_status(request_id: int) -> dict:
    """Return the status of a payment request (and the content once it is paid)."""
    return await asyncio.to_thread(gateway().payment_status, request_id)


def main():
    asyncio.run(mcp.run_stdio_async())


if __name__ == "__main__":
    main()
