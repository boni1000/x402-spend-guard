#!/usr/bin/env python3
"""Research agent: an Ollama model on the GPU server that uses the governance gateway over MCP.

The agent never holds a key. It can only call the gateway's three tools; every payment it asks
for is checked and recorded on the agentgov chain.

  python examples/agent_ollama.py run --agent <agent account> --task "..."   (transcript saved in runs/)
  python examples/agent_ollama.py replay runs/<file>.json                     (re-run tool calls, no LLM)
"""
import argparse
import asyncio
import json
import os
import sys
import time

import httpx
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

HERE = os.path.dirname(os.path.abspath(__file__))
OLLAMA = os.environ.get("OLLAMA_URL", "http://localhost:11434")
DEFAULT_MODEL = os.environ.get("AGENT_MODEL", "qwen2.5:7b-instruct")

SYSTEM = (
    "You are a research agent. You can buy paid web "
    "resources with the paid_fetch tool (prices in USDC) and read free pages with it as well. Your "
    "spending is limited by your organisation's rules; use get_budget to see your limits. When a "
    "payment waits for approval, tell the user the request id. Report what you bought and what it cost."
)


def to_ollama_tool(t):
    return {"type": "function", "function": {"name": t.name, "description": t.description or "",
                                             "parameters": getattr(t, "input_schema", None) or getattr(t, "inputSchema", None)
                                             or {"type": "object", "properties": {}}}}


def tool_payload(result):
    sc = getattr(result, "structured_content", None) or getattr(result, "structuredContent", None)
    if sc:
        return sc.get("result", sc)
    try:
        return json.loads(result.content[0].text)
    except (ValueError, IndexError, AttributeError):
        return {"raw": str(result)}


async def ollama_chat(model, messages, tools):
    body = {"model": model, "messages": messages, "tools": tools, "stream": False, "keep_alive": "10m",
            "options": {"temperature": 0, "seed": 1, "num_ctx": 8192}}
    if any(x in model for x in ("qwen3", "gemma4", "nemotron")):
        body["think"] = False
    async with httpx.AsyncClient(timeout=300) as c:
        r = await c.post(f"{OLLAMA}/api/chat", json=body)
        r.raise_for_status()
    return r.json()["message"]


def server_params(agent):
    # Starts the gateway's MCP server over stdio, from the working directory with your .env files.
    env = dict(os.environ, AGENT=agent, JOURNAL=f"journal-{agent}.sqlite")
    return StdioServerParameters(command=sys.executable, args=["-m", "spend_guard.mcp_server"], cwd=os.getcwd(), env=env)


async def run(agent, task, model=DEFAULT_MODEL, max_steps=10, label="task"):
    t0 = time.time()
    calls, answer = [], ""
    async with stdio_client(server_params(agent)) as (read, write):
        async with ClientSession(read, write) as s:
            await s.initialize()
            tools = [to_ollama_tool(t) for t in (await s.list_tools()).tools]
            messages = [{"role": "system", "content": SYSTEM}, {"role": "user", "content": task}]
            for _ in range(max_steps):
                msg = await ollama_chat(model, messages, tools)
                messages.append(msg)
                tool_calls = msg.get("tool_calls") or []
                if not tool_calls:
                    answer = msg.get("content", "")
                    break
                for tc in tool_calls:
                    name = tc["function"]["name"]
                    args = tc["function"].get("arguments") or {}
                    if isinstance(args, str):
                        args = json.loads(args or "{}")
                    try:
                        payload = tool_payload(await s.call_tool(name, args))
                    except Exception as e:  # noqa: BLE001 - shown to the model as a tool error
                        payload = {"status": "error", "reason": str(e)}
                    calls.append({"tool": name, "args": args, "result": payload})
                    print(f"  -> {name}({json.dumps(args)}) = {payload.get('status', '')} "
                          f"{payload.get('reason', '') or payload.get('tx', '')}", flush=True)
                    messages.append({"role": "tool", "tool_name": name,
                                     "content": json.dumps(payload, ensure_ascii=False)[:6000]})
            else:
                answer = "(step limit reached)"
    record = {"label": label, "agent": agent, "model": model, "task": task, "calls": calls, "answer": answer,
              "seconds": round(time.time() - t0, 1), "date": time.strftime("%Y-%m-%d %H:%M:%S")}
    os.makedirs("runs", exist_ok=True)
    path = os.path.join("runs", time.strftime("%Y%m%d-%H%M%S") + f"-{label}-{agent}.json")
    with open(path, "w") as f:
        json.dump(record, f, indent=1, ensure_ascii=False)
    record["path"] = path
    return record


async def replay(path):
    rec = json.load(open(path))
    print(f"replaying {len(rec['calls'])} tool calls of '{rec['label']}' for {rec['agent']} (no LLM)")
    async with stdio_client(server_params(rec["agent"])) as (read, write):
        async with ClientSession(read, write) as s:
            await s.initialize()
            for c in rec["calls"]:
                payload = tool_payload(await s.call_tool(c["tool"], c["args"]))
                print(f"  -> {c['tool']}({json.dumps(c['args'])}) = {payload.get('status', '')} "
                      f"{payload.get('reason', '') or payload.get('tx', '')}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--agent", default=os.environ.get("AGENT"), required=not os.environ.get("AGENT"))
    r.add_argument("--model", default=DEFAULT_MODEL)
    r.add_argument("--task", required=True)
    p = sub.add_parser("replay")
    p.add_argument("path")
    a = ap.parse_args()
    if a.cmd == "run":
        rec = asyncio.run(run(a.agent, a.task, a.model))
        print("\nANSWER:\n" + rec["answer"] + f"\n\n({rec['seconds']} s, transcript {rec['path']})")
    else:
        asyncio.run(replay(a.path))
