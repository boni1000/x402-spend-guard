"""cleos access to the dev chain (tests/chain/devchain.sh), locally or over SSH.

    AGENTGOV_CLEOS  cleos command line, e.g. "cleos -u http://127.0.0.1:18888 --wallet-url http://127.0.0.1:18900"
    AGENTGOV_SSH    host to run it on (optional)

DevClient has the methods of spend_guard.spring.Spring that the gateway uses, so gateway code can
run against the dev chain unchanged.
"""
import json
import os
import shlex
import subprocess
from pathlib import Path

CLEOS = os.environ.get("AGENTGOV_CLEOS")
SSH = os.environ.get("AGENTGOV_SSH")


class ChainError(Exception):
    pass


def _fill(fmt, data):
    for k, v in data.items():
        fmt = fmt.replace("${" + k + "}", str(v))
    return fmt


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
            raise ChainError(" | ".join(_fill(s.get("format", ""), s.get("data", {})) for s in stack))
        except (ValueError, KeyError, TypeError):
            raise ChainError(p.stderr or p.stdout) from None
    return p.stdout


class DevClient:
    def __init__(self, code):
        self.contract = code

    def info(self):
        return json.loads(cleos("get", "info"))

    def table(self, table, scope=None, lower=None, upper=None, index=None, key_type=None, limit=100):
        args = ["get", "table", self.contract, scope or self.contract, table, "-l", limit]
        if index is not None:
            args += ["--index", index, "--key-type", key_type]
        if lower is not None:
            args += ["-L", lower]
        if upper is not None:
            args += ["-U", upper]
        return json.loads(cleos(*args))["rows"]

    def push(self, action, data, actor, permission="active"):
        """Same result shape as Spring.push: {"ok", "trx_id", "block_num", "return"} or {"ok": False, "error"}."""
        try:
            out = json.loads(cleos("push", "action", self.contract, action, json.dumps(data),
                                   "-p", f"{actor}@{permission}", "-j"))
        except ChainError as e:
            return {"ok": False, "error": str(e)}
        p = out["processed"]
        return {"ok": True, "trx_id": out["transaction_id"], "block_num": p["block_num"],
                "return": p["action_traces"][0].get("return_value_data"), "traces": p["action_traces"]}

    def wait_included(self, trx_id, start_block, timeout=None):
        return start_block   # one producer, no forks: executed is included
