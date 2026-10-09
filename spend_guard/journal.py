"""Local journal of payment requests, so the gateway can recover after a crash.

The chain is the source of truth for authorization; the journal remembers what the gateway
itself was doing (which URL, which exact requirement, whether a payment was already sent).
"""
import json
import sqlite3
import threading
import time

SCHEMA = """
create table if not exists requests (
  nonce      integer primary key,
  agent      text not null,
  url        text not null,
  accepted   text not null,      -- the exact x402 requirement that was authorized (json)
  amount     integer not null,   -- micro-USDC
  vendor_id  integer,
  req_id     integer,            -- id in agentgov::payreqs
  phase      text not null,      -- see PHASES
  ext_tx     text,
  base_block integer,            -- Base block number just before paying (for the reconciler)
  content    text,
  error      text,
  created    real not null,
  updated    real not null
)"""

# refused | authorizing | pending_approval | authorized | paying | payment_unknown |
# paid_not_recorded | settled | failed | rejected | expired
PHASES_OPEN = ("authorizing", "pending_approval", "authorized", "paying", "payment_unknown", "paid_not_recorded")


class Journal:
    def __init__(self, path):
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.lock = threading.Lock()
        with self.lock:
            self.db.execute(SCHEMA)
            cols = [c[1] for c in self.db.execute("pragma table_info(requests)")]
            if "attempts" not in cols:   # authorization nonces of every payment attempt (json list)
                self.db.execute("alter table requests add column attempts text")
            self.db.commit()

    def insert(self, nonce, agent, url, accepted, amount, vendor_id, phase):
        now = time.time()
        with self.lock:
            self.db.execute("insert into requests (nonce, agent, url, accepted, amount, vendor_id, phase, created, updated)"
                            " values (?,?,?,?,?,?,?,?,?)",
                            (nonce, agent, url, json.dumps(accepted), amount, vendor_id, phase, now, now))
            self.db.commit()

    def update(self, nonce, **fields):
        fields["updated"] = time.time()
        cols = ", ".join(f"{k} = ?" for k in fields)
        with self.lock:
            self.db.execute(f"update requests set {cols} where nonce = ?", (*fields.values(), nonce))
            self.db.commit()

    def get(self, nonce):
        with self.lock:
            r = self.db.execute("select * from requests where nonce = ?", (nonce,)).fetchone()
        return dict(r) if r else None

    def by_req_id(self, req_id):
        with self.lock:
            r = self.db.execute("select * from requests where req_id = ?", (req_id,)).fetchone()
        return dict(r) if r else None

    def by_phase(self, *phases):
        q = "select * from requests where phase in (%s) order by created" % ",".join("?" * len(phases))
        with self.lock:
            return [dict(r) for r in self.db.execute(q, phases).fetchall()]
