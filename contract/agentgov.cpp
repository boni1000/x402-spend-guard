// agentgov: on-chain governance for AI agents that make payments.
//
// The governance gateway calls authorize() before paying, settle() after the public-chain
// payment, and fail() if the payment did not happen. Admin registers agents, policies and
// vendors; the policy's approver decides on payments above the approval threshold.
// Amounts are integers in micro-USDC (6 decimals), the same units x402 uses.
#include <eosio/crypto.hpp>
#include <eosio/eosio.hpp>
#include <eosio/singleton.hpp>
#include <eosio/system.hpp>

using namespace eosio;

namespace {
   enum req_status : uint8_t {
      AUTHORIZED = 1, PENDING = 2, APPROVED = 3, REJECTED = 4, SETTLED = 5, FAILED = 6, EXPIRED = 7
   };
   enum agent_status : uint8_t { REVOKED = 0, ACTIVE = 1 };

   std::string lower(std::string s) {
      for (auto& c : s) if (c >= 'A' && c <= 'Z') c = c - 'A' + 'a';
      return s;
   }
   checksum256 key_of(const std::string& network, const std::string& value) {
      const std::string k = lower(network) + "|" + lower(value);
      return sha256(k.data(), k.size());
   }
   uint128_t nonce_key(name agent, uint64_t nonce) {
      return (uint128_t(agent.value) << 64) | nonce;
   }
   time_point_sec now() { return time_point_sec(current_time_point()); }
}

struct auth_result {
   uint64_t id;
   uint8_t  status;
};

struct budget_info {
   uint64_t per_tx_max;
   uint64_t daily_max;
   uint64_t approval_threshold;
   uint64_t committed_today;
   uint64_t remaining_today;
   uint32_t day;
   uint8_t  agent_status;
};

class [[eosio::contract("agentgov")]] agentgov : public contract {
public:
   using contract::contract;

   // ---------------------------------------------------------------- configuration

   // day_sec: length of a budget "day" (86400 in production; shorter in test mode).
   // pending_ttl_sec / auth_ttl_sec: how long pending or authorized requests stay valid.
   [[eosio::action]]
   void init(name admin, uint32_t day_sec, uint32_t pending_ttl_sec, uint32_t auth_ttl_sec) {
      require_auth(get_self());
      check(is_account(admin), "admin account does not exist");
      check(day_sec >= 60, "day_sec must be at least 60");
      check(pending_ttl_sec >= 10 && auth_ttl_sec >= 10, "ttl must be at least 10 seconds");
      config_t(get_self(), get_self().value).set(config{admin, day_sec, pending_ttl_sec, auth_ttl_sec}, get_self());
   }

   [[eosio::action]]
   void regagent(name agent, name owner, checksum256 model_hash, std::string label) {
      const auto cfg = get_cfg();
      require_auth(cfg.admin);
      check(is_account(agent), "agent account does not exist");
      check(is_account(owner), "owner account does not exist");
      check(label.size() <= 64, "label too long");
      agents_t agents(get_self(), get_self().value);
      auto it = agents.find(agent.value);
      if (it == agents.end()) {
         agents.emplace(cfg.admin, [&](auto& r) {
            r.agent = agent; r.owner = owner; r.model_hash = model_hash; r.label = label;
            r.status = ACTIVE; r.registered = now();
         });
      } else {
         // The current admin signs, so it also pays for any growth (the admin may have changed).
         agents.modify(it, cfg.admin, [&](auto& r) { r.owner = owner; r.model_hash = model_hash; r.label = label; });
      }
   }

   [[eosio::action]]
   void setpolicy(name agent, uint64_t per_tx_max, uint64_t daily_max, uint64_t approval_threshold, name approver) {
      const auto cfg = get_cfg();
      require_auth(cfg.admin);
      agents_t agents(get_self(), get_self().value);
      check(agents.find(agent.value) != agents.end(), "agent not registered");
      check(per_tx_max > 0, "per_tx_max must be positive");
      check(per_tx_max <= daily_max, "per_tx_max cannot exceed daily_max");
      check(approval_threshold <= per_tx_max, "approval_threshold cannot exceed per_tx_max");
      check(is_account(approver), "approver account does not exist");
      check(approver != agent, "an agent cannot approve its own payments");
      policies_t policies(get_self(), get_self().value);
      auto it = policies.find(agent.value);
      auto set = [&](auto& r) {
         r.agent = agent; r.per_tx_max = per_tx_max; r.daily_max = daily_max;
         r.approval_threshold = approval_threshold; r.approver = approver;
      };
      if (it == policies.end()) policies.emplace(cfg.admin, set);
      else policies.modify(it, same_payer, set);
   }

   // Returns the vendor id. Re-adding a removed vendor reactivates it.
   [[eosio::action]]
   uint64_t addvendor(std::string network, std::string pay_to, std::string label) {
      const auto cfg = get_cfg();
      require_auth(cfg.admin);
      check(!network.empty() && network.size() <= 48, "invalid network");
      check(!pay_to.empty() && pay_to.size() <= 96, "invalid pay_to");
      check(label.size() <= 64, "label too long");
      vendors_t vendors(get_self(), get_self().value);
      const auto key = key_of(network, pay_to);
      auto byk = vendors.get_index<"bykey"_n>();
      auto it = byk.find(key);
      if (it != byk.end()) {
         check(!it->active, "vendor already registered");
         byk.modify(it, cfg.admin, [&](auto& r) { r.active = true; r.label = label; });
         return it->id;
      }
      const uint64_t id = vendors.available_primary_key();
      vendors.emplace(cfg.admin, [&](auto& r) {
         r.id = id; r.network = lower(network); r.pay_to = lower(pay_to); r.label = label;
         r.active = true; r.key = key;
      });
      return id;
   }

   [[eosio::action]]
   void rmvendor(uint64_t id) {
      require_auth(get_cfg().admin);
      vendors_t vendors(get_self(), get_self().value);
      const auto& v = vendors.get(id, "unknown vendor");
      vendors.modify(v, same_payer, [&](auto& r) { r.active = false; });
   }

   [[eosio::action]]
   void revoke(name agent, std::string reason) {
      const auto cfg = get_cfg();
      require_auth(cfg.admin);
      check(reason.size() <= 128, "reason too long");
      agents_t agents(get_self(), get_self().value);
      const auto& a = agents.get(agent.value, "agent not registered");
      // The row grows by the reason; the signing admin pays (the chain refuses to bill a former admin).
      agents.modify(a, cfg.admin, [&](auto& r) { r.status = REVOKED; r.note = reason; });
   }

   [[eosio::action]]
   void reinstate(name agent) {
      const auto cfg = get_cfg();
      require_auth(cfg.admin);
      agents_t agents(get_self(), get_self().value);
      const auto& a = agents.get(agent.value, "agent not registered");
      agents.modify(a, cfg.admin, [&](auto& r) { r.status = ACTIVE; r.note = ""; });
   }

   // ---------------------------------------------------------------- payment flow

   [[eosio::action]]
   auth_result authorize(name agent, uint64_t vendor_id, uint64_t amount, checksum256 params_hash, uint64_t nonce) {
      require_auth(agent);
      const auto cfg = get_cfg();
      agents_t agents(get_self(), get_self().value);
      const auto& a = agents.get(agent.value, "agent not registered");
      check(a.status == ACTIVE, "agent is revoked");
      policies_t policies(get_self(), get_self().value);
      const auto& p = policies.get(agent.value, "agent has no policy");
      vendors_t vendors(get_self(), get_self().value);
      const auto& v = vendors.get(vendor_id, "unknown vendor");
      check(v.active, "vendor is not whitelisted");
      check(amount > 0, "amount must be positive");
      check(amount <= p.per_tx_max, "amount exceeds per-payment limit");

      payreqs_t reqs(get_self(), get_self().value);
      auto bynonce = reqs.get_index<"bynonce"_n>();
      check(bynonce.find(nonce_key(agent, nonce)) == bynonce.end(), "nonce already used");

      const uint32_t day = today(cfg);
      spend_t spend(get_self(), agent.value);
      auto s = spend.find(day);
      const uint64_t committed = (s == spend.end()) ? 0 : s->committed;
      check(committed + amount <= p.daily_max, "daily limit exceeded");
      if (s == spend.end()) spend.emplace(agent, [&](auto& r) { r.day = day; r.committed = amount; });
      else spend.modify(s, same_payer, [&](auto& r) { r.committed += amount; });

      const uint8_t status = amount > p.approval_threshold ? PENDING : AUTHORIZED;
      const uint32_t ttl = status == PENDING ? cfg.pending_ttl_sec : cfg.auth_ttl_sec;
      const uint64_t id = reqs.available_primary_key();
      const auto t = now();
      reqs.emplace(agent, [&](auto& r) {
         r.id = id; r.agent = agent; r.vendor_id = vendor_id; r.amount = amount;
         r.params_hash = params_hash; r.nonce = nonce; r.status = status; r.day = day;
         r.created = t; r.updated = t; r.expires = t + ttl;
      });
      return auth_result{id, status};
   }

   [[eosio::action]]
   void approve(name approver, uint64_t id) {
      require_auth(approver);
      const auto cfg = get_cfg();
      payreqs_t reqs(get_self(), get_self().value);
      const auto& r = reqs.get(id, "unknown request");
      check(r.status == PENDING, "request is not pending");
      check(now() < r.expires, "request has expired");
      check_approver(r.agent, approver);
      agents_t agents(get_self(), get_self().value);
      check(agents.get(r.agent.value).status == ACTIVE, "agent is revoked");
      reqs.modify(r, same_payer, [&](auto& x) {
         x.status = APPROVED; x.approved_by = approver; x.updated = now(); x.expires = now() + cfg.auth_ttl_sec;
      });
   }

   [[eosio::action]]
   void reject(name approver, uint64_t id, std::string reason) {
      require_auth(approver);
      check(reason.size() <= 128, "reason too long");
      payreqs_t reqs(get_self(), get_self().value);
      const auto& r = reqs.get(id, "unknown request");
      check(r.status == PENDING, "request is not pending");
      check_approver(r.agent, approver);
      release(r);
      // The row's RAM is paid by the agent, so it must not grow here (the chain refuses to
      // bill an account that did not sign). The reason stays on chain in this signed action.
      reqs.modify(r, same_payer, [&](auto& x) {
         x.status = REJECTED; x.approved_by = approver; x.updated = now();
      });
   }

   // Records the public-chain payment. Allowed even if the agent was revoked meanwhile:
   // the money has already moved, so the record must be kept.
   [[eosio::action]]
   void settle(name agent, uint64_t id, std::string ext_network, std::string ext_txid) {
      require_auth(agent);
      payreqs_t reqs(get_self(), get_self().value);
      const auto& r = reqs.get(id, "unknown request");
      check(r.agent == agent, "not your request");
      check(r.status == AUTHORIZED || r.status == APPROVED, "request is not authorized for payment");
      check(!ext_txid.empty() && ext_txid.size() <= 100, "invalid transaction id");
      vendors_t vendors(get_self(), get_self().value);
      check(lower(ext_network) == vendors.get(r.vendor_id).network, "network does not match vendor");
      const auto txk = key_of(ext_network, ext_txid);
      auto bytx = reqs.get_index<"bytx"_n>();
      for (auto it = bytx.lower_bound(txk); it != bytx.end() && it->by_tx() == txk; ++it)
         check(it->status != SETTLED, "transaction already recorded");
      reqs.modify(r, same_payer, [&](auto& x) {
         x.status = SETTLED; x.ext_network = lower(ext_network); x.ext_txid = lower(ext_txid); x.updated = now();
      });
   }

   [[eosio::action]]
   void fail(name agent, uint64_t id, std::string reason) {
      require_auth(agent);
      check(reason.size() <= 128, "reason too long");
      payreqs_t reqs(get_self(), get_self().value);
      const auto& r = reqs.get(id, "unknown request");
      check(r.agent == agent, "not your request");
      check(r.status == AUTHORIZED || r.status == APPROVED || r.status == PENDING, "request cannot be failed");
      release(r);
      reqs.modify(r, same_payer, [&](auto& x) { x.status = FAILED; x.note = reason; x.updated = now(); });
   }

   // Anyone may expire a request whose validity has passed; this releases its reservation.
   [[eosio::action]]
   void expire(uint64_t id) {
      payreqs_t reqs(get_self(), get_self().value);
      const auto& r = reqs.get(id, "unknown request");
      check(r.status == AUTHORIZED || r.status == APPROVED || r.status == PENDING, "request cannot expire");
      check(now() >= r.expires, "not expired yet");
      release(r);
      reqs.modify(r, same_payer, [&](auto& x) { x.status = EXPIRED; x.updated = now(); });
   }

   // Audit attestation: any account may publish the result of an independent audit of the
   // payment records; the record shows who signed it. `root` is the Merkle root over the verified
   // records in [from_id, to_id], recomputable by anyone from this contract's own tables.
   [[eosio::action]]
   uint64_t logaudit(name auditor, checksum256 root, uint64_t from_id, uint64_t to_id, uint32_t records,
                     uint64_t total, uint32_t problems, std::string note) {
      require_auth(auditor);
      check(from_id <= to_id, "invalid range");
      check(note.size() <= 128, "note too long");
      audits_t audits(get_self(), get_self().value);
      const uint64_t id = audits.available_primary_key();
      audits.emplace(auditor, [&](auto& r) {
         r.id = id; r.auditor = auditor; r.root = root; r.from_id = from_id; r.to_id = to_id;
         r.records = records; r.total = total; r.problems = problems; r.note = note; r.created = now();
      });
      return id;
   }

   // Read-only: limits and remaining budget, without writing anything.
   [[eosio::action, eosio::read_only]]
   budget_info getbudget(name agent) {
      const auto cfg = get_cfg();
      agents_t agents(get_self(), get_self().value);
      const auto& a = agents.get(agent.value, "agent not registered");
      policies_t policies(get_self(), get_self().value);
      const auto& p = policies.get(agent.value, "agent has no policy");
      const uint32_t day = today(cfg);
      spend_t spend(get_self(), agent.value);
      auto s = spend.find(day);
      const uint64_t committed = (s == spend.end()) ? 0 : s->committed;
      return budget_info{p.per_tx_max, p.daily_max, p.approval_threshold, committed,
                         committed >= p.daily_max ? 0 : p.daily_max - committed, day, a.status};
   }

private:
   struct [[eosio::table("config")]] config {
      name     admin;
      uint32_t day_sec;
      uint32_t pending_ttl_sec;
      uint32_t auth_ttl_sec;
   };
   using config_t = singleton<"config"_n, config>;

   struct [[eosio::table]] agent_row {
      name           agent;
      name           owner;
      checksum256    model_hash;
      std::string    label;
      uint8_t        status;
      std::string    note;
      time_point_sec registered;
      uint64_t primary_key() const { return agent.value; }
   };
   using agents_t = multi_index<"agents"_n, agent_row>;

   struct [[eosio::table]] policy_row {
      name     agent;
      uint64_t per_tx_max;
      uint64_t daily_max;
      uint64_t approval_threshold;
      name     approver;
      uint64_t primary_key() const { return agent.value; }
   };
   using policies_t = multi_index<"policies"_n, policy_row>;

   struct [[eosio::table]] vendor_row {
      uint64_t    id;
      std::string network;
      std::string pay_to;
      std::string label;
      bool        active;
      checksum256 key;
      uint64_t    primary_key() const { return id; }
      checksum256 by_key() const { return key; }
   };
   using vendors_t = multi_index<"vendors"_n, vendor_row,
      indexed_by<"bykey"_n, const_mem_fun<vendor_row, checksum256, &vendor_row::by_key>>>;

   // Scoped by agent; one row per budget day.
   struct [[eosio::table]] spend_row {
      uint32_t day;
      uint64_t committed;
      uint64_t primary_key() const { return day; }
   };
   using spend_t = multi_index<"spend"_n, spend_row>;

   struct [[eosio::table]] payreq_row {
      uint64_t       id;
      name           agent;
      uint64_t       vendor_id;
      uint64_t       amount;
      checksum256    params_hash;
      uint64_t       nonce;
      uint8_t        status;
      uint32_t       day;
      name           approved_by;
      std::string    ext_network;
      std::string    ext_txid;
      std::string    note;
      time_point_sec created;
      time_point_sec updated;
      time_point_sec expires;
      uint64_t    primary_key() const { return id; }
      uint64_t    by_agent() const { return agent.value; }
      uint128_t   by_nonce() const { return nonce_key(agent, nonce); }
      uint64_t    by_status() const { return status; }
      checksum256 by_tx() const { return key_of(ext_network, ext_txid); }
   };
   using payreqs_t = multi_index<"payreqs"_n, payreq_row,
      indexed_by<"byagent"_n, const_mem_fun<payreq_row, uint64_t, &payreq_row::by_agent>>,
      indexed_by<"bynonce"_n, const_mem_fun<payreq_row, uint128_t, &payreq_row::by_nonce>>,
      indexed_by<"bystatus"_n, const_mem_fun<payreq_row, uint64_t, &payreq_row::by_status>>,
      indexed_by<"bytx"_n, const_mem_fun<payreq_row, checksum256, &payreq_row::by_tx>>>;

   struct [[eosio::table]] audit_row {
      uint64_t       id;
      name           auditor;
      checksum256    root;
      uint64_t       from_id;
      uint64_t       to_id;
      uint32_t       records;
      uint64_t       total;      // micro-USDC
      uint32_t       problems;
      std::string    note;
      time_point_sec created;
      uint64_t primary_key() const { return id; }
   };
   using audits_t = multi_index<"audits"_n, audit_row>;

   config get_cfg() {
      config_t c(get_self(), get_self().value);
      check(c.exists(), "contract not initialised");
      return c.get();
   }
   static uint32_t today(const config& cfg) {
      return current_time_point().sec_since_epoch() / cfg.day_sec;
   }
   void check_approver(name agent, name approver) {
      policies_t policies(get_self(), get_self().value);
      check(policies.get(agent.value, "agent has no policy").approver == approver,
            "not the approver for this agent");
   }
   void release(const payreq_row& r) {
      spend_t spend(get_self(), r.agent.value);
      auto s = spend.find(r.day);
      if (s != spend.end())
         spend.modify(s, same_payer, [&](auto& x) { x.committed -= std::min(x.committed, r.amount); });
   }
};
