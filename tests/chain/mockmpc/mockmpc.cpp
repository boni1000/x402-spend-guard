// mockmpc: a stand-in for Alcor's MPC signing contract, with the interface as announced on
// 2026-11-24, for the dev chain only. The real network splits each key into shares held by
// independent operators; here tests/chain/mock_mpc_node.py holds one key per (requester, path)
// and registers its address with setkey.
//
//   sign(requester, path, payload, domain) -> id   the requester's authority (inline from its code)
//   respond(id, r, s, v)                           the node; the signature must recover to the key of
//                                                  (requester, path); stored, requester notified
//   getaddress(requester, path)                    read-only: the EVM address of that key
//
// Build: cdt-cpp -abigen -o mockmpc.wasm mockmpc.cpp
#include <eosio/crypto.hpp>
#include <eosio/crypto_ext.hpp>
#include <eosio/eosio.hpp>
#include <eosio/system.hpp>

using namespace eosio;

namespace {
   uint64_t key_id(name requester, const std::string& path) {
      const std::string k = requester.to_string() + "/" + path;
      const auto h = sha256(k.data(), k.size()).extract_as_byte_array();
      uint64_t id = 0;
      for (int i = 0; i < 8; ++i) id = (id << 8) | h[i];
      return id;
   }
}

class [[eosio::contract("mockmpc")]] mockmpc : public contract {
public:
   using contract::contract;

   [[eosio::action]]
   uint64_t sign(name requester, std::string path, checksum256 payload, uint8_t domain) {
      require_auth(requester);
      check(domain == 0, "only domain 0 (secp256k1) is supported");
      check(!path.empty() && path.size() <= 64, "invalid path");
      requests_t reqs(get_self(), get_self().value);
      const uint64_t id = reqs.available_primary_key();
      reqs.emplace(requester, [&](auto& r) {
         r.id = id; r.requester = requester; r.path = path; r.payload = payload; r.block = current_block_number();
      });
      return id;
   }

   [[eosio::action]]
   void respond(uint64_t id, checksum256 r, checksum256 s, uint8_t v) {
      require_auth(get_self());
      requests_t reqs(get_self(), get_self().value);
      const auto& q = reqs.get(id, "unknown request");
      signatures_t sigs(get_self(), get_self().value);
      check(sigs.find(id) == sigs.end(), "already signed");
      keys_t keys(get_self(), get_self().value);
      const auto& k = keys.get(key_id(q.requester, q.path), "no key for this requester and path");

      // k1_recover wants v || r || s and returns the uncompressed key 04 || X || Y.
      char sig[65], pub[65];
      sig[0] = char(v);
      const auto rb = r.extract_as_byte_array(), sb = s.extract_as_byte_array();
      std::copy(rb.begin(), rb.end(), sig + 1);
      std::copy(sb.begin(), sb.end(), sig + 33);
      const auto digest = q.payload.extract_as_byte_array();
      check(k1_recover(sig, 65, reinterpret_cast<const char*>(digest.data()), 32, pub, 65) == 0, "invalid signature");
      const auto h = keccak(pub + 1, 64).extract_as_byte_array();
      std::array<uint8_t, 20> addr;
      std::copy(h.begin() + 12, h.end(), addr.begin());
      check(checksum160(addr) == k.address, "signature does not match the derived key");

      sigs.emplace(get_self(), [&](auto& x) { x.id = id; x.payload = q.payload; x.r = r; x.s = s; x.v = v; });
      require_recipient(q.requester);
   }

   [[eosio::action]]
   void setkey(name requester, std::string path, checksum160 address) {
      require_auth(get_self());
      keys_t keys(get_self(), get_self().value);
      const uint64_t id = key_id(requester, path);
      auto it = keys.find(id);
      auto set = [&](auto& x) { x.id = id; x.requester = requester; x.path = path; x.address = address; };
      if (it == keys.end()) keys.emplace(get_self(), set);
      else keys.modify(it, same_payer, set);
   }

   [[eosio::action, eosio::read_only]]
   checksum160 getaddress(name requester, std::string path) {
      keys_t keys(get_self(), get_self().value);
      return keys.get(key_id(requester, path), "no key for this requester and path").address;
   }

private:
   struct [[eosio::table]] request_row {
      uint64_t    id;
      name        requester;
      std::string path;
      checksum256 payload;
      uint32_t    block;
      uint64_t primary_key() const { return id; }
   };
   using requests_t = multi_index<"requests"_n, request_row>;

   struct [[eosio::table]] signature_row {
      uint64_t    id;
      checksum256 payload;
      checksum256 r;
      checksum256 s;
      uint8_t     v;
      uint64_t    primary_key() const { return id; }
      checksum256 by_payload() const { return payload; }
   };
   using signatures_t = multi_index<"signatures"_n, signature_row,
      indexed_by<"bypayload"_n, const_mem_fun<signature_row, checksum256, &signature_row::by_payload>>>;

   struct [[eosio::table]] key_row {
      uint64_t    id;
      name        requester;
      std::string path;
      checksum160 address;
      uint64_t primary_key() const { return id; }
   };
   using keys_t = multi_index<"keys"_n, key_row>;
};
