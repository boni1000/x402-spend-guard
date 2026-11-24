// eip3009check: read-only actions that run contract/eip3009.hpp with the chain's own keccak, so a
// node's answer can be compared with tests/test_eip3009.py. Stores nothing and signs nothing.
// Build: cdt-cpp -abigen -o eip3009check.wasm eip3009check.cpp
#include <eosio/crypto_ext.hpp>
#include <eosio/eosio.hpp>

#include "../eip3009.hpp"

using namespace eosio;

namespace {
   eip3009::bytes32 chain_keccak(const uint8_t* p, size_t n) {
      return keccak(reinterpret_cast<const char*>(p), n).extract_as_byte_array();
   }
   eip3009::address addr(const std::string& s) {
      eip3009::address a{};
      check(eip3009::parse_address(s, a), "invalid address: " + s);
      return a;
   }
}

class [[eosio::contract("eip3009check")]] eip3009check : public contract {
public:
   using contract::contract;

   [[eosio::action, eosio::read_only]]
   checksum256 digest(std::string name, std::string version, uint64_t chain_id, std::string token,
                      std::string from, std::string to, uint64_t value, uint64_t valid_after,
                      uint64_t valid_before, checksum256 nonce) {
      const eip3009::domain d{name, version, chain_id, addr(token)};
      const eip3009::authorization a{addr(from), addr(to), value, valid_after, valid_before,
                                     nonce.extract_as_byte_array()};
      return checksum256(eip3009::digest(d, a, chain_keccak));
   }

   [[eosio::action, eosio::read_only]]
   checksum256 reqnonce(name contract, uint64_t request_id) {
      return checksum256(eip3009::request_nonce(contract.value, request_id, chain_keccak));
   }
};
