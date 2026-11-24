// eip3009: the EIP-712 digest of an EIP-3009 TransferWithAuthorization, i.e. exactly the 32 bytes
// a USDC payer signs for an x402 "exact" payment. agentgov builds this digest itself from fields it
// has checked and asks the MPC network to sign it; it never signs a digest handed to it.
//
// Plain C++ with no eosio headers: the contract passes eosio::keccak, the native tests pass a
// reference Keccak, so both run the same code. A Keccak is any callable
//    bytes32 keccak(const uint8_t* data, size_t len)
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string_view>

namespace eip3009 {

using bytes32 = std::array<uint8_t, 32>;
using address = std::array<uint8_t, 20>;

// The token's EIP-712 domain. It differs per network: USDC is "USDC" on Base Sepolia but
// "USD Coin" on Base, so it is configured per network, never assumed.
struct domain {
   std::string_view name;
   std::string_view version;
   uint64_t         chain_id;
   address          token;     // verifyingContract
};

struct authorization {
   address  from;               // the payer (the agent's MPC-derived address)
   address  to;                 // the vendor
   uint64_t value;              // token units (micro-USDC)
   uint64_t valid_after;        // unix seconds
   uint64_t valid_before;       // unix seconds
   bytes32  nonce;
};

namespace detail {
   // ABI words are 32 bytes, big-endian, left-padded.
   inline void put_u64(uint8_t* word, uint64_t v) {
      std::memset(word, 0, 32);
      for (int i = 0; i < 8; ++i) word[31 - i] = uint8_t(v >> (8 * i));
   }
   inline void put_address(uint8_t* word, const address& a) {
      std::memset(word, 0, 12);
      std::memcpy(word + 12, a.data(), 20);
   }
   inline void put_bytes32(uint8_t* word, const bytes32& b) { std::memcpy(word, b.data(), 32); }

   template <typename Keccak>
   bytes32 hash_text(Keccak&& keccak, std::string_view s) {
      return keccak(reinterpret_cast<const uint8_t*>(s.data()), s.size());
   }
}

template <typename Keccak>
bytes32 domain_separator(const domain& d, Keccak&& keccak) {
   using namespace detail;
   uint8_t buf[5 * 32];
   put_bytes32(buf, hash_text(keccak,
      "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"));
   put_bytes32(buf + 32, hash_text(keccak, d.name));
   put_bytes32(buf + 64, hash_text(keccak, d.version));
   put_u64(buf + 96, d.chain_id);
   put_address(buf + 128, d.token);
   return keccak(buf, sizeof buf);
}

template <typename Keccak>
bytes32 struct_hash(const authorization& a, Keccak&& keccak) {
   using namespace detail;
   uint8_t buf[7 * 32];
   put_bytes32(buf, hash_text(keccak,
      "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,"
      "uint256 validBefore,bytes32 nonce)"));
   put_address(buf + 32, a.from);
   put_address(buf + 64, a.to);
   put_u64(buf + 96, a.value);
   put_u64(buf + 128, a.valid_after);
   put_u64(buf + 160, a.valid_before);
   put_bytes32(buf + 192, a.nonce);
   return keccak(buf, sizeof buf);
}

// keccak256(0x19 0x01 || domainSeparator || structHash): what transferWithAuthorization verifies.
template <typename Keccak>
bytes32 digest(const domain& d, const authorization& a, Keccak&& keccak) {
   uint8_t buf[2 + 64];
   buf[0] = 0x19;
   buf[1] = 0x01;
   detail::put_bytes32(buf + 2, domain_separator(d, keccak));
   detail::put_bytes32(buf + 34, struct_hash(a, keccak));
   return keccak(buf, sizeof buf);
}

// The EIP-3009 nonce of one agentgov payment request. Request ids are never reused (payreqs rows
// are never erased), so each request gets its own nonce and a signature cannot pay a second one.
template <typename Keccak>
bytes32 request_nonce(uint64_t contract, uint64_t request_id, Keccak&& keccak) {
   static constexpr std::string_view tag = "x402-spend-guard/eip3009-nonce/v1";
   uint8_t buf[tag.size() + 16];
   std::memcpy(buf, tag.data(), tag.size());
   for (int i = 0; i < 8; ++i) {
      buf[tag.size() + i]     = uint8_t(contract >> (56 - 8 * i));
      buf[tag.size() + 8 + i] = uint8_t(request_id >> (56 - 8 * i));
   }
   return keccak(buf, sizeof buf);
}

// "0x" followed by exactly 40 hex digits, either case. The EIP-55 checksum is not checked.
inline bool parse_address(std::string_view s, address& out) {
   if (s.size() != 42 || s[0] != '0' || (s[1] != 'x' && s[1] != 'X')) return false;
   auto nibble = [](char c) -> int {
      if (c >= '0' && c <= '9') return c - '0';
      if (c >= 'a' && c <= 'f') return c - 'a' + 10;
      if (c >= 'A' && c <= 'F') return c - 'A' + 10;
      return -1;
   };
   for (size_t i = 0; i < 20; ++i) {
      const int hi = nibble(s[2 + 2 * i]), lo = nibble(s[3 + 2 * i]);
      if (hi < 0 || lo < 0) return false;
      out[i] = uint8_t(hi << 4 | lo);
   }
   return true;
}

} // namespace eip3009
