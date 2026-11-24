// Reference Keccak-256 (the original padding Ethereum uses, not NIST SHA3-256), for the native
// tests only. In the contract the chain's keccak host function does this.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace keccak_ref {

inline uint64_t rol(uint64_t x, int s) { return (x << s) | (x >> (64 - s)); }

inline void f1600(uint64_t st[25]) {
   static const uint64_t RC[24] = {
      0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
      0x000000000000808bULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
      0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
      0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
      0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
      0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL};
   static const int ROT[24] = {1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
                               27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44};
   static const int PI[24] = {10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
                              15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1};
   for (int r = 0; r < 24; ++r) {
      uint64_t bc[5];
      for (int i = 0; i < 5; ++i) bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
      for (int i = 0; i < 5; ++i) {
         const uint64_t t = bc[(i + 4) % 5] ^ rol(bc[(i + 1) % 5], 1);
         for (int j = 0; j < 25; j += 5) st[j + i] ^= t;
      }
      uint64_t t = st[1];
      for (int i = 0; i < 24; ++i) {
         const uint64_t next = st[PI[i]];
         st[PI[i]] = rol(t, ROT[i]);
         t = next;
      }
      for (int j = 0; j < 25; j += 5) {
         uint64_t row[5];
         for (int i = 0; i < 5; ++i) row[i] = st[j + i];
         for (int i = 0; i < 5; ++i) st[j + i] = row[i] ^ (~row[(i + 1) % 5] & row[(i + 2) % 5]);
      }
      st[0] ^= RC[r];
   }
}

inline std::array<uint8_t, 32> keccak256(const uint8_t* data, size_t len) {
   constexpr size_t rate = 136;
   uint64_t st[25] = {};
   size_t pos = 0;
   auto absorb = [&](uint8_t b) {
      st[pos / 8] ^= uint64_t(b) << (8 * (pos % 8));
      if (++pos == rate) { f1600(st); pos = 0; }
   };
   for (size_t i = 0; i < len; ++i) absorb(data[i]);
   st[pos / 8] ^= uint64_t(0x01) << (8 * (pos % 8));
   st[(rate - 1) / 8] ^= uint64_t(0x80) << (8 * ((rate - 1) % 8));
   f1600(st);
   std::array<uint8_t, 32> out;
   for (size_t i = 0; i < 32; ++i) out[i] = uint8_t(st[i / 8] >> (8 * (i % 8)));
   return out;
}

} // namespace keccak_ref
