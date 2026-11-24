// Runs contract/eip3009.hpp natively for tests/test_eip3009.py. One command per line on stdin,
// fields separated by tabs (token names may contain spaces); one hex answer per line on stdout.
//   keccak  <hex>
//   digest  <name> <version> <chain_id> <token> <from> <to> <value> <valid_after> <valid_before> <nonce>
//           -> "<domain separator> <digest>"
//   nonce   <contract> <request_id>
//   address <text>      -> hex, or "invalid"
#include "eip3009.hpp"
#include "keccak_ref.hpp"

#include <algorithm>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
   eip3009::bytes32 keccak(const uint8_t* p, size_t n) { return keccak_ref::keccak256(p, n); }

   template <size_t N> std::string hex(const std::array<uint8_t, N>& b) {
      static const char* d = "0123456789abcdef";
      std::string s;
      for (uint8_t x : b) { s += d[x >> 4]; s += d[x & 15]; }
      return s;
   }
   std::vector<uint8_t> unhex(const std::string& s) {
      std::vector<uint8_t> out;
      for (size_t i = 0; i + 1 < s.size(); i += 2) out.push_back(uint8_t(std::stoi(s.substr(i, 2), nullptr, 16)));
      return out;
   }
   eip3009::address addr(const std::string& s) {
      eip3009::address a{};
      if (!eip3009::parse_address(s, a)) throw std::runtime_error("bad address " + s);
      return a;
   }
}

int main() {
   std::string line;
   while (std::getline(std::cin, line)) {
      std::vector<std::string> f;
      size_t start = 0, tab;
      while ((tab = line.find('\t', start)) != std::string::npos) { f.push_back(line.substr(start, tab - start)); start = tab + 1; }
      f.push_back(line.substr(start));
      if (f[0] == "keccak") {
         const auto data = unhex(f.size() > 1 ? f[1] : "");
         std::cout << hex(keccak(data.data(), data.size())) << "\n";
      } else if (f[0] == "digest") {
         const eip3009::domain d{f[1], f[2], std::stoull(f[3]), addr(f[4])};
         eip3009::authorization a{addr(f[5]), addr(f[6]), std::stoull(f[7]), std::stoull(f[8]), std::stoull(f[9]), {}};
         const auto n = unhex(f[10]);
         std::copy(n.begin(), n.end(), a.nonce.begin());
         std::cout << hex(eip3009::domain_separator(d, keccak)) << " " << hex(eip3009::digest(d, a, keccak)) << "\n";
      } else if (f[0] == "nonce") {
         std::cout << hex(eip3009::request_nonce(std::stoull(f[1]), std::stoull(f[2]), keccak)) << "\n";
      } else if (f[0] == "address") {
         eip3009::address a{};
         std::cout << (eip3009::parse_address(f[1], a) ? hex(a) : "invalid") << "\n";
      }
   }
}
