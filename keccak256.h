#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

// Keccak-256 hash (original Keccak, 0x01 padding — Ethereum-compatible).
// NOT SHA3-256 (which uses 0x06 padding per FIPS 202).

// Convenience: one-shot hash returning a 32-byte digest.
std::array<uint8_t, 32> keccak256(const void *data, size_t len);
std::array<uint8_t, 32> keccak256(std::span<const uint8_t> data);
std::array<uint8_t, 32> keccak256(std::string_view s);

// Streaming API for incremental hashing.
class Keccak {
 public:
  // One-shot: hash `in` (inlen bytes) and write digest to `md`.
  Keccak(const void *in, size_t inlen, void *md, int mdlen);

  // Streaming: construct, then call Update() one or more times, then Finalize().
  explicit Keccak(int mdlen = 32);

  void Update(const void *data, size_t len);
  void Update(std::span<const uint8_t> data);
  void Update(std::string_view s);

  void Finalize(void *md);
  std::array<uint8_t, 32> Finalize();

  void Reset();

 private:
  void Init(int mdlen);

  union {
    uint8_t b[200];
    uint64_t w[25];
  } st;

  int pt, rsiz, mdlen;
};
