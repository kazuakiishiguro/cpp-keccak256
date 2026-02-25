#include "keccak256.h"

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace {

constexpr int ROUNDS = 24;

constexpr std::array<uint64_t, ROUNDS> RNDC = {
  0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
  0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
  0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
  0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
  0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
  0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
  0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
  0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

constexpr std::array<int, ROUNDS> RHO = {
  1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
  27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
};

constexpr std::array<int, ROUNDS> PI = {
  10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
  15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
};

uint64_t Rotl(uint64_t x, int n) { return (x << n) | (x >> (64 - n)); }

// Keccak-f[1600] permutation.
void KeccakF(uint64_t st[25]) {
  int i, j;
  uint64_t t, bc[5];

  for (int round = 0; round < ROUNDS; ++round) {
    // θ step
    for (i = 0; i < 5; ++i)
      bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];

    for (i = 0; i < 5; ++i) {
      t = bc[(i + 4) % 5] ^ Rotl(bc[(i + 1) % 5], 1);
      for (j = 0; j < 25; j += 5)
        st[j + i] ^= t;
    }

    // ρ and π steps
    t = st[1];
    for (i = 0; i < ROUNDS; ++i) {
      j = PI[i];
      bc[0] = st[j];
      st[j] = Rotl(t, RHO[i]);
      t = bc[0];
    }

    // χ step
    for (j = 0; j < 25; j += 5) {
      for (i = 0; i < 5; ++i)
        bc[i] = st[j + i];
      for (i = 0; i < 5; ++i)
        st[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
    }

    // ι step
    st[0] ^= RNDC[round];
  }
}

} // namespace

// --- Free functions ---

std::array<uint8_t, 32> keccak256(const void *data, size_t len) {
  std::array<uint8_t, 32> out;
  Keccak(data, len, out.data(), 32);
  return out;
}

std::array<uint8_t, 32> keccak256(std::span<const uint8_t> data) {
  return keccak256(data.data(), data.size());
}

std::array<uint8_t, 32> keccak256(std::string_view s) {
  return keccak256(s.data(), s.size());
}

// --- Keccak class: one-shot constructor ---

Keccak::Keccak(const void *in, size_t inlen, void *md, int _mdlen) {
  Init(_mdlen);
  Update(in, inlen);
  Finalize(md);
}

// --- Keccak class: streaming constructor ---

Keccak::Keccak(int _mdlen) {
  Init(_mdlen);
}

// --- Private ---

void Keccak::Init(int _mdlen) {
  std::memset(st.b, 0, sizeof(st.b));
  mdlen = _mdlen;
  rsiz = 200 - 2 * mdlen;
  pt = 0;
}

// --- Public ---

void Keccak::Update(const void *data, size_t len) {
  int j = pt;

  for (size_t i = 0; i < len; ++i) {
    st.b[j++] ^= ((const uint8_t *)data)[i];
    if (j >= rsiz) {
      KeccakF(st.w);
      j = 0;
    }
  }

  pt = j;
}

void Keccak::Update(std::span<const uint8_t> data) {
  Update(data.data(), data.size());
}

void Keccak::Update(std::string_view s) {
  Update(s.data(), s.size());
}

void Keccak::Finalize(void *md) {
  st.b[pt] ^= 0x01;
  st.b[rsiz - 1] ^= 0x80;
  KeccakF(st.w);

  std::memcpy(md, st.b, mdlen);
}

std::array<uint8_t, 32> Keccak::Finalize() {
  std::array<uint8_t, 32> out;
  Finalize(out.data());
  return out;
}

void Keccak::Reset() {
  Init(mdlen);
}
