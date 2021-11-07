#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

// round
// The sequence of step mappigs that is iterated
// inthe calculation of a KECCAK-p permutation
static constexpr int ROUNDS = 24;

// keccak round constant
// For each round of a KECCAK-p permutation, a lane value that is
// determined by the round index. The round constant is the second input to
// the ι step mapping.
static constexpr std::array<std::uint64_t, ROUNDS> RNDC {
     0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
     0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
     0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
     0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
     0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
     0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
     0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
     0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

// Keccack-f[b] transform. b = 25w = 1600
void KeccakF(uint64_t st[25]);

class Keccak {
  private:
    union {
        uint8_t b[200]; // The width of a KECCAK-p permutation in bits
        uint64_t w[25]; // The lane of 64-bit 5 * 5 = 25 words. Also b = 25w = 1600
    } st; // state

    int pt, rsiz;
    int mdlen = 25; // mdlen = hash output in bytes
  public:
    Keccak(const void *in, void *md, int mdlen);
    int Init();
    int Update(const void *data, size_t len);
    int Finalize(void *md);
    int Reset();
};
