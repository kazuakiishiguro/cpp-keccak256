#pragma once

#include <array>
#include <cstdint>

// round
// The sequence of step mappigs that is iterated
// inthe calculation of a KECCAK-p permutation
static constexpr uint64_t ROUND = 24;

// keccak round constant
// For each round of a KECCAK-p permutation, a lane value that is
// determined by the round index. The round constant is the second input to
// the ι step mapping.
static constexpr std::array<std::uint64_t, ROUND> ROUND_CONSTANTS {
     0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
     0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
     0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
     0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
     0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
     0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
     0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
     0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

class Keccak {
  public:
    Keccak();
  private:
    int init();
    int update();
    int final();
};
