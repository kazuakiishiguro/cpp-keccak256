#include <cstdint>
#include <cstdio>
#include <cstring>

#include "keccak256.h"

static int test_hexdigit(char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  return -1;
}

static int test_readhex(uint8_t *buf, const char *str, int maxbytes) {
  int i, h, l;

  for (i = 0; i < maxbytes; ++i) {
    h = test_hexdigit(str[2 * i]);
    if (h < 0)
      return i;
    l = test_hexdigit(str[2 * i + 1]);
    if (l < 0)
      return i;
    buf[i] = (h << 4) + l;
  }

  return i;
}

static void print_hex(const uint8_t *buf, int len) {
  for (int i = 0; i < len; ++i)
    printf("%02X", buf[i]);
}

// Golden test vectors for Keccak-256 (original, 0x01 padding).
// Sources:
//   - Keccak team reference: https://keccak.team/files/Keccak-reference-3.0.pdf
//   - Ethereum canonical values (empty, "abc")
//   - KeccakKAT (ShortMsgKAT_256, LongMsgKAT_256)
struct TestVec {
  const char *name;
  const char *msg;  // hex-encoded input
  const char *hash; // hex-encoded expected Keccak-256 digest
};

static const TestVec testvec[] = {
  // 0 bytes - Ethereum canonical empty hash
  {
    "empty (0 bytes)",
    "",
    "C5D2460186F7233C927E7DB2DCC703C0E500B653CA82273B7BFAD8045D85A470"
  },
  // 3 bytes - "abc"
  {
    "abc (3 bytes)",
    "616263",
    "4E03657AEA45A94FC7D47BA826C8D667C0D1E6E33A64A036EC44F58FA12D6C45"
  },
  // 56 bytes - "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
  {
    "56-byte NIST string",
    "6162636462636465636465666465666765666768666768696768696A68696A6B"
    "696A6B6C6A6B6C6D6B6C6D6E6C6D6E6F6D6E6F706E6F7071",
    "45D3B367A6904E6E8D502EE04999A7C27647F91FA845D456525FD352AE3D7371"
  },
  // 112 bytes - "abcdefghbcdefghi...mnopqrstnopqrstu"
  {
    "112-byte NIST string",
    "61626364656667686263646566676869636465666768696A6465666768696A6B"
    "65666768696A6B6C666768696A6B6C6D6768696A6B6C6D6E68696A6B6C6D6E"
    "6F696A6B6C6D6E6F706A6B6C6D6E6F70716B6C6D6E6F7071726C6D6E6F7071"
    "72736D6E6F70717273746E6F707172737475",
    "F519747ED599024F3882238E5AB43960132572B7345FBEB9A90769DAFD21AD67"
  },
  // 136 zero bytes - exactly one full rate block (r = 136)
  {
    "136 zero bytes (full rate block)",
    "00000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000",
    "3A5912A7C5FAA06EE4FE906253E339467A9CE87D533C65BE3C15CB231CDB25F9"
  },
  // 200 bytes of 0xA3 - Keccak team KAT vector
  {
    "200 x 0xA3 (Keccak KAT)",
    "A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3"
    "A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3"
    "A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3"
    "A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3"
    "A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3"
    "A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3A3"
    "A3A3A3A3A3A3A3A3",
    "3A57666B048777F2C953DC4456F45A2588E1CB6F2DA760122D530AC2CE607D4A"
  },
};

static constexpr int NUM_TESTS = sizeof(testvec) / sizeof(testvec[0]);

int main() {
  uint8_t msg[512], expected[32], got[32];
  int fails = 0;

  for (int t = 0; t < NUM_TESTS; ++t) {
    memset(msg, 0, sizeof(msg));
    memset(expected, 0, sizeof(expected));
    memset(got, 0, sizeof(got));

    int msg_len = test_readhex(msg, testvec[t].msg, sizeof(msg));
    test_readhex(expected, testvec[t].hash, 32);

    Keccak(msg, msg_len, got, 32);

    if (memcmp(expected, got, 32) != 0) {
      printf("FAIL [%d] %s\n", t, testvec[t].name);
      printf("  expected: ");
      print_hex(expected, 32);
      printf("\n  got:      ");
      print_hex(got, 32);
      printf("\n");
      fails++;
    }
  }

  if (fails == 0)
    printf("ok (%d tests passed)\n", NUM_TESTS);
  else
    printf("%d / %d tests FAILED\n", fails, NUM_TESTS);

  return fails;
}
