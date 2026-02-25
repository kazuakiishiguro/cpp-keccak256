#include <cstdint>
#include <cstdio>
#include <cstring>
#include <span>
#include <string_view>
#include <vector>

#include "keccak256.h"

static int test_hexdigit(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  return -1;
}

static int test_readhex(uint8_t *buf, const char *str, int maxbytes) {
  for (int i = 0; i < maxbytes; ++i) {
    int h = test_hexdigit(str[2 * i]);
    if (h < 0) return i;
    int l = test_hexdigit(str[2 * i + 1]);
    if (l < 0) return i;
    buf[i] = (h << 4) + l;
  }
  return maxbytes;
}

static void print_hex(const uint8_t *buf, int len) {
  for (int i = 0; i < len; ++i) printf("%02X", buf[i]);
}

// ---------------------------------------------------------------------------
// Golden test vectors for Keccak-256 (original Keccak, 0x01 padding).
//
// Sources:
//   - Keccak team: https://keccak.team/files/Keccak-reference-3.0.pdf
//   - Ethereum canonical values (empty, "abc")
//   - Generated from KeccakKAT / reference implementation
// ---------------------------------------------------------------------------

struct TestVec {
  const char *name;
  const char *msg;   // hex-encoded input
  const char *hash;  // hex-encoded expected 32-byte digest
};

static const TestVec testvec[] = {
  // --- Core vectors ---
  {
    "empty (0 bytes)",
    "",
    "C5D2460186F7233C927E7DB2DCC703C0E500B653CA82273B7BFAD8045D85A470"
  },
  {
    "abc (3 bytes)",
    "616263",
    "4E03657AEA45A94FC7D47BA826C8D667C0D1E6E33A64A036EC44F58FA12D6C45"
  },
  {
    "56-byte NIST string",
    "6162636462636465636465666465666765666768666768696768696A68696A6B"
    "696A6B6C6A6B6C6D6B6C6D6E6C6D6E6F6D6E6F706E6F7071",
    "45D3B367A6904E6E8D502EE04999A7C27647F91FA845D456525FD352AE3D7371"
  },
  {
    "112-byte NIST string",
    "61626364656667686263646566676869636465666768696A6465666768696A6B"
    "65666768696A6B6C666768696A6B6C6D6768696A6B6C6D6E68696A6B6C6D6E"
    "6F696A6B6C6D6E6F706A6B6C6D6E6F70716B6C6D6E6F7071726C6D6E6F7071"
    "72736D6E6F70717273746E6F707172737475",
    "F519747ED599024F3882238E5AB43960132572B7345FBEB9A90769DAFD21AD67"
  },
  {
    "136 zero bytes (full rate block)",
    "00000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000",
    "3A5912A7C5FAA06EE4FE906253E339467A9CE87D533C65BE3C15CB231CDB25F9"
  },
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

  // --- Extended vectors: incrementing byte pattern [0..n-1] at various lengths ---
  // Covers partial blocks, exact rate boundary (135, 136, 137), and near-max.
  { "1 byte",   "00",
    "BC36789E7A1E281436464229828F817D6612F7B477D66591FF96A9E064BCC98A" },
  { "16 bytes",  "000102030405060708090A0B0C0D0E0F",
    "01AEC967BA5D2A807EDD3FD8942C6F72C0C62961BFEB10C1F79C756F7294B0E3" },
  { "32 bytes",
    "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
    "8AE1AA597FA146EBD3AA2CEDDF360668DEA5E526567E92B0321816A4E895BD2D" },
  { "48 bytes",
    "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
    "202122232425262728292A2B2C2D2E2F",
    "39264A37173F6BB8BA919E2B6E820682FD23710F40B2466EE82228E8447A1F6A" },
  { "64 bytes",
    "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
    "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F",
    "002030BDE3D4CF89919649775CD71875C4D0AB1708A380E03FEFC3A28AA24831" },
  { "80 bytes",
    "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
    "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"
    "404142434445464748494A4B4C4D4E4F",
    "F0FE5C66FA31E6089CE5553A1BEE59A71251A9801E1CBCD133353CE8079E085F" },
  { "96 bytes",
    "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
    "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"
    "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F",
    "894F0180A325BF111F4E5979AB53CB88426AF23845F5CBAA5A9735A00CC87F10" },
  { "112 bytes (incrementing)",
    "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
    "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"
    "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F"
    "606162636465666768696A6B6C6D6E6F",
    "57B2F6B1B1692C57745FA6D76F34F06273AFF8A75FBEB33CDC5456DC450A5BEC" },
  { "128 bytes",
    "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
    "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"
    "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F"
    "606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F",
    "ED4C9ADC183FB8CB025B1500EC3EEAE1B45517314441A187605DE1BB8A64726E" },
  { "135 bytes (rate - 1)",
    "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
    "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"
    "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F"
    "606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F"
    "80818283848586",
    "CBDFD9DEE5FAAD3818D6B06F95A219FD290B0E1706F6A82E5A595B9CE9FACA62" },
  { "137 bytes (rate + 1)",
    "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
    "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"
    "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F"
    "606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F"
    "808182838485868788",
    "AC73D4FAE68B8453F764007C1A20CE95994187861F0C3227A3A8E99A73A3B1DB" },
  { "255 bytes",
    "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
    "202122232425262728292A2B2C2D2E2F303132333435363738393A3B3C3D3E3F"
    "404142434445464748494A4B4C4D4E4F505152535455565758595A5B5C5D5E5F"
    "606162636465666768696A6B6C6D6E6F707172737475767778797A7B7C7D7E7F"
    "808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F"
    "A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF"
    "C0C1C2C3C4C5C6C7C8C9CACBCCCDCECFD0D1D2D3D4D5D6D7D8D9DADBDCDDDEDF"
    "E0E1E2E3E4E5E6E7E8E9EAEBECEDEEEFF0F1F2F3F4F5F6F7F8F9FAFBFCFDFE",
    "DF819D2E7B8489CDD9729E77BD40A2C02F9BA2CEA4EA9433385BF79350E849D3" },
};

static constexpr int NUM_KAT = sizeof(testvec) / sizeof(testvec[0]);

// ---------------------------------------------------------------------------
// Test runner
// ---------------------------------------------------------------------------

static int fails = 0;
static int total = 0;

static void check(const char *label, const uint8_t *expected,
                   const uint8_t *got, int len) {
  ++total;
  if (memcmp(expected, got, len) != 0) {
    printf("FAIL [%d] %s\n", total, label);
    printf("  expected: "); print_hex(expected, len);
    printf("\n  got:      "); print_hex(got, len);
    printf("\n");
    ++fails;
  }
}

int main() {
  uint8_t msg[512], expected[32], got[32];

  // --- KAT: one-shot via legacy constructor ---
  for (int t = 0; t < NUM_KAT; ++t) {
    memset(msg, 0, sizeof(msg));
    int msg_len = test_readhex(msg, testvec[t].msg, sizeof(msg));
    test_readhex(expected, testvec[t].hash, 32);

    Keccak(msg, msg_len, got, 32);
    check(testvec[t].name, expected, got, 32);
  }

  // --- Test free function: keccak256(void*, size_t) ---
  {
    auto h = keccak256("abc", 3);
    uint8_t exp[32];
    test_readhex(exp, "4E03657AEA45A94FC7D47BA826C8D667C0D1E6E33A64A036EC44F58FA12D6C45", 32);
    check("keccak256(void*,size_t)", exp, h.data(), 32);
  }

  // --- Test free function: keccak256(string_view) ---
  {
    auto h = keccak256(std::string_view("abc"));
    uint8_t exp[32];
    test_readhex(exp, "4E03657AEA45A94FC7D47BA826C8D667C0D1E6E33A64A036EC44F58FA12D6C45", 32);
    check("keccak256(string_view)", exp, h.data(), 32);
  }

  // --- Test free function: keccak256(span) ---
  {
    std::vector<uint8_t> data = {0x61, 0x62, 0x63};
    auto h = keccak256(std::span<const uint8_t>(data));
    uint8_t exp[32];
    test_readhex(exp, "4E03657AEA45A94FC7D47BA826C8D667C0D1E6E33A64A036EC44F58FA12D6C45", 32);
    check("keccak256(span)", exp, h.data(), 32);
  }

  // --- Test streaming API: multiple Update() calls ---
  {
    Keccak k;
    k.Update("abc", 3);
    k.Update("dbc", 3);
    k.Update("dec", 3);
    auto h = k.Finalize();

    // Should match keccak256("abcdbcdec") = keccak256 of those 9 bytes
    auto h2 = keccak256("abcdbcdec", 9);
    check("streaming: multiple Update()", h2.data(), h.data(), 32);
  }

  // --- Test streaming API with string_view ---
  {
    Keccak k;
    k.Update(std::string_view("abc"));
    auto h = k.Finalize();
    uint8_t exp[32];
    test_readhex(exp, "4E03657AEA45A94FC7D47BA826C8D667C0D1E6E33A64A036EC44F58FA12D6C45", 32);
    check("streaming: Update(string_view)", exp, h.data(), 32);
  }

  // --- Test Reset() ---
  {
    Keccak k;
    k.Update("garbage", 7);
    k.Reset();
    k.Update("abc", 3);
    auto h = k.Finalize();
    uint8_t exp[32];
    test_readhex(exp, "4E03657AEA45A94FC7D47BA826C8D667C0D1E6E33A64A036EC44F58FA12D6C45", 32);
    check("Reset() then hash abc", exp, h.data(), 32);
  }

  // --- Test empty via free function ---
  {
    auto h = keccak256(nullptr, 0);
    uint8_t exp[32];
    test_readhex(exp, "C5D2460186F7233C927E7DB2DCC703C0E500B653CA82273B7BFAD8045D85A470", 32);
    check("keccak256(nullptr, 0)", exp, h.data(), 32);
  }

  // --- Summary ---
  if (fails == 0)
    printf("ok (%d tests passed)\n", total);
  else
    printf("%d / %d tests FAILED\n", fails, total);

  return fails;
}
