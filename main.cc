#include <cstdint>
#include <iostream>
#include <cstring>

#include "keccak256.h"

void help(char *argv) {
    std::cout << "Usage: " << argv << " file_name" << std::endl;
}

// read a hex string, return byte length or -a on error.
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

int main(int argc, char **argv) {

    if (argc != 2 || !strcmp(argv[1], "-h")) {
        help(argv[0]);
        exit(1);
    }

    const char *testvec[][2] = {
        {
            // SHA3-256, short message
            "9F2FCC7C90DE090D6B87CD7E9718C1EA6CB21118FC2D5DE9F97E5DB6AC1E9C10",
            "2F1A5F7159E34EA19CDDC70EBF9B81F1A66DB40615D7EAD3CC1F1B954D82A3AF"
        }
    };

    uint8_t sha[64], buf[64], msg[256];
    int sha_len = test_readhex(sha, testvec[0][1], sizeof(sha));

    std::cout << sha_len << std::endl;

    //    Keccak k(msg, buf, sha_len);

    return 0;
}
