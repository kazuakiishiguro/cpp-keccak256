#include <iostream>
#include <cstring>

#include "keccak256.h"

void help(char *argv) {
    std::cout << "Usage: " << argv << " file_name" << std::endl;
}

int main(int argc, char **argv) {
    const std::uint8_t *hash;

    if (argc != 2 || !strcmp(argv[1], "-h")) {
        help(argv[0]);
        exit(1);
    }

    std::cout << hash << std::endl;
    return 0;
}
