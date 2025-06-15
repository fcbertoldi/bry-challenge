#include "bry_challenge/core/msg_digest.h"
#include <cstdio>
#include <iostream>
#include <fstream>
#include <vector>
#include <iomanip>

namespace {

// output hash in hexadecimal format
void printHash(const unsigned char* hash, unsigned int len, const char* filePath) {
    std::cout << std::hex << std::setfill('0');
    for (unsigned int i = 0; i < len; ++i) {
        std::cout << std::setw(2) << static_cast<int>(hash[i]);
    }
    std::cout << "  " << filePath << std::endl;
}

}

int main(int argc, char* argv[]) {

    int ret = 1;

    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <file_path>\n";
        return ret;
    }

    const char* filePath = argv[1];
    std::ifstream file(filePath, std::ios::binary);

    if (!file) {
        std::cerr << "Error: Could not open file: " << filePath << '\n';
        return ret;
    }

    std::vector<unsigned char> hash;
    ret = bry_challenge::msgDigest(file, hash);
    if (ret != 0) {
        return ret;
    }
    printHash(hash.data(), hash.size(), filePath);

    ret = 0;
    return ret;
}
