#include "bry_challenge/core.h"
#include <cstdio>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <iomanip>


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
    std::string hexDigest;
    ret = bry_challenge::msgDigestHex(file, hexDigest);
    if (ret != 0) {
        return ret;
    }

    std::cout << hexDigest << "  " << filePath << std::endl;

    ret = 0;
    return ret;
}
