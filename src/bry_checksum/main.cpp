#include "bry_challenge/core.h"
#include <cstdio>
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <iomanip>


int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <file_path>\n";
        return 1;
    }

    const char* filePath = argv[1];
    std::ifstream file(filePath, std::ios::binary);

    if (!file) {
        std::cerr << "Error: Could not open file: " << filePath << '\n';
        return 1;
    }

    std::vector<unsigned char> hash;
    std::string hexDigest;
    try {
        bry_challenge::msgDigestHex(file, hexDigest);
    } catch (const std::exception& err) {
        std::cerr << "Error: " << err.what() << '\n';
        return 1;
    }

    std::cout << hexDigest << "  " << filePath << std::endl;

    return 0;
}
