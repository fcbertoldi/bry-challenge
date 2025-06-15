#include <cstdio>
#include <iostream>
#include <fstream>
#include <vector>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <scope_guard/scope_guard.hpp>

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

    EVP_MD* msgDigest = nullptr;
    EVP_MD_CTX* ctx = nullptr;

    auto ctxGuard = sg::make_scope_guard([&]{
        if (ret != 0) {
            ERR_print_errors_fp(stderr);
        }
        EVP_MD_free(msgDigest);
        EVP_MD_CTX_free(ctx);
    });

    msgDigest = EVP_MD_fetch(nullptr, "SHA-512", nullptr);
    if (!msgDigest) {
        std::cerr << "EVP_MD_fetch could not find SHA-512.\n";
        return ret;
    }

    const int digestLen = EVP_MD_get_size(msgDigest);
    if (digestLen < 0) {
        std::cerr << "EVP_MD_get_size returned invalid size.\n";
        return ret;
    }


    // Initialize OpenSSL digest context
    ctx = EVP_MD_CTX_new();
    if (!ctx) {
        std::cerr << "Error: Failed to create digest context.\n";
        return ret;
    }

    if (EVP_DigestInit_ex(ctx, msgDigest, nullptr) != 1) {
        std::cerr << "Error: EVP_DigestInit_ex failed.\n";
        return ret;
    }

    std::vector<char> buffer(digestLen);
    while (file.good()) {
        file.read(buffer.data(), buffer.size());
        auto bytesRead = file.gcount();
        if (bytesRead > 0 && EVP_DigestUpdate(ctx, buffer.data(), bytesRead) != 1) {
            std::cerr << "Error: EVP_DigestUpdate failed.\n";
            return ret;
        }
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hashLen = 0;

    if (EVP_DigestFinal_ex(ctx, hash, &hashLen) != 1) {
        std::cerr << "Error: EVP_DigestFinal_ex failed.\n";
        return ret;
    }

    printHash(hash, hashLen, filePath);

    ret = 0;
    return ret;
}
