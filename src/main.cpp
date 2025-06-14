#include <iostream>
#include <fstream>
#include <vector>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/sha.h>

constexpr size_t BUFFER_SIZE = 8192;

struct MdCtxGuard {
    MdCtxGuard(EVP_MD_CTX* ctx) noexcept : ctx(ctx) {}

    MdCtxGuard(const MdCtxGuard&) = delete;

    MdCtxGuard& operator=(const MdCtxGuard&) = delete;

    ~MdCtxGuard() noexcept {
        if (ctx) {
            EVP_MD_CTX_free(ctx);
        }
    }

    EVP_MD_CTX* ctx;
};

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <file_path>\n";
        return 1;
    }

    const char* filePath = argv[1];
    std::ifstream file(filePath, std::ios::binary);

    if (!file) {
        std::cerr << "Error: Could not open file: " << filePath << "\n";
        return 1;
    }

    // Initialize OpenSSL digest context
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    MdCtxGuard ctxGuard{ctx};
    if (!ctx) {
        std::cerr << "Error: Failed to create digest context.\n";
        return 1;
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha512(), nullptr) != 1) {
        std::cerr << "Error: EVP_DigestInit_ex failed.\n";
        return 1;
    }

    std::vector<char> buffer(BUFFER_SIZE);
    while (file.good()) {
        file.read(buffer.data(), buffer.size());
        std::streamsize bytesRead = file.gcount();
        if (bytesRead > 0) {
            if (EVP_DigestUpdate(ctx, buffer.data(), bytesRead) != 1) {
                std::cerr << "Error: EVP_DigestUpdate failed.\n";
                return 1;
            }
        }
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hashLen = 0;

    if (EVP_DigestFinal_ex(ctx, hash, &hashLen) != 1) {
        std::cerr << "Error: EVP_DigestFinal_ex failed.\n";
        return 1;
    }

    // Output hash in hexadecimal format
    for (unsigned int i = 0; i < hashLen; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    std::cout << "  " << filePath << std::endl;

    return 0;
}
