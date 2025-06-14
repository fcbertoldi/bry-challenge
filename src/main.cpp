#include <iostream>
#include <fstream>
#include <vector>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/sha.h>

namespace {

constexpr size_t BUFFER_SIZE = 8192;

class MdCtxGuard {
public:
    explicit MdCtxGuard(EVP_MD_CTX* ctx = EVP_MD_CTX_new()) noexcept
        : ctx_(ctx) {}

    ~MdCtxGuard() noexcept {
        if (ctx_) {
            EVP_MD_CTX_free(ctx_);
        }
    }

    MdCtxGuard(const MdCtxGuard&) = delete;
    MdCtxGuard& operator=(const MdCtxGuard&) = delete;
    MdCtxGuard(MdCtxGuard&&) = delete;
    MdCtxGuard& operator=(MdCtxGuard&&) = delete;

    EVP_MD_CTX* get() const noexcept { return ctx_; }
    operator EVP_MD_CTX*() const noexcept { return ctx_; }

private:
    EVP_MD_CTX* ctx_;
};

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

    // Initialize OpenSSL digest context
    MdCtxGuard ctx;
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
        auto bytesRead = file.gcount();
        if (bytesRead > 0 && EVP_DigestUpdate(ctx, buffer.data(), bytesRead) != 1) {
            std::cerr << "Error: EVP_DigestUpdate failed.\n";
            return 1;
        }
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hashLen = 0;

    if (EVP_DigestFinal_ex(ctx, hash, &hashLen) != 1) {
        std::cerr << "Error: EVP_DigestFinal_ex failed.\n";
        return 1;
    }

    printHash(hash, hashLen, filePath);

    return 0;
}
