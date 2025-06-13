#include <iostream>
#include <fstream>
#include <vector>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/sha.h>

constexpr size_t BUFFER_SIZE = 8192;

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <file_path>\n";
        return 1;
    }

    const char* file_path = argv[1];
    std::ifstream file(file_path, std::ios::binary);

    if (!file) {
        std::cerr << "Error: Could not open file: " << file_path << "\n";
        return 1;
    }

    // Initialize OpenSSL digest context
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        std::cerr << "Error: Failed to create digest context.\n";
        return 1;
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha512(), nullptr) != 1) {
        std::cerr << "Error: EVP_DigestInit_ex failed.\n";
        EVP_MD_CTX_free(ctx);
        return 1;
    }

    std::vector<char> buffer(BUFFER_SIZE);
    while (file.good()) {
        file.read(buffer.data(), buffer.size());
        std::streamsize bytes_read = file.gcount();
        if (bytes_read > 0) {
            if (EVP_DigestUpdate(ctx, buffer.data(), bytes_read) != 1) {
                std::cerr << "Error: EVP_DigestUpdate failed.\n";
                EVP_MD_CTX_free(ctx);
                return 1;
            }
        }
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;

    if (EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
        std::cerr << "Error: EVP_DigestFinal_ex failed.\n";
        EVP_MD_CTX_free(ctx);
        return 1;
    }

    EVP_MD_CTX_free(ctx);

    // Output hash in hexadecimal format
    for (unsigned int i = 0; i < hash_len; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    std::cout << "  " << file_path << std::endl;

    return 0;
}
