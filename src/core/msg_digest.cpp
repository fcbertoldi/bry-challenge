#include "bry_challenge/core/msg_digest.h"

#include <iostream>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <scope_guard/scope_guard.hpp>


namespace {

constexpr size_t BUFFER_SIZE = 8192;

}

namespace bry_challenge {

int msgDigest(std::istream& istream, std::vector<unsigned char>& outDigest) {
    int ret = 1;
    if (!istream) {
        std::cerr << "Istream error \n";
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

    std::vector<char> buffer(BUFFER_SIZE);
    while (istream.good()) {
        istream.read(buffer.data(), buffer.size());
        auto bytesRead = istream.gcount();
        if (bytesRead > 0 && EVP_DigestUpdate(ctx, buffer.data(), bytesRead) != 1) {
            std::cerr << "Error: EVP_DigestUpdate failed.\n";
            return ret;
        }
    }

    const int digestLen = EVP_MD_get_size(msgDigest);
    if (digestLen < 0) {
        std::cerr << "EVP_MD_get_size returned invalid size.\n";
        return ret;
    }

    outDigest.resize(digestLen);
    unsigned int hashLen = 0;

    if (EVP_DigestFinal_ex(ctx, outDigest.data(), &hashLen) != 1) {
        std::cerr << "Error: EVP_DigestFinal_ex failed.\n";
        return ret;
    }

    outDigest.resize(hashLen);

    ret = 0;
    return ret;
}

}
