#include "bry_challenge/core.h"
#include "core_utils.h"

#include <iomanip>
#include <iostream>
#include <sstream>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <scope_guard/scope_guard.hpp>


namespace {

constexpr size_t BUFFER_SIZE = 8192;

std::string toHex(const unsigned char* hash, unsigned int len) {
    std::ostringstream sstream;
    sstream << std::hex << std::setfill('0');
    for (unsigned int i = 0; i < len; ++i) {
        sstream << std::setw(2) << static_cast<int>(hash[i]);
    }

    return sstream.str();
}

}

namespace bry_challenge {

BryError::BryError(const std::string& message) : std::runtime_error(message) {}

void msgDigest(std::istream& istream, std::vector<unsigned char>& outDigest) {
    int ret = 1;

    EVP_MD* msgDigest = nullptr;
    EVP_MD_CTX* ctx = nullptr;

    auto ctxGuard = sg::make_scope_guard([&]{
        BRY_LOG_OPENSSL_ERROR(ret != 0);
        EVP_MD_free(msgDigest);
        EVP_MD_CTX_free(ctx);
    });

    msgDigest = EVP_MD_fetch(nullptr, "SHA-512", nullptr);
    if (!msgDigest) {
        throw BryError("EVP_MD_fetch could not find SHA-512");
    }

    // Initialize OpenSSL digest context
    ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw BryError("Error: Failed to create digest context");
    }

    if (EVP_DigestInit_ex(ctx, msgDigest, nullptr) != 1) {
        throw BryError("Error: EVP_DigestInit_ex failed");
    }

    std::vector<char> buffer(BUFFER_SIZE);
    while (istream.good()) {
        istream.read(buffer.data(), buffer.size());
        auto bytesRead = istream.gcount();
        if (bytesRead > 0 && EVP_DigestUpdate(ctx, buffer.data(), bytesRead) != 1) {
            throw BryError("Error: EVP_DigestUpdate failed");
        }
    }

    const int digestLen = EVP_MD_get_size(msgDigest);
    if (digestLen < 0) {
        throw BryError("EVP_MD_get_size returned invalid size");
    }

    outDigest.resize(digestLen);
    unsigned int hashLen = 0;

    if (EVP_DigestFinal_ex(ctx, outDigest.data(), &hashLen) != 1) {
        throw BryError("Error: EVP_DigestFinal_ex failed");
    }

    outDigest.resize(hashLen);
}

void msgDigestHex(std::istream& istream, std::string& hexDigest) {
    std::vector<unsigned char> outDigest;
    msgDigest(istream, outDigest);
    hexDigest = toHex(outDigest.data(), outDigest.size());
}

}
