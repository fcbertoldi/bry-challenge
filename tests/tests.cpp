#include <filesystem>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "bry_challenge/core.h"

#include <openssl/cms.h>
#include <openssl/x509.h>
#include <openssl/err.h>

#include <catch2/catch_test_macros.hpp>

namespace fs = std::filesystem;

namespace {



std::string toHex(const char* hash, unsigned int len) {
    std::ostringstream sstream;
    sstream << std::hex << std::setfill('0');
    for (unsigned int i = 0; i < len; ++i) {
        sstream << std::setw(2) << static_cast<int>(hash[i]);
    }

    return sstream.str();
}
}

TEST_CASE("msgDigest", "[core]") {
    std::istringstream data("Teste vaga back-end Java");
    std::string hexDigest;
    bry_challenge::msgDigestHex(data, hexDigest);

    const std::string expected(
        "dc1a7de77c59a29f366a4b154b03ad7d99013e36e08beb50d976358bea7b045884fe72111b27cf7d6302916b2691ac7696c1637e1ab44584d8d6613825149e35"
    );

    REQUIRE(hexDigest == expected);
}

TEST_CASE("cmsSign", "[core]") {
    const fs::path dataPath(DATA_DIR);
    const char* p7File = "doc.txt.p7s";
    constexpr const char* passphrase = "bry123456";

    int ret = bry_challenge::cmsSign(
        (dataPath / "certificado_teste_hub.pfx").c_str(),
        passphrase,
        (dataPath / "doc.txt").c_str(),
        p7File
    );

    REQUIRE(ret == 0);

    BIO* p7BIO = BIO_new_file(p7File, "rb");
    CMS_ContentInfo* cms = d2i_CMS_bio(p7BIO, nullptr);
    REQUIRE(cms != nullptr);

    int verifyResult = CMS_verify(
        cms,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        CMS_NO_SIGNER_CERT_VERIFY
    );

    if (verifyResult != 1) {
        ERR_print_errors_fp(stderr);
    }
    REQUIRE(verifyResult == 1);

    CMS_ContentInfo_free(cms);
    BIO_free(p7BIO);
}
