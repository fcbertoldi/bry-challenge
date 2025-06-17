#include <filesystem>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "bry_challenge/core.h"

#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>

#include <catch2/catch_test_macros.hpp>

namespace fs = std::filesystem;

namespace {

const fs::path dataPath(DATA_DIR);

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

    REQUIRE_NOTHROW(bry_challenge::msgDigestHex(data, hexDigest));
    const std::string expected(
        "dc1a7de77c59a29f366a4b154b03ad7d99013e36e08beb50d976358bea7b045884fe72111b27cf7d6302916b2691ac7696c1637e1ab44584d8d6613825149e35"
    );

    REQUIRE(hexDigest == expected);
}

TEST_CASE("cmsSign", "[core]") {
    const char* signedFile = "doc.txt.p7s";
    constexpr const char* passphrase = "bry123456";
    auto certFile = dataPath / "certificado_teste_hub.pfx";
    auto dataFile = dataPath / "doc.txt";

    REQUIRE_NOTHROW(bry_challenge::cmsSign(
        certFile.c_str(),
        passphrase,
        dataFile.c_str(),
        signedFile
    ));

    BIO* p7BIO = BIO_new_file(signedFile, "rb");
    PKCS7* p7 = d2i_PKCS7_bio(p7BIO, nullptr);
    REQUIRE(p7 != nullptr);

    int verifyResult = PKCS7_verify(
        p7, nullptr, nullptr, nullptr, nullptr, PKCS7_NOVERIFY
    );
    REQUIRE(verifyResult == 1);

    // CMS_ContentInfo_free(cms);
    PKCS7_free(p7);
    BIO_free(p7BIO);
}

TEST_CASE("cmsVerify", "[core]") {
    const auto signedFile = dataPath / "doc.txt.p7s";

    const std::string expCommonName = "HUB2 TESTES";
    const std::string expContentInfo = "54657374652076616761206261636b2d656e64204a617661";
    const std::string expAlgo = "sha512";

    bool validSignature = false;
    bry_challenge::SignInfo signInfo;
    REQUIRE_NOTHROW(validSignature = bry_challenge::cmsVerify(signedFile.c_str(), signInfo));

    REQUIRE(validSignature);
    REQUIRE(signInfo.commonName == expCommonName);
    REQUIRE(signInfo.encapContentInfoHex == expContentInfo);
    REQUIRE(signInfo.digestAlgorithm == expAlgo);
}
