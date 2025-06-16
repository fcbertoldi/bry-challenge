#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "bry_challenge/core.h"
#include "p12_data.h"
#include "signed_data.h"

#include <openssl/cms.h>
#include <openssl/x509.h>
#include <openssl/err.h>

#include <catch2/catch_test_macros.hpp>

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
    char* out;
    std::size_t outLength;


    std::string data("Teste vaga back-end Java");
    std::string passphrase("bry123456");
    int ret = bry_challenge::cmsSign(
        data_certificado_teste_hub_pfx,
        sizeof(data_certificado_teste_hub_pfx),
        passphrase.data(),
        data.data(),
        &out,
        &outLength
    );

    REQUIRE(ret == 0);

    BIO* cms_bio = BIO_new_mem_buf(out, outLength);
    BIO* data_bio = BIO_new_mem_buf(data.data(), static_cast<int>(data.size()));
    BIO* out_bio = BIO_new(BIO_s_mem());

    CMS_ContentInfo* cms = d2i_CMS_bio(cms_bio, nullptr);
    REQUIRE(cms != nullptr);

    // NULL store == use certs embedded in CMS
    X509_STORE* store = X509_STORE_new();
    REQUIRE(store != nullptr);

    int verify_result = CMS_verify(cms, nullptr, store, data_bio, out_bio, CMS_BINARY);
    REQUIRE(verify_result == 1); // Signature must be valid

    CMS_ContentInfo_free(cms);
    X509_STORE_free(store);
    BIO_free(cms_bio);
    BIO_free(data_bio);
    BIO_free(out_bio);
    std::free(out);
}
