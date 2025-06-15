#include "bry_challenge/core.h"
#include <iostream>
#include <openssl/bio.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#include <scope_guard/scope_guard.hpp>

namespace {

int cmsSign(PKCS12* p12, const char* passphrase, BIO* data, BIO* out) {
    int ret = 1;
    EVP_PKEY *pkey = nullptr;
    X509 *cert = nullptr;
    STACK_OF(X509) *ca = nullptr;

    CMS_ContentInfo *cms = nullptr;
    int flags = CMS_BINARY;

    auto cleanupGuard = sg::make_scope_guard([&]{
        CMS_ContentInfo_free(cms);
        X509_free(cert);
        EVP_PKEY_free(pkey);
        OSSL_STACK_OF_X509_free(ca);
    });

    if (!PKCS12_parse(p12, passphrase, &pkey, &cert, &ca)) {
        std::cerr << "Error parsing PKCS#12 file\n";
        return ret;
    }

    cms = CMS_sign(cert, pkey, nullptr, data, flags);
    if (!cms) {
        std::cerr << "Error signing data.\n";
        return ret;
    }

    if (!i2d_CMS_bio(out, cms)) {
        std::cerr << "Error writing signed CMS file.\n";
        return ret;
    }


    return 0;
}

}

namespace bry_challenge {

int cmsSign(
    const char* p12File, const char* passphrase, const char* dataFile, const char* out
) {
    int ret = 0;
    BIO* p12BIO = nullptr;
    BIO* dataBIO = nullptr;
    BIO* outBIO = nullptr;
    PKCS12* p12 = nullptr;

    auto cleanupGuard = sg::make_scope_guard([&]{
        if (ret != 0) {
            ERR_print_errors_fp(stderr);
        }

        PKCS12_free(p12);
        BIO_free(p12BIO);
        BIO_free(dataBIO);
        BIO_free(outBIO);
    });

    // Create BIO from file
    p12BIO = BIO_new_file(p12File, "rb");
    if (!p12BIO) {
        std::cerr << "Error: Failed to create new PKCS12 BIO file";
        ret = 1;
        return ret;
    }

    p12 = d2i_PKCS12_bio(p12BIO, nullptr);
    if (!p12) {
        std::cerr << "Error: Failed to read PKCS12 file";
        ret = 1;
        return ret;
    }

    dataBIO = BIO_new_file(dataFile, "r");
    if (!dataBIO) {
        std::cerr << "Error: Failed to create new data BIO file";
        ret = 1;
        return ret;
    }

    outBIO = BIO_new_file(out, "wb");
    if (!dataBIO) {
        std::cerr << "Error: Failed to create new out BIO file";
        ret = 1;
        return ret;
    }

    ret = ::cmsSign(p12, passphrase, dataBIO, outBIO);
    return ret;
}


}
