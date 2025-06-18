#include "bry_challenge/core.h"
#include "core_utils.h"
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <openssl/bio.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <openssl/x509.h>
#include <scope_guard/scope_guard.hpp>

namespace {

void cmsSign(PKCS12* p12, const char* passphrase, BIO* data, BIO* out) {
    int ret = 1;
    EVP_PKEY *pkey = nullptr;
    X509 *cert = nullptr;
    STACK_OF(X509) *ca = nullptr;
    EVP_MD* msgDigest = nullptr;

    CMS_ContentInfo *cms = nullptr;
    int flags = CMS_BINARY | CMS_PARTIAL;

    auto cleanupGuard = sg::make_scope_guard([&]{
        EVP_MD_free(msgDigest);
        CMS_ContentInfo_free(cms);
        X509_free(cert);
        EVP_PKEY_free(pkey);
        OSSL_STACK_OF_X509_free(ca);
    });

    if (!PKCS12_parse(p12, passphrase, &pkey, &cert, &ca)) {
        throw bry_challenge::InvalidPKCS12("Error parsing PKCS#12 file");
    }

    cms = CMS_sign(nullptr, nullptr, nullptr, data, flags);
    if (!cms) {
        throw bry_challenge::BryError("Error signing data");
    }

    msgDigest = EVP_MD_fetch(nullptr, "SHA-512", nullptr);
    if (!msgDigest) {
        throw bry_challenge::BryError("EVP_MD_fetch could not find SHA-512");
    }

    if (!CMS_add1_signer(cms, cert, pkey, msgDigest, 0)) {
        throw bry_challenge::BryError("CMS_add1_signer failed");
    }

    if (!CMS_final(cms, data, nullptr, flags)) {
        throw bry_challenge::BryError("CMS_final failed");
    }

    if (!i2d_CMS_bio(out, cms)) {
        throw bry_challenge::BryError("Error writing signed CMS file");
    }
}

std::string asn1ToHex(const ASN1_OCTET_STRING* str) {
    std::ostringstream oss;
    for (int i = 0; i < str->length; ++i) {
        oss << std::hex << std::setfill('0') << std::setw(2)
            << static_cast<int>(str->data[i]);
    }
    return oss.str();
}

// Helper: Convert ASN1_TIME to readable string
void extractX509Data(PKCS7* p7, bry_challenge::SignInfo& signInfo) {
    PKCS7_SIGNED* signedData = p7->d.sign;

    // === Certificates: Print CN ===
    STACK_OF(X509)* certs = signedData->cert;
    for (int i = 0; i < sk_X509_num(certs); ++i) {
        X509* cert = sk_X509_value(certs, i);
        X509_NAME* subj = X509_get_subject_name(cert);
        int cn_index = X509_NAME_get_index_by_NID(subj, NID_commonName, -1);
        if (cn_index >= 0) {
            X509_NAME_ENTRY* cn_entry = X509_NAME_get_entry(subj, cn_index);
            ASN1_STRING* cn_asn1 = X509_NAME_ENTRY_get_data(cn_entry);
            unsigned char* cn_utf8 = nullptr;
            ASN1_STRING_to_UTF8(&cn_utf8, cn_asn1);
            signInfo.commonName = reinterpret_cast<char*>(cn_utf8);
            OPENSSL_free(cn_utf8);
        }
    }

    // === Signer Info ===
    STACK_OF(PKCS7_SIGNER_INFO)* signers = signedData->signer_info;
    PKCS7_SIGNER_INFO* si = sk_PKCS7_SIGNER_INFO_value(signers, 0);

    // -- Digest Algorithm --
    int digest_nid = OBJ_obj2nid(si->digest_alg->algorithm);
    signInfo.digestAlgorithm = OBJ_nid2ln(digest_nid);

    // -- Signing Time (if present) --
    ASN1_TYPE* signing_time_asn1 = PKCS7_get_signed_attribute(si, NID_pkcs9_signingTime);
    if (signing_time_asn1 && signing_time_asn1->type == V_ASN1_UTCTIME) {
        ASN1_TIME* signingTime = signing_time_asn1->value.utctime;
        ASN1_TIME_to_tm(signingTime, &signInfo.signingTime);
    }

    // === Encapsulated content (encapContentInfo) ===
    if (signedData->contents->d.other->type == V_ASN1_OCTET_STRING) {
        ASN1_OCTET_STRING* content = signedData->contents->d.other->value.octet_string;
        signInfo.encapContentInfoHex = asn1ToHex(content);
    } else if (signedData->contents->d.data) {
        ASN1_OCTET_STRING* content = signedData->contents->d.data;
        signInfo.encapContentInfoHex = asn1ToHex(content);
    }
}

bool cmsVerify(BIO* signedBIO, bry_challenge::SignInfo& signInfo) {
    PKCS7* p7 = nullptr;
    auto cleanupGuard = sg::make_scope_guard([&]{
        PKCS7_free(p7);
    });

    p7 = d2i_PKCS7_bio(signedBIO, nullptr);
    if (!p7) {
        throw bry_challenge::BryError("Error while parsing signed file.");
    }

    STACK_OF(X509)* certs = p7->d.sign->cert;
    if (!certs) {
        throw bry_challenge::BryError("No certificates found in SignedData");
    }

    ::extractX509Data(p7, signInfo);

    int verifyResult = PKCS7_verify(
        p7, nullptr, nullptr, nullptr, nullptr, PKCS7_NOVERIFY
    );
    return verifyResult == 1;
}

}

namespace bry_challenge {

void cmsSign(
    const char* p12File, const char* passphrase, const char* dataFile, const char* out
) {
    int ret = 1;
    BIO* p12BIO = nullptr;
    BIO* dataBIO = nullptr;
    BIO* outBIO = nullptr;
    PKCS12* p12 = nullptr;

    auto cleanupGuard = sg::make_scope_guard([&]{
        BRY_LOG_OPENSSL_ERROR(ret != 0);
        PKCS12_free(p12);
        BIO_free(p12BIO);
        BIO_free(dataBIO);
        BIO_free(outBIO);
    });

    // Create BIO from file
    p12BIO = BIO_new_file(p12File, "rb");
    if (!p12BIO) {
        throw BryError("Error: Failed to create new PKCS12 BIO file");
    }

    p12 = d2i_PKCS12_bio(p12BIO, nullptr);
    if (!p12) {
        throw InvalidPKCS12("Error: Failed to read PKCS12 file");
    }

    dataBIO = BIO_new_file(dataFile, "r");
    if (!dataBIO) {
        throw BryError("Error: Failed to create new data BIO file");
    }

    outBIO = BIO_new_file(out, "wb");
    if (!dataBIO) {
        throw BryError("Error: Failed to create new out BIO file");
    }

    ::cmsSign(p12, passphrase, dataBIO, outBIO);
    ret = 0;
}

void cmsSign(
    const unsigned char* p12Data, std::size_t p12Length, const char* passphrase, const char* data, std::size_t dataLength, char** out, std::size_t* outLength
) {
    if (!p12Data || p12Length == 0 || !passphrase || !data || !out) {
        throw BryError("Invalid input parameters");
    }

    PKCS12* p12 = d2i_PKCS12(nullptr, &p12Data, static_cast<long>(p12Length));
    if (!p12) {
        throw BryError("Failed to parse PKCS#12 data");
    }

    BIO* dataBio = BIO_new_mem_buf(data, dataLength);
    if (!dataBio) {
        PKCS12_free(p12);
        throw BryError("Failed to create BIO for data");
    }

    BIO* outBio = BIO_new(BIO_s_mem());
    if (!outBio) {
        BIO_free(dataBio);
        PKCS12_free(p12);
        throw BryError("Failed to create BIO for output");
    }

    try {
        ::cmsSign(p12, passphrase, dataBio, outBio);
    } catch (const std::exception& err) {
        *out = nullptr;
        *outLength = 0;

        throw;
    }

    BUF_MEM* bptr = nullptr;
    *outLength = BIO_get_mem_data(outBio, out);
    BIO_get_mem_ptr(outBio, &bptr);
    BIO_set_close(outBio, BIO_NOCLOSE);
    bptr->data = nullptr;    // orphan buffer (you own it now)
    BUF_MEM_free(bptr);      // free only the BUF_MEM struct

    BIO_free(outBio);  // won't free buffer due to BIO_NOCLOSE
    BIO_free(dataBio);
    PKCS12_free(p12);
}

bool cmsVerify(const char* signedFile, SignInfo& signInfo) {
    int ret = 1;
    BIO* p7BIO = nullptr;

    auto cleanupGuard = sg::make_scope_guard([&]{
        BRY_LOG_OPENSSL_ERROR(ret != 0);
        BIO_free(p7BIO);
    });

    p7BIO = BIO_new_file(signedFile, "rb");
    if (!p7BIO) {
        throw BryError("Could not open signed file");
    }

    return ::cmsVerify(p7BIO, signInfo);
}

bool cmsVerify(const char* signedData, std::size_t signedLen, SignInfo& signInfo) {
    int ret = 1;
    BIO* signedBIO = nullptr;
    auto cleanupGuard = sg::make_scope_guard([&]{
        BIO_free(signedBIO);
    });
    signedBIO = BIO_new_mem_buf(signedData, signedLen);

    return ::cmsVerify(signedBIO, signInfo);
}

}
