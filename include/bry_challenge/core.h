#ifndef BRY_CHALLENGE_CORE_MSG_DIGEST_H
#define BRY_CHALLENGE_CORE_MSG_DIGEST_H

#include <ctime>
#include <istream>
#include <stdexcept>
#include <string>
#include <vector>

namespace bry_challenge {

class BryError : public std::runtime_error {
public:
    explicit BryError(const std::string& message);
};

class PKCS12Error : public BryError {
public:
    explicit PKCS12Error(const std::string& message);
};

class PKCS7Error : public BryError {
public:
    explicit PKCS7Error(const std::string& message);
};

struct SignInfo {
    std::string commonName;
    std::tm signingTime;
    std::string encapContentInfoHex;
    std::string digestAlgorithm;
};

void msgDigest(std::istream& istream, std::vector<unsigned char>& outDigest);

void msgDigestHex(std::istream& istream, std::string& hexDigest);

void cmsSign(
    const char* p12File, const char* passphrase, const char* dataFile, const char* out
);

void cmsSign(
    const char* p12Data, std::size_t p12Length, const char* passphrase, const char* data, std::size_t dataLength, char** out, std::size_t* outLength
);

bool cmsVerify(const char* signedFile, SignInfo& signInfo);

bool cmsVerify(const char* signedData, std::size_t signedLen, SignInfo& signInfo);

}

#endif // BRY_CHALLENGE_CORE_MSG_DIGEST_H
