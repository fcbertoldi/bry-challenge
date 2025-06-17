#ifndef BRY_CHALLENGE_CORE_MSG_DIGEST_H
#define BRY_CHALLENGE_CORE_MSG_DIGEST_H

#include <istream>
#include <stdexcept>
#include <string>
#include <vector>

namespace bry_challenge {

class BryError : public std::runtime_error {
public:
    explicit BryError(const std::string& message);
};

void msgDigest(std::istream& istream, std::vector<unsigned char>& outDigest);

void msgDigestHex(std::istream& istream, std::string& hexDigest);

void cmsSign(
    const char* p12File, const char* passphrase, const char* dataFile, const char* out
);

void cmsSign(
    const unsigned char* p12Data, std::size_t p12Length, const char* passphrase, const char* data, char** out, std::size_t* outLength
);

bool cmsVerify(const char* signedFile);

}

#endif // BRY_CHALLENGE_CORE_MSG_DIGEST_H
