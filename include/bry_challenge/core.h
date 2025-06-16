#ifndef BRY_CHALLENGE_CORE_MSG_DIGEST_H
#define BRY_CHALLENGE_CORE_MSG_DIGEST_H

#include <istream>
#include <string>
#include <vector>

namespace bry_challenge {

int msgDigest(std::istream& istream, std::vector<unsigned char>& outDigest);

int msgDigestHex(std::istream& istream, std::string& hexDigest);

int cmsSign(
    const char* p12File, const char* passphrase, const char* dataFile, const char* out
);

int cmsSign(
    const unsigned char* p12Data, std::size_t p12Length, const char* passphrase, const char* data, char** out, std::size_t* outLength
);

}

#endif // BRY_CHALLENGE_CORE_MSG_DIGEST_H
