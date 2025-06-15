#ifndef BRY_CHALLENGE_CORE_MSG_DIGEST_H
#define BRY_CHALLENGE_CORE_MSG_DIGEST_H

#include <istream>
#include <string>
#include <vector>

namespace bry_challenge {

int msgDigest(std::istream& istream, std::vector<unsigned char>& outDigest);

int msgDigestHex(std::istream& istream, std::string& hexDigest);

}

#endif // BRY_CHALLENGE_CORE_MSG_DIGEST_H
