#ifndef BRY_CHALLENGE_CORE_MSG_DIGEST_H
#define BRY_CHALLENGE_CORE_MSG_DIGEST_H

#include <istream>
#include <vector>

namespace bry_challenge {

int msgDigest(std::istream& istream, std::vector<unsigned char>& outDigest);

}

#endif // BRY_CHALLENGE_CORE_MSG_DIGEST_H
