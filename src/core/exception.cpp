#include "bry_challenge/core.h"

namespace bry_challenge {

BryError::BryError(const std::string& message) : std::runtime_error(message) {}

PKCS12Error::PKCS12Error(const std::string& message) : BryError(message) {}

PKCS7Error::PKCS7Error(const std::string& message) : BryError(message) {}

}
