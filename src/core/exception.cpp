#include "bry_challenge/core.h"

namespace bry_challenge {

BryError::BryError(const std::string& message) : std::runtime_error(message) {}

InvalidPKCS12::InvalidPKCS12(const std::string& message) : BryError(message) {}

}
