#ifndef BRY_CHALLENGE_CORE_H
#define BRY_CHALLENGE_CORE_H

#include <cstdio>
#include <openssl/err.h>

#if defined(NDEBUG) && !defined(BRY_LOG_OPENSSL_ERRORS)
#define BRY_LOG_OPENSSL_ERROR()
#else
#define BRY_LOG_OPENSSL_ERROR(error) \
do { \
    if (error) {\
        bry_challenge::detail::logOpenSSLError(); \
    }\
} while(0)
#endif

namespace bry_challenge {
namespace detail {

inline void logOpenSSLError() {
    ERR_print_errors_fp(stderr);
}

}
}
#endif
