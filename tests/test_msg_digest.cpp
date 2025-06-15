#include <sstream>
#include <string>
#include <vector>

#include "bry_challenge/core/msg_digest.h"

#include <catch2/catch_test_macros.hpp>


TEST_CASE("msgDigest", "[core]") {
    std::istringstream data("Teste vaga back-end Java");
    std::string hexDigest;
    bry_challenge::msgDigestHex(data, hexDigest);

    const std::string expected(
        "dc1a7de77c59a29f366a4b154b03ad7d99013e36e08beb50d976358bea7b045884fe72111b27cf7d6302916b2691ac7696c1637e1ab44584d8d6613825149e35"
    );

    REQUIRE(hexDigest == expected);
}
