cmake_minimum_required(VERSION 3.23)

project(bry-challenge CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

add_subdirectory(external/scope_guard)

find_package(OpenSSL REQUIRED)
find_package(Catch2 CONFIG REQUIRED)
find_package(Poco REQUIRED COMPONENTS Foundation Net Util)

include_directories(include)

add_library(core STATIC src/core/msg_digest.cpp src/core/cms_signature.cpp src/core/exception.cpp)
target_include_directories(core PUBLIC include)
target_link_libraries(core PUBLIC OpenSSL::Crypto PRIVATE scope_guard)

add_executable(bry-checksum src/bry_checksum.cpp)
target_link_libraries(bry-checksum PRIVATE core)

add_executable(bry-signature src/bry_signature.cpp)
target_link_libraries(bry-signature PRIVATE core)

add_executable(bry-verify src/bry_verify.cpp)
target_link_libraries(bry-verify PRIVATE core)

add_executable(bry-server src/bry_server.cpp)
target_link_libraries(bry-server PRIVATE core Poco::Foundation Poco::Net Poco::Util)

add_executable(tests tests/tests.cpp)
target_compile_definitions(tests PRIVATE DATA_DIR="${PROJECT_SOURCE_DIR}/data")
target_link_libraries(tests PRIVATE core Catch2::Catch2WithMain)
include(CTest)
include(Catch)
catch_discover_tests(tests)
