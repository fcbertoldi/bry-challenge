cmake_minimum_required(VERSION 3.23)

project(bry-challenge CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

add_subdirectory(external/scope_guard)

find_package(OpenSSL REQUIRED)

include_directories(include)

add_library(core src/core/msg_digest.cpp)
target_include_directories(core PUBLIC include)
target_link_libraries(core PUBLIC OpenSSL::Crypto PRIVATE scope_guard)

add_executable(bry-checksum src/bry_checksum/main.cpp)
target_link_libraries(bry-checksum PRIVATE core)
