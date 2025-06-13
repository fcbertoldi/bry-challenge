cmake_minimum_required(VERSION 3.23)

project(bry-challenge CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

find_package(OpenSSL REQUIRED)

add_executable(bry-checksum src/main.cpp)
target_link_libraries(bry-checksum PRIVATE OpenSSL::Crypto)
