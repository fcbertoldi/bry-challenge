add_executable(test-msg-digest test_msg_digest.cpp)
target_link_libraries(test-msg-digest PRIVATE core Catch2::Catch2WithMain)

include(CTest)
include(Catch)
catch_discover_tests(test-msg-digest)
