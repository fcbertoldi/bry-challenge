add_executable(tests tests.cpp)
target_link_libraries(tests PRIVATE core Catch2::Catch2WithMain)

include(CTest)
include(Catch)
catch_discover_tests(tests)
