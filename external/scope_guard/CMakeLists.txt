add_library(scope_guard INTERFACE)

target_include_directories(scope_guard SYSTEM INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/include)

target_sources(scope_guard INTERFACE
  FILE_SET HEADERS BASE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/include
  FILES ${CMAKE_CURRENT_SOURCE_DIR}/include/scope_guard/scope_guard.hpp
)
