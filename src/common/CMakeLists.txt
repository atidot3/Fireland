# ============================================================================
# common — shared libraries & smoke test
# ============================================================================

# Shared libraries (order matters: Network depends on Utils)
add_subdirectory(Utils)
add_subdirectory(Crypto)
add_subdirectory(Network)

# Smoke-test executable
add_executable(fireland_smoke_test
  main.cpp
)

target_link_libraries(fireland_smoke_test
  PRIVATE
    fireland_compiler_options
    Boost::system
    Boost::regex
    Boost::log
    Boost::date_time
    Boost::coroutine
    Boost::program_options
    Boost::url
    Boost::charconv
)

set_target_properties(fireland_smoke_test PROPERTIES FOLDER "Common")
