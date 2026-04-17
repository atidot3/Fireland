# ============================================================================
# Fireland — WoW Cataclysm Private Server
# ============================================================================
cmake_minimum_required(VERSION 3.20)

project(Fireland
  VERSION   0.1.0
  LANGUAGES CXX
)

# ----------------------------------------------------------------------------
# IDE: group projects into solution folders
# ----------------------------------------------------------------------------
set_property(GLOBAL PROPERTY USE_FOLDERS ON)

# ----------------------------------------------------------------------------
# C++ standard
# ----------------------------------------------------------------------------
set(CMAKE_CXX_STANDARD          23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS        OFF)

# ----------------------------------------------------------------------------
# Boost configuration (consumed by 3rdParty/boost)
# ----------------------------------------------------------------------------
set(FIRELAND_BOOST_VERSION "1.90.0")
set(FIRELAND_BOOST_COMPONENTS
  asio system regex log date_time test coroutine program_options url charconv multiprecision uuid mysql
)

# ----------------------------------------------------------------------------
# CMake modules
# ----------------------------------------------------------------------------
include(cmake/Platform.cmake)
include(cmake/CompilerOptions.cmake)
include(cmake/Macros.cmake)

# ----------------------------------------------------------------------------
# FetchContent — disable update checks after first download so that
# reconfiguring (e.g. after a CMakeLists.txt edit) never re-fetches or
# re-configures Boost.  Set FETCHCONTENT_UPDATES_DISCONNECTED=OFF to force
# an update check on the next configure.
# ----------------------------------------------------------------------------
option(FETCHCONTENT_UPDATES_DISCONNECTED "Skip FetchContent update step on reconfigure" ON)

# ----------------------------------------------------------------------------
# Dependencies & sources
# ----------------------------------------------------------------------------
add_subdirectory(3rdParty)
add_subdirectory(src)
add_subdirectory(tests)

# ----------------------------------------------------------------------------
# IDE: put CMake utility targets in a CMake/ folder
# ----------------------------------------------------------------------------
set_target_properties(fireland_compiler_options PROPERTIES FOLDER "CMake")
if(TARGET ZERO_CHECK)
  set_target_properties(ZERO_CHECK PROPERTIES FOLDER "CMake")
endif()
if(TARGET ALL_BUILD)
  set_target_properties(ALL_BUILD PROPERTIES FOLDER "CMake")
endif()
