# ============================================================================
# Boost — Download and configure via FetchContent
# ============================================================================
#
# Downloads Boost ${FIRELAND_BOOST_VERSION} from GitHub releases and builds
# only the components listed in FIRELAND_BOOST_COMPONENTS (set in root CMake).
#
# IMPORTANT: Only GitHub releases contain CMakeLists.txt.
#            SourceForge / official tarballs do NOT work with CMake.
# ============================================================================

# ----------------------------------------------------------------------------
# Fast path: if Boost was previously installed via the 'deps' preset, use it
# directly via find_package — FetchContent is never invoked.
# ----------------------------------------------------------------------------
find_package(Boost ${FIRELAND_BOOST_VERSION} QUIET CONFIG)
if(Boost_FOUND)
  message(STATUS "[Fireland] Boost ${Boost_VERSION} found at ${Boost_DIR} — skipping FetchContent")
  return()
endif()

# Slow path: first run or 'deps' preset — download and build from source.
message(STATUS "[Fireland] Boost not found locally, fetching from source...")

include(FetchContent)

# Version string manipulation (1.90.0 -> 1_90_0 for URL paths if needed)
string(REPLACE "." "_" _boost_version_underscored "${FIRELAND_BOOST_VERSION}")

# ----------------------------------------------------------------------------
# Declare Boost download
# ----------------------------------------------------------------------------
set(_boost_url_base "https://github.com/boostorg/boost/releases/download/boost-${FIRELAND_BOOST_VERSION}")

FetchContent_Declare(Boost
  URL             "${_boost_url_base}/boost-${FIRELAND_BOOST_VERSION}-cmake.tar.xz"
  # Fallback URLs for environments where .tar.xz is not supported
  # URL          "${_boost_url_base}/boost-${FIRELAND_BOOST_VERSION}-cmake.tar.gz"
  # URL          "${_boost_url_base}/boost-${FIRELAND_BOOST_VERSION}-cmake.zip"
  DOWNLOAD_EXTRACT_TIMESTAMP ON
  FIND_PACKAGE_ARGS ${FIRELAND_BOOST_VERSION} CONFIG
)

# ----------------------------------------------------------------------------
# Configure which Boost libraries to build
# ----------------------------------------------------------------------------
# Only build the components we need — dramatically reduces build time
set(BOOST_INCLUDE_LIBRARIES "${FIRELAND_BOOST_COMPONENTS}" CACHE STRING "" FORCE)

# Static linking
set(BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)

# Disable optional subsystems we don't need
set(BOOST_ENABLE_MPI    OFF CACHE BOOL "" FORCE)
set(BOOST_ENABLE_PYTHON OFF CACHE BOOL "" FORCE)

# Suppress Boost internal testing
set(BUILD_TESTING OFF CACHE BOOL "" FORCE)

# ----------------------------------------------------------------------------
# Make Boost available
# ----------------------------------------------------------------------------
message(STATUS "[Fireland] Fetching Boost ${FIRELAND_BOOST_VERSION} ...")
message(STATUS "[Fireland] Boost components: ${FIRELAND_BOOST_COMPONENTS}")

FetchContent_MakeAvailable(Boost)

# ----------------------------------------------------------------------------
# IDE: move all Boost targets into Dependencies/Boost solution folder
# ----------------------------------------------------------------------------
get_property(_all_targets DIRECTORY "${boost_SOURCE_DIR}" PROPERTY BUILDSYSTEM_TARGETS)
foreach(_target IN LISTS _all_targets)
  set_target_properties(${_target} PROPERTIES FOLDER "Dependencies/Boost")
endforeach()

# Also gather targets from Boost library subdirectories
get_property(_boost_subdirs DIRECTORY "${boost_SOURCE_DIR}" PROPERTY SUBDIRECTORIES)
foreach(_subdir IN LISTS _boost_subdirs)
  get_property(_sub_targets DIRECTORY "${_subdir}" PROPERTY BUILDSYSTEM_TARGETS)
  foreach(_target IN LISTS _sub_targets)
    set_target_properties(${_target} PROPERTIES FOLDER "Dependencies/Boost")
  endforeach()
  # One level deeper (e.g. libs/<name>)
  get_property(_sub_subdirs DIRECTORY "${_subdir}" PROPERTY SUBDIRECTORIES)
  foreach(_sub_subdir IN LISTS _sub_subdirs)
    get_property(_sub_sub_targets DIRECTORY "${_sub_subdir}" PROPERTY BUILDSYSTEM_TARGETS)
    foreach(_target IN LISTS _sub_sub_targets)
      set_target_properties(${_target} PROPERTIES FOLDER "Dependencies/Boost")
    endforeach()
  endforeach()
endforeach()

message(STATUS "[Fireland] Boost ${FIRELAND_BOOST_VERSION} ready")

# ----------------------------------------------------------------------------
# When running the 'deps' preset, install Boost to CMAKE_INSTALL_PREFIX so
# subsequent dev builds can find it via find_package without rebuilding.
# ----------------------------------------------------------------------------
if(FIRELAND_DEPS_ONLY AND CMAKE_INSTALL_PREFIX)
  message(STATUS "[Fireland] Boost will be installed to ${CMAKE_INSTALL_PREFIX}")
  install(CODE "
    message(STATUS \"Installing Boost to ${CMAKE_INSTALL_PREFIX}...\")
    execute_process(
      COMMAND \"${CMAKE_COMMAND}\" --install \"${boost_BINARY_DIR}\"
                                  --prefix  \"${CMAKE_INSTALL_PREFIX}\"
    )
  ")
endif()
