# ============================================================================
# common/Database — Async MySQL library (Boost.Asio + C++20 coroutines + Boost::mysql)
#
# Depends on firelands_utils for IoContext, logging, etc.
# ============================================================================

set(headers_files
  include/Database/connection_pool_wrapper.h
  
  include/Database/Auth/AuthWrapper.h
  include/Database/Char/CharWrapper.h
)

set(sources_files
  src/connection_pool_wrapper.cpp

  src/Auth/AuthWrapper.cpp
  src/Char/CharWrapper.cpp
)

add_library(firelands_database STATIC
  ${headers_files}
  ${sources_files}
)

target_include_directories(firelands_database
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include/>
    $<INSTALL_INTERFACE:include/>
)

target_link_libraries(firelands_database
  PUBLIC
    firelands_utils   # brings Boost::asio, Boost::system, Boost::log, ws2_32, etc.
    firelands_shared  # for shared data structures
    Boost::mysql
)

# includes for internal use
target_include_directories(firelands_database PRIVATE 
  include/
  src/
)

source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${headers_files} ${sources_files})

set_target_properties(firelands_database PROPERTIES FOLDER "Common")