# ============================================================================
# common/Database — Async MySQL library (Boost.Asio + C++20 coroutines + Boost::mysql)
#
# Depends on fireland_utils for IoContext, logging, etc.
# ============================================================================

set(headers_files
  include/Database/connection_pool_wrapper.h
  
  include/Database/Auth/AuthWrapper.h
)

set(sources_files
  src/connection_pool_wrapper.cpp

  src/Auth/AuthWrapper.cpp
)

add_library(fireland_database STATIC
  ${headers_files}
  ${sources_files}
)

target_include_directories(fireland_database
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include/>
    $<INSTALL_INTERFACE:include/>
)

target_link_libraries(fireland_database
  PUBLIC
    fireland_utils   # brings Boost::asio, Boost::system, Boost::log, ws2_32, etc.
    fireland_shared  # for shared data structures
    Boost::mysql
)

# includes for internal use
target_include_directories(fireland_database PRIVATE 
  include/
  src/
)

source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${headers_files} ${sources_files})

set_target_properties(fireland_database PROPERTIES FOLDER "Common")