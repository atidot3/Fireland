# ============================================================================
# common/Database — Async MySQL library (Boost.Asio + C++20 coroutines + Boost::mysql)
#
# Depends on fireland_utils for IoContext, logging, etc.
# ============================================================================

set(headers_files
  connection_pool_wrapper.h
)

set(sources_files
  connection_pool_wrapper.cpp
)

add_library(fireland_database STATIC
  ${headers_files}
  ${sources_files}
)

target_include_directories(fireland_database
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/..   # allows #include <Network/TcpListener.h>
)

target_link_libraries(fireland_database
  PUBLIC
    Boost::mysql
    fireland_utils   # brings Boost::asio, Boost::system, Boost::log, ws2_32, etc.
)

set_target_properties(fireland_database PROPERTIES FOLDER "Common")