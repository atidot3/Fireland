# ============================================================================
# common/Network — Async TCP networking library (Boost.Asio + C++20 coroutines)
#
# Depends on fireland_utils for IoContext, ByteBuffer, logging, etc.
# ============================================================================

set(headers_files
  IoContext.h
  PacketBuffer.h
  SessionManager.h
  TcpListener.h
  TcpSession.h
)

set(sources_files
  IoContext.cpp
  PacketBuffer.cpp
  SessionManager.cpp
  TcpListener.cpp
  TcpSession.cpp
)

add_library(fireland_network STATIC
  ${headers_files}
  ${sources_files}
)

target_include_directories(fireland_network
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/..   # allows #include <Network/TcpListener.h>
)

target_link_libraries(fireland_network
  PUBLIC
    fireland_utils   # brings Boost::asio, Boost::system, Boost::log, ws2_32, etc.
)

set_target_properties(fireland_network PROPERTIES FOLDER "Common")
