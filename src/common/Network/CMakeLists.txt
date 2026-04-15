# ============================================================================
# common/Network — Async TCP networking library (Boost.Asio + C++20 coroutines)
#
# Depends on fireland_utils for IoContext, ByteBuffer, logging, etc.
# ============================================================================

set(headers_files
  include/Network/PacketBuffer.h
  include/Network/SessionManager.h
  include/Network/TcpListener.h
  include/Network/TcpSession.h
)

set(sources_files
  src/PacketBuffer.cpp
  src/SessionManager.cpp
  src/TcpSession.cpp
)

add_library(fireland_network STATIC
  ${headers_files}
  ${sources_files}
)

target_include_directories(fireland_network
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include/>
    $<INSTALL_INTERFACE:include/>
)

# includes for internal use
target_include_directories(fireland_network PRIVATE 
  include/
  src/
)

target_link_libraries(fireland_network
  PUBLIC
    fireland_utils   # brings Boost::asio, Boost::system, Boost::log, ws2_32, etc.
)

set_target_properties(fireland_network PROPERTIES FOLDER "Common")
