# ============================================================================
# common/Network — Async TCP networking library (Boost.Asio + C++20 coroutines)
#
# Depends on firelands_utils for IoContext, ByteBuffer, logging, etc.
# ============================================================================

set(headers_files
  include/Network/NetDefines.h
  include/Network/TcpListener.h

  include/Network/Auth/AuthOpcode.hpp
  include/Network/Auth/AuthPacket.hpp

  include/Network/World/WorldOpcode.hpp
  include/Network/World/WorldPacket.h
)

set(sources_files
  src/Network/WorldPacket.cpp
)

add_library(firelands_network STATIC
  ${headers_files}
  ${sources_files}
)

target_include_directories(firelands_network
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include/>
    $<INSTALL_INTERFACE:include/>
)

# includes for internal use
target_include_directories(firelands_network PRIVATE 
  include/
  src/
)

target_link_libraries(firelands_network
  PUBLIC
    firelands_utils   # brings Boost::asio, Boost::system, Boost::log, ws2_32, etc.
)

source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${headers_files} ${sources_files})

set_target_properties(firelands_network PROPERTIES FOLDER "Common")
