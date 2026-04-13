# ============================================================================
# common/Utils — Shared utility library
#
# General-purpose: async infrastructure, string ops, logging, byte buffers.
# No networking code here — that lives in Network.
# ============================================================================

set(headers_files
    Async.hpp
    ByteBuffer.h
    IoContext.h
    Log.h
    ProgramOptions.h
    StringUtils.h
)

set(sources_files
  IoContext.cpp
  ByteBuffer.cpp
  Log.cpp
)

add_library(fireland_utils STATIC
  ${headers_files}
  ${sources_files}
)

target_include_directories(fireland_utils
  PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/..   # allows #include <Utils/IoContext.h>
)

target_link_libraries(fireland_utils
  PUBLIC
    fireland_compiler_options
    Boost::asio
    Boost::system
    Boost::log
    Boost::program_options
)

# Platform-specific deps for Boost.Asio
if(WIN32)
  target_link_libraries(fireland_utils PUBLIC ws2_32 mswsock)
endif()

set_target_properties(fireland_utils PROPERTIES FOLDER "Common")
