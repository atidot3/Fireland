# ============================================================================
# common/Utils — Shared utility library
#
# General-purpose: async infrastructure, string ops, logging, byte buffers.
# No networking code here — that lives in Network.
# ============================================================================


set(headers_files
    include/Utils/Async.hpp
    include/Utils/Bytes/ByteBuffer.h
    include/Utils/Bytes/ByteHelper.hpp
    include/Utils/Describe.hpp
    include/Utils/Filesystem.h
    include/Utils/IoContext.h
    include/Utils/Log.h
    include/Utils/ProgramOptions.h
    include/Utils/StringUtils.h
)

set(sources_files
  src/ByteBuffer.cpp
  src/Filesystem.cpp
  src/IoContext.cpp
  src/Log.cpp
)

add_library(fireland_utils STATIC
  ${headers_files}
  ${sources_files}
)

target_include_directories(fireland_utils
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include/>
    $<INSTALL_INTERFACE:include/>
)

target_link_libraries(fireland_utils
  PUBLIC
    fireland_compiler_options
    Boost::asio
    Boost::system
    Boost::log
    Boost::program_options
)

# includes for internal use
target_include_directories(fireland_utils PRIVATE 
  include/
  src/
)

# Platform-specific deps for Boost.Asio
if(WIN32)
  target_link_libraries(fireland_utils PUBLIC ws2_32 mswsock)
endif()

set_target_properties(fireland_utils PROPERTIES FOLDER "Common")
