# ============================================================================
# common/Shared — Shared utility library
#
# General-purpose: async infrastructure, string ops, logging, byte buffers.
# No networking code here — that lives in Network.
# ============================================================================


set(headers_files
  include/Shared/SharedDefines.hpp
  include/Shared/Auth/Account.h

  include/Shared/Realm/Realmlist.h
)

set(sources_files
    src/test.cpp
)

add_library(fireland_shared STATIC
  ${headers_files}
  ${sources_files}
)

target_include_directories(fireland_shared
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include/>
    $<INSTALL_INTERFACE:include/>
)

target_link_libraries(fireland_shared
  PUBLIC
    fireland_utils
)

# includes for internal use
target_include_directories(fireland_shared PRIVATE 
  include/
  src/
)

set_target_properties(fireland_shared PROPERTIES FOLDER "Common")
