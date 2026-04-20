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

  include/Shared/Char/Characters.h
  include/Shared/Char/MovementInfo.h
  include/Shared/Char/UpdateFields.h
)

set(sources_files
    src/test.cpp
)

add_library(firelands_shared STATIC
  ${headers_files}
  ${sources_files}
)

target_include_directories(firelands_shared
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include/>
    $<INSTALL_INTERFACE:include/>
)

target_link_libraries(firelands_shared
  PUBLIC
    firelands_utils
)

# includes for internal use
target_include_directories(firelands_shared PRIVATE 
  include/
  src/
)

source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${headers_files} ${sources_files})

set_target_properties(firelands_shared PROPERTIES FOLDER "Common")
