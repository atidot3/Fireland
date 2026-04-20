# ============================================================================
# common/Game — Main game library, containing core game logic and data structures.
#
# General-purpose: core logic, data structures, utilities, and platform abstractions that are used across the game.
# ============================================================================


set(headers_files
    include/Game/Objects/UpdateData.h

    include/Game/World/WorldSession.h
)

set(sources_files
    src/Objects/UpdateData.cpp

    src/World/WorldSession.cpp
)

add_library(fireland_game STATIC
  ${headers_files}
  ${sources_files}
)

target_include_directories(fireland_game
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include/>
    $<INSTALL_INTERFACE:include/>
)

target_link_libraries(fireland_game
  PUBLIC
    fireland_compiler_options
    fireland_utils
    fireland_shared
    fireland_network
    fireland_database
    fireland_crypto
)

# includes for internal use
target_include_directories(fireland_game PRIVATE 
  include/
  src/
)

# Platform-specific deps for Boost.Asio
if(WIN32)
  target_link_libraries(fireland_game PUBLIC ws2_32 mswsock)
endif()

source_group(TREE ${CMAKE_CURRENT_SOURCE_DIR} FILES ${headers_files} ${sources_files})

set_target_properties(fireland_game PROPERTIES FOLDER "Common")
