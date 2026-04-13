# ============================================================================
# Compiler options — cross-platform warning levels and optimization flags
# ============================================================================

# Sanitizer option (Debug only)
option(FIRELAND_ENABLE_SANITIZERS "Enable address/undefined sanitizers in Debug" OFF)

add_library(fireland_compiler_options INTERFACE)

if(MSVC)
  target_compile_options(fireland_compiler_options INTERFACE
    /W4
    /MP                   # Multi-process compilation
    /permissive-          # Strict conformance
    /Zc:__cplusplus       # Correct __cplusplus macro value
    /Zc:preprocessor      # Standard-conforming preprocessor
    /utf-8                # Source and execution charset
  )

else()
  # GCC / Clang / Apple Clang
  target_compile_options(fireland_compiler_options INTERFACE
    -Wall
    -Wextra
    -Wpedantic
    -Wno-unused-parameter
  )

  # Release optimisation
  target_compile_options(fireland_compiler_options INTERFACE
    $<$<CONFIG:Release>:-O2>
    $<$<CONFIG:RelWithDebInfo>:-O2 -g>
  )

  # Sanitizers
  if(FIRELAND_ENABLE_SANITIZERS)
    target_compile_options(fireland_compiler_options INTERFACE
      $<$<CONFIG:Debug>:-fsanitize=address,undefined -fno-omit-frame-pointer>
    )
    target_link_options(fireland_compiler_options INTERFACE
      $<$<CONFIG:Debug>:-fsanitize=address,undefined>
    )
  endif()
endif()
