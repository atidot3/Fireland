# ============================================================================
# Platform detection & platform-specific definitions
# ============================================================================

if(WIN32)
  set(FIRELAND_PLATFORM "WIN")

  # Trim Windows headers
  add_compile_definitions(
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    _WIN32_WINNT=0x0A00   # Windows 10+
  )

  if(MSVC)
    message(STATUS "[Firelands] Platform: Windows (MSVC ${MSVC_VERSION})")
  elseif(MINGW)
    message(STATUS "[Firelands] Platform: Windows (MinGW)")
  else()
    message(STATUS "[Firelands] Platform: Windows (unknown compiler)")
  endif()

elseif(APPLE)
  set(FIRELAND_PLATFORM "MACOS")

  if(NOT CMAKE_OSX_DEPLOYMENT_TARGET)
    set(CMAKE_OSX_DEPLOYMENT_TARGET "12.0" CACHE STRING "Minimum macOS deployment target" FORCE)
  endif()

  message(STATUS "[Firelands] Platform: macOS (deployment target ${CMAKE_OSX_DEPLOYMENT_TARGET})")

elseif(UNIX)
  set(FIRELAND_PLATFORM "LINUX")
  message(STATUS "[Firelands] Platform: Linux")

else()
  message(FATAL_ERROR "[Firelands] Unsupported platform")
endif()

# ----------------------------------------------------------------------------
# Architecture
# ----------------------------------------------------------------------------
if(CMAKE_SIZEOF_VOID_P EQUAL 8)
  set(FIRELAND_ARCH "x64")
else()
  set(FIRELAND_ARCH "x86")
  message(WARNING "[Firelands] 32-bit builds are not officially supported")
endif()

message(STATUS "[Firelands] Architecture: ${FIRELAND_ARCH}")
