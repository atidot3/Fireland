# ============================================================================
# common — shared libraries & smoke test
# ============================================================================

# Shared libraries (order matters: Network depends on Utils)
add_subdirectory(Utils)
add_subdirectory(Shared)
add_subdirectory(Crypto)
add_subdirectory(Network)
add_subdirectory(Database)
add_subdirectory(Game)
