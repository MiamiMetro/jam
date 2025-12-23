# Server-specific configuration

include(cmake/common.cmake)

# ============================================================
# Server Dependencies
# ============================================================

# ============================================================
# Server Target
# ============================================================

add_executable(server server.cpp)
target_link_libraries(server PRIVATE asio concurrentqueue spdlog::spdlog opus)
