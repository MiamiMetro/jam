# Listener-specific configuration

include(cmake/common.cmake)

# ============================================================
# Listener Dependencies
# ============================================================


# ============================================================
# Listener Target
# ============================================================

add_executable(listener_bot listener_bot.cpp)
target_link_libraries(listener_bot PRIVATE asio concurrentqueue spdlog::spdlog opus)
