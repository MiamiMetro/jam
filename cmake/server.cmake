# Server-specific configuration

include(cmake/common.cmake)

# ============================================================
# Server Dependencies
# ============================================================

find_package(Threads REQUIRED)

# ============================================================
# Server Target
# ============================================================

add_executable(server server.cpp)
target_link_libraries(server PRIVATE asio concurrentqueue spdlog::spdlog opus token_crypto Threads::Threads)
if(WIN32)
    target_link_libraries(server PRIVATE Qwave)
endif()
