# Server-specific configuration

include(cmake/common.cmake)

# ============================================================
# Server Dependencies
# ============================================================

FetchContent_Declare(
    srt
    GIT_REPOSITORY https://github.com/Haivision/srt
    GIT_TAG        v1.5.4
)
set(ENABLE_ENCRYPTION OFF CACHE BOOL "Enable SRT encryption" FORCE)
set(ENABLE_APPS OFF CACHE BOOL "Should the Support Applications be Built?" FORCE)

FetchContent_MakeAvailable(srt)

# ============================================================
# Server Target
# ============================================================

add_executable(server server.cpp)
target_link_libraries(server PRIVATE asio concurrentqueue spdlog::spdlog opus srt_static)
target_include_directories(server PRIVATE
    ${srt_SOURCE_DIR}/srtcore
    ${srt_SOURCE_DIR}/common
    ${srt_BINARY_DIR}
)

