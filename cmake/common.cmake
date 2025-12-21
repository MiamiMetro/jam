# Common dependencies and setup for both server and client

# ============================================================
# Platform / Asio config
# ============================================================

add_library(asio_config INTERFACE)

if (WIN32)
    target_compile_definitions(asio_config INTERFACE
        _WIN32_WINNT=0x0A00
        ASIO_STANDALONE
    )
endif()

# ============================================================
# Dependencies
# ============================================================

FetchContent_Declare(
    asio_src
    GIT_REPOSITORY https://github.com/chriskohlhoff/asio.git
    GIT_TAG        asio-1-36-0
)

FetchContent_Declare(
    opus
    GIT_REPOSITORY https://github.com/xiph/opus.git
    GIT_TAG        v1.5.2
)

FetchContent_Declare(
    concurrentqueue_src
    GIT_REPOSITORY https://github.com/cameron314/concurrentqueue.git
    GIT_TAG        v1.0.4
)

FetchContent_Declare(
    spdlog
    GIT_REPOSITORY https://github.com/gabime/spdlog.git
    GIT_TAG        v1.16.0
)

FetchContent_MakeAvailable(asio_src opus concurrentqueue_src spdlog)

target_compile_definitions(spdlog PUBLIC SPDLOG_USE_STD_FORMAT)

# ============================================================
# Common Wrappers
# ============================================================

add_library(asio INTERFACE)
target_include_directories(asio INTERFACE
    ${asio_src_SOURCE_DIR}/asio/include
)
target_link_libraries(asio INTERFACE asio_config)

