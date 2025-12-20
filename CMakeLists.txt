cmake_minimum_required(VERSION 3.25)
project(jam LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(FetchContent)

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
    portaudio
    GIT_REPOSITORY https://github.com/PortAudio/portaudio.git
    GIT_TAG        b0cc303e95fdb7c6c953337051378071c9043e88
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

FetchContent_MakeAvailable(
    asio_src
    portaudio
    opus
    concurrentqueue_src
    spdlog
)

target_compile_definitions(spdlog PUBLIC SPDLOG_USE_STD_FORMAT)

# ============================================================
# Header-only wrappers
# ============================================================

add_library(asio INTERFACE)
target_include_directories(asio INTERFACE
    ${asio_src_SOURCE_DIR}/asio/include
)
target_link_libraries(asio INTERFACE asio_config)

# ============================================================
# Targets
# ============================================================

add_executable(server server.cpp)
target_link_libraries(server PRIVATE asio concurrentqueue spdlog::spdlog portaudio opus)

add_executable(client client.cpp)
target_link_libraries(client PRIVATE asio concurrentqueue spdlog::spdlog portaudio opus)
