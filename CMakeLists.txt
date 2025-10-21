cmake_minimum_required(VERSION 3.25)
project(jam LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Windows-specific Asio definitions
if(WIN32)
    add_compile_definitions(_WIN32_WINNT=0x0A00)  # Windows 10
    add_compile_definitions(ASIO_STANDALONE)
    add_compile_definitions(ASIO_HAS_STD_ADDRESSOF)
    add_compile_definitions(ASIO_HAS_STD_ARRAY)
    add_compile_definitions(ASIO_HAS_CSTDINT)
    add_compile_definitions(ASIO_HAS_STD_SHARED_PTR)
    add_compile_definitions(ASIO_HAS_STD_TYPE_TRAITS)
endif()

include(FetchContent)

# Fetch Asio
FetchContent_Declare(
  asio
  GIT_REPOSITORY https://github.com/chriskohlhoff/asio.git
  GIT_TAG        asio-1-36-0
)
# Fetch PortAudio
FetchContent_Declare(
  portaudio
  GIT_REPOSITORY https://github.com/PortAudio/portaudio.git
  GIT_TAG        b0cc303e95fdb7c6c953337051378071c9043e88
)
# Fetch Opus
FetchContent_Declare(
  opus
  GIT_REPOSITORY https://github.com/xiph/opus.git
  GIT_TAG        v1.5.2
)

# Fetch readerwriterqueue
FetchContent_Declare(
  concurrentqueue
  GIT_REPOSITORY https://github.com/cameron314/concurrentqueue.git
  GIT_TAG        v1.0.4   # or a specific commit/tag
)

# Fetch IXWebSocket
FetchContent_Declare(
  ixwebsocket
  GIT_REPOSITORY https://github.com/machinezone/IXWebSocket.git
  GIT_TAG        v11.4.6
)
set(USE_ZLIB OFF CACHE BOOL "" FORCE)
set(USE_SSL OFF CACHE BOOL "" FORCE)

FetchContent_Declare(
  json
  GIT_REPOSITORY https://github.com/nlohmann/json.git
  GIT_TAG        v3.12.0
)

FetchContent_Declare(
  spdlog
  GIT_REPOSITORY https://github.com/gabime/spdlog.git
  GIT_TAG        v1.16.0
)

set(SPDLOG_USE_STD_FORMAT ON CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(asio portaudio opus concurrentqueue ixwebsocket json spdlog)

# --- Targets ---
add_executable(server server.cpp)
target_include_directories(server PRIVATE
  ${asio_SOURCE_DIR}/asio/include
  ${portaudio_SOURCE_DIR}/include
  ${opus_SOURCE_DIR}/include
  ${concurrentqueue_SOURCE_DIR}/include
  ${spdlog_SOURCE_DIR}/include
)
target_link_libraries(server PRIVATE portaudio opus concurrentqueue spdlog::spdlog)

add_executable(client client.cpp)
target_include_directories(client PRIVATE
  ${asio_SOURCE_DIR}/asio/include
  ${portaudio_SOURCE_DIR}/include
  ${opus_SOURCE_DIR}/include
  ${concurrentqueue_SOURCE_DIR}/include
  ${ixwebsocket_SOURCE_DIR}/include
  ${json_SOURCE_DIR}/include
  ${spdlog_SOURCE_DIR}/include
)
target_link_libraries(client PRIVATE portaudio opus concurrentqueue ixwebsocket nlohmann_json::nlohmann_json spdlog::spdlog)