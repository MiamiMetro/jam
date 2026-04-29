cmake_minimum_required(VERSION 3.25)
set(CMAKE_POLICY_VERSION_MINIMUM 3.5)
project(jam LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(FetchContent)

include(cmake/server.cmake)
include(cmake/client.cmake)
include(cmake/listener.cmake)

add_executable(latency_probe latency_probe.cpp)
target_link_libraries(latency_probe PRIVATE asio concurrentqueue spdlog::spdlog opus)

add_executable(room_routing_probe room_routing_probe.cpp)
target_link_libraries(room_routing_probe PRIVATE asio spdlog::spdlog opus token_crypto)
