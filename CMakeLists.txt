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

add_executable(opus_receiver_harness opus_receiver_harness.cpp)
add_custom_target(opus_receiver_harness_self_test
    COMMAND $<TARGET_FILE:opus_receiver_harness> --self-test
    DEPENDS opus_receiver_harness
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)

add_executable(udp_impair_proxy udp_impair_proxy.cpp)
target_link_libraries(udp_impair_proxy PRIVATE asio)

add_executable(multi_participant_jitter_probe multi_participant_jitter_probe.cpp)
target_link_libraries(multi_participant_jitter_probe PRIVATE asio)
