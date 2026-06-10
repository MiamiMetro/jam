cmake_minimum_required(VERSION 3.25)
set(CMAKE_POLICY_VERSION_MINIMUM 3.5)
project(jam LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(FetchContent)

option(JAM_BUILD_CLIENT "Build the desktop GUI client" ON)
option(JAM_BUILD_TESTS "Build and register jam self-tests" ON)

include(cmake/server.cmake)

if(JAM_BUILD_CLIENT)
    include(cmake/client.cmake)
endif()

add_executable(latency_probe latency_probe.cpp)
target_link_libraries(latency_probe PRIVATE asio concurrentqueue spdlog::spdlog opus token_crypto)

add_executable(udp_path_probe udp_path_probe.cpp)
target_link_libraries(udp_path_probe PRIVATE asio token_crypto)

add_executable(room_routing_probe room_routing_probe.cpp)
target_link_libraries(room_routing_probe PRIVATE asio spdlog::spdlog opus token_crypto)

add_executable(join_token_tool join_token_tool.cpp)
target_link_libraries(join_token_tool PRIVATE token_crypto)

add_executable(listener_audio_sender_probe listener_audio_sender_probe.cpp)
target_link_libraries(listener_audio_sender_probe PRIVATE asio spdlog::spdlog opus token_crypto)

add_executable(jam_broadcaster jam_broadcaster.cpp)
target_link_libraries(jam_broadcaster PRIVATE asio spdlog::spdlog)

if(JAM_BUILD_TESTS)
    add_executable(client_manager_self_test client_manager_self_test.cpp)
    target_link_libraries(client_manager_self_test PRIVATE asio concurrentqueue)

    add_executable(join_reliability_self_test join_reliability_self_test.cpp)

    add_executable(opus_network_clock_self_test opus_network_clock_self_test.cpp)

    add_executable(audio_packet_self_test audio_packet_self_test.cpp)

    add_executable(participant_packet_queue_self_test participant_packet_queue_self_test.cpp)
    target_link_libraries(participant_packet_queue_self_test PRIVATE concurrentqueue spdlog::spdlog opus)

    add_executable(sequence_tracker_self_test sequence_tracker_self_test.cpp)

    add_executable(redundant_receive_policy_self_test redundant_receive_policy_self_test.cpp)
    target_link_libraries(redundant_receive_policy_self_test PRIVATE concurrentqueue spdlog::spdlog opus)
endif()

add_executable(opus_receiver_harness opus_receiver_harness.cpp)
if(JAM_BUILD_TESTS)
    add_custom_target(opus_receiver_harness_self_test
        COMMAND $<TARGET_FILE:opus_receiver_harness> --self-test
        DEPENDS opus_receiver_harness
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    )
endif()

add_executable(udp_impair_proxy udp_impair_proxy.cpp)
target_link_libraries(udp_impair_proxy PRIVATE asio)

add_executable(multi_participant_jitter_probe multi_participant_jitter_probe.cpp)
target_link_libraries(multi_participant_jitter_probe PRIVATE asio)

if(JAM_BUILD_TESTS)
    add_executable(recording_writer_self_test recording_writer_self_test.cpp)
    target_link_libraries(recording_writer_self_test PRIVATE concurrentqueue)

    add_executable(audio_analysis_self_test audio_analysis_self_test.cpp)

    add_executable(audio_backend_policy_self_test audio_backend_policy_self_test.cpp)

    add_executable(juce_audio_adapter_self_test juce_audio_adapter_self_test.cpp)
endif()

if(JAM_BUILD_TESTS)
    enable_testing()

    function(jam_add_executable_test target_name)
        add_test(NAME ${target_name} COMMAND $<TARGET_FILE:${target_name}>)
    endfunction()

    jam_add_executable_test(client_manager_self_test)
    jam_add_executable_test(join_reliability_self_test)
    jam_add_executable_test(opus_network_clock_self_test)
    jam_add_executable_test(audio_packet_self_test)
    jam_add_executable_test(participant_packet_queue_self_test)
    jam_add_executable_test(sequence_tracker_self_test)
    jam_add_executable_test(redundant_receive_policy_self_test)
    jam_add_executable_test(recording_writer_self_test)
    jam_add_executable_test(audio_analysis_self_test)
    jam_add_executable_test(audio_backend_policy_self_test)
    jam_add_executable_test(juce_audio_adapter_self_test)

    add_test(NAME opus_receiver_harness_self_test
             COMMAND $<TARGET_FILE:opus_receiver_harness> --self-test)
    add_test(NAME server_redundancy_relay_smoke
             COMMAND $<TARGET_FILE:server> --redundancy-relay-smoke)
    if(TARGET client)
        add_test(NAME client_udp_endpoint_guard_smoke
                 COMMAND $<TARGET_FILE:client> --udp-endpoint-guard-smoke)
    endif()
endif()
