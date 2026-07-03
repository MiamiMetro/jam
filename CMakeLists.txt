cmake_minimum_required(VERSION 3.25)
set(CMAKE_POLICY_VERSION_MINIMUM 3.5)
project(jam LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(FetchContent)

option(JAM_BUILD_CLIENT "Build the desktop GUI client" ON)
option(JAM_BUILD_TESTS "Build and register jam self-tests" ON)

# Release binaries are bundled inside Electron and must not depend on
# build-machine dylib paths.
set(BUILD_SHARED_LIBS OFF CACHE BOOL "Build dependencies as static libraries" FORCE)
set(GLFW_LIBRARY_TYPE STATIC CACHE STRING "Build GLFW as a static library" FORCE)
set(SPDLOG_BUILD_SHARED OFF CACHE BOOL "Build spdlog as a static library" FORCE)
set(OPUS_BUILD_SHARED_LIBRARY OFF CACHE BOOL "Build opus as a static library" FORCE)

include(cmake/server.cmake)

if(JAM_BUILD_CLIENT)
    include(cmake/client.cmake)
endif()

add_executable(latency_probe latency_probe.cpp)
target_link_libraries(latency_probe PRIVATE asio concurrentqueue spdlog::spdlog opus token_crypto)
if(WIN32)
    target_link_libraries(latency_probe PRIVATE winmm)
endif()

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
    target_link_libraries(client_manager_self_test PRIVATE asio concurrentqueue token_crypto)

    add_executable(server_rate_limiter_self_test server_rate_limiter_self_test.cpp)
    target_link_libraries(server_rate_limiter_self_test PRIVATE asio)

    add_executable(server_metrics_self_test server_metrics_self_test.cpp)

    add_executable(logger_self_test logger_self_test.cpp)
    target_link_libraries(logger_self_test PRIVATE spdlog::spdlog)

    add_executable(periodic_timer_self_test periodic_timer_self_test.cpp)
    target_link_libraries(periodic_timer_self_test PRIVATE asio spdlog::spdlog)

    add_executable(crash_reporter_self_test crash_reporter_self_test.cpp)
    if(WIN32)
        target_link_libraries(crash_reporter_self_test PRIVATE Dbghelp)
    endif()

    add_executable(join_reliability_self_test join_reliability_self_test.cpp)

    add_executable(opus_network_clock_self_test opus_network_clock_self_test.cpp)

    add_executable(audio_packet_self_test audio_packet_self_test.cpp)

    add_executable(session_crypto_self_test session_crypto_self_test.cpp)
    target_link_libraries(session_crypto_self_test PRIVATE token_crypto)

    add_executable(participant_packet_queue_self_test participant_packet_queue_self_test.cpp)
    target_link_libraries(participant_packet_queue_self_test PRIVATE concurrentqueue spdlog::spdlog opus)

    add_executable(participant_manager_self_test participant_manager_self_test.cpp)
    target_link_libraries(participant_manager_self_test PRIVATE concurrentqueue spdlog::spdlog opus)

    add_executable(sequence_tracker_self_test sequence_tracker_self_test.cpp)

    add_executable(udp_port_self_test udp_port_self_test.cpp)

    add_executable(udp_socket_config_self_test udp_socket_config_self_test.cpp)
    target_link_libraries(udp_socket_config_self_test PRIVATE asio)
    if(WIN32)
        target_link_libraries(udp_socket_config_self_test PRIVATE Qwave)
    endif()

    add_executable(jitter_policy_self_test jitter_policy_self_test.cpp)

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

add_executable(relay_load_probe relay_load_probe.cpp)
target_link_libraries(relay_load_probe PRIVATE asio)

if(JAM_BUILD_TESTS)
    add_executable(recording_writer_self_test recording_writer_self_test.cpp)
    target_link_libraries(recording_writer_self_test PRIVATE concurrentqueue)

    add_executable(audio_analysis_self_test audio_analysis_self_test.cpp)

    add_executable(audio_backend_policy_self_test audio_backend_policy_self_test.cpp)

    add_executable(juce_audio_adapter_self_test juce_audio_adapter_self_test.cpp)
endif()

if(JAM_BUILD_TESTS)
    enable_testing()
    find_program(NODE_EXECUTABLE node)

    function(jam_add_executable_test target_name)
        add_test(NAME ${target_name} COMMAND $<TARGET_FILE:${target_name}>)
    endfunction()

    jam_add_executable_test(client_manager_self_test)
    jam_add_executable_test(server_rate_limiter_self_test)
    jam_add_executable_test(server_metrics_self_test)
    jam_add_executable_test(logger_self_test)
    jam_add_executable_test(periodic_timer_self_test)
    jam_add_executable_test(crash_reporter_self_test)
    jam_add_executable_test(join_reliability_self_test)
    jam_add_executable_test(opus_network_clock_self_test)
    jam_add_executable_test(audio_packet_self_test)
    jam_add_executable_test(session_crypto_self_test)
    jam_add_executable_test(participant_packet_queue_self_test)
    jam_add_executable_test(participant_manager_self_test)
    jam_add_executable_test(sequence_tracker_self_test)
    jam_add_executable_test(udp_port_self_test)
    jam_add_executable_test(udp_socket_config_self_test)
    jam_add_executable_test(jitter_policy_self_test)
    jam_add_executable_test(redundant_receive_policy_self_test)
    jam_add_executable_test(recording_writer_self_test)
    jam_add_executable_test(audio_analysis_self_test)
    jam_add_executable_test(audio_backend_policy_self_test)
    jam_add_executable_test(juce_audio_adapter_self_test)

    add_test(NAME opus_receiver_harness_self_test
             COMMAND $<TARGET_FILE:opus_receiver_harness> --self-test)
    add_test(NAME server_redundancy_relay_smoke
             COMMAND $<TARGET_FILE:server> --redundancy-relay-smoke)
    add_test(NAME server_timestamp_relay_smoke
             COMMAND $<TARGET_FILE:server> --timestamp-relay-smoke)
    add_test(NAME server_dual_stack_relay_smoke
             COMMAND $<TARGET_FILE:server> --dual-stack-relay-smoke)
    add_test(NAME server_security_smoke
             COMMAND $<TARGET_FILE:server> --security-smoke)
    add_test(NAME server_metrics_export_smoke
             COMMAND $<TARGET_FILE:server> --metrics-export-smoke)
    add_test(NAME server_crash_report_smoke
             COMMAND $<TARGET_FILE:server> --crash-report-smoke)
    add_test(NAME latency_probe_v3_receive_smoke
             COMMAND $<TARGET_FILE:latency_probe> --v3-receive-smoke)
    if(NODE_EXECUTABLE)
        add_test(NAME server_audio_path_feedback_smoke
                 COMMAND ${NODE_EXECUTABLE}
                         ${CMAKE_SOURCE_DIR}/tools/audio-path-feedback-smoke.mjs
                         --server-exe $<TARGET_FILE:server>)
        add_test(NAME latency_probe_return_burst_smoke
                 COMMAND ${NODE_EXECUTABLE}
                         ${CMAKE_SOURCE_DIR}/tools/latency-burst-smoke.mjs
                         --server-exe $<TARGET_FILE:server>
                         --proxy-exe $<TARGET_FILE:udp_impair_proxy>
                         --probe-exe $<TARGET_FILE:latency_probe>)
        add_test(NAME latency_probe_large_gap_smoke
                 COMMAND ${NODE_EXECUTABLE}
                         ${CMAKE_SOURCE_DIR}/tools/latency-burst-smoke.mjs
                         --server-exe $<TARGET_FILE:server>
                         --proxy-exe $<TARGET_FILE:udp_impair_proxy>
                         --probe-exe $<TARGET_FILE:latency_probe>
                         --frames 480
                         --jitter 14
                         --packets 600
                         --burst-every 1000
                         --burst-count 80
                         --burst-offset 120
                         --drop-direction server-to-client
                         --allow-loss
                         --max-gap-plc-run 2
                         --min-decoder-resets 1)
        add_test(NAME e2e_latency_loopback_smoke
                 COMMAND ${NODE_EXECUTABLE}
                         ${CMAKE_SOURCE_DIR}/tools/e2e-latency-smoke.mjs
                         --server-exe $<TARGET_FILE:server>
                         --probe-exe $<TARGET_FILE:latency_probe>)
        add_test(NAME phase5_track_d_impairment_matrix_smoke
                 COMMAND ${NODE_EXECUTABLE}
                         ${CMAKE_SOURCE_DIR}/tools/phase5-track-d-impairment-matrix.mjs
                         --server-exe $<TARGET_FILE:server>
                         --proxy-exe $<TARGET_FILE:udp_impair_proxy>
                         --probe-exe $<TARGET_FILE:latency_probe>
                         --quick
                         --out-dir ${CMAKE_BINARY_DIR}/phase5-track-d/impairment-smoke)
        add_test(NAME phase5_track_d_load_benchmark_smoke
                 COMMAND ${NODE_EXECUTABLE}
                         ${CMAKE_SOURCE_DIR}/tools/phase5-track-d-load-benchmark.mjs
                         --server-exe $<TARGET_FILE:server>
                         --probe-exe $<TARGET_FILE:relay_load_probe>
                         --clients 8
                         --senders 4
                         --seconds 3
                         --frames 480
                         --min-delivery-ratio 0.95
                         --out-dir ${CMAKE_BINARY_DIR}/phase5-track-d/load-smoke)
        add_test(NAME phase5_track_d_soak_parser_smoke
                 COMMAND ${NODE_EXECUTABLE}
                         ${CMAKE_SOURCE_DIR}/tools/phase5-track-d-soak.mjs
                         --parser-smoke)
    endif()
    if(TARGET client)
        add_test(NAME client_udp_endpoint_guard_smoke
                 COMMAND $<TARGET_FILE:client> --udp-endpoint-guard-smoke)
        add_test(NAME client_auto_jitter_empty_playout_smoke
                 COMMAND $<TARGET_FILE:client> --auto-jitter-empty-playout-smoke)
        add_test(NAME client_audio_path_feedback_smoke
                 COMMAND $<TARGET_FILE:client> --audio-path-feedback-smoke)
        add_test(NAME client_opus_playout_policy_smoke
                 COMMAND $<TARGET_FILE:client> --opus-playout-policy-smoke)
        add_test(NAME client_opus_redundancy_policy_smoke
                 COMMAND $<TARGET_FILE:client> --opus-redundancy-policy-smoke)
        add_test(NAME client_opus_encode_buffer_smoke
                 COMMAND $<TARGET_FILE:client> --opus-encode-buffer-smoke)
        add_test(NAME client_udp_audio_sync_send_smoke
                 COMMAND $<TARGET_FILE:client> --udp-audio-sync-send-smoke)
        add_test(NAME client_audio_v3_receive_smoke
                 COMMAND $<TARGET_FILE:client> --audio-v3-receive-smoke)
        add_test(NAME client_e2e_latency_metric_smoke
                 COMMAND $<TARGET_FILE:client> --e2e-latency-metric-smoke)
        add_test(NAME client_startup_config_adaptive_smoke
                 COMMAND $<TARGET_FILE:client> --startup-config-smoke)
        set_tests_properties(client_startup_config_adaptive_smoke PROPERTIES
            PASS_REGULAR_EXPRESSION
                "Startup config smoke:.*opus_packet=480.*jitter_floor=2.*jitter_ms=20.*auto_start_jitter=disabled.*age_limit_ms=120.*auto_jitter=false")
        add_test(NAME client_startup_config_low_smoke
                 COMMAND $<TARGET_FILE:client> --startup-config-smoke --latency-profile low)
        set_tests_properties(client_startup_config_low_smoke PROPERTIES
            PASS_REGULAR_EXPRESSION
                "Startup config smoke:.*opus_packet=120.*jitter_floor=4.*jitter_ms=10.*auto_start_jitter=disabled.*age_limit_ms=60.*auto_jitter=false")
        add_test(NAME client_startup_config_stable_smoke
                 COMMAND $<TARGET_FILE:client> --startup-config-smoke --latency-profile stable)
        set_tests_properties(client_startup_config_stable_smoke PROPERTIES
            PASS_REGULAR_EXPRESSION
                "Startup config smoke:.*opus_packet=960.*jitter_floor=4.*jitter_ms=80.*auto_start_jitter=disabled.*age_limit_ms=250.*auto_jitter=false")
        add_test(NAME client_startup_config_jitter_ms_scaling_smoke
                 COMMAND $<TARGET_FILE:client> --startup-config-smoke
                         --opus-packet-frames 960
                         --jitter-ms 40)
        set_tests_properties(client_startup_config_jitter_ms_scaling_smoke PROPERTIES
            PASS_REGULAR_EXPRESSION
                "Startup config smoke:.*opus_packet=960.*jitter_floor=2.*jitter_ms=40.*age_limit_ms=120")
        add_test(NAME client_startup_config_jitter_requested_ms_smoke
                 COMMAND $<TARGET_FILE:client> --startup-config-smoke
                         --opus-packet-frames 960
                         --jitter-ms 45)
        set_tests_properties(client_startup_config_jitter_requested_ms_smoke PROPERTIES
            PASS_REGULAR_EXPRESSION
                "Startup config smoke:.*opus_packet=960.*jitter_floor=3.*jitter_ms=45.*age_limit_ms=120")
        add_test(NAME client_startup_config_jitter_age_validation_smoke
                 COMMAND $<TARGET_FILE:client> --startup-config-smoke
                         --jitter-ms 200
                         --age-limit-ms 100)
        set_tests_properties(client_startup_config_jitter_age_validation_smoke PROPERTIES
            PASS_REGULAR_EXPRESSION
                "Startup config smoke:.*opus_packet=480.*jitter_floor=10.*jitter_ms=100.*age_limit_ms=100")
        add_test(NAME client_startup_config_jitter_unit_conflict_smoke
                 COMMAND $<TARGET_FILE:client> --startup-config-smoke
                         --jitter-ms 50
                         --jitter 4)
        set_tests_properties(client_startup_config_jitter_unit_conflict_smoke PROPERTIES
            WILL_FAIL TRUE)
        add_test(NAME client_startup_config_redundancy_depth_smoke
                 COMMAND $<TARGET_FILE:client> --startup-config-smoke
                         --opus-packet-frames 120
                         --redundancy-depth off)
        set_tests_properties(client_startup_config_redundancy_depth_smoke PROPERTIES
            PASS_REGULAR_EXPRESSION
                "Startup config smoke:.*opus_packet=120.*redundancy_depth=0.*effective_redundancy_depth=0")
    endif()
endif()
