# Test executable
add_executable(test_vpncore
    aead_utils_tests.cpp
    client_config_generator_tests.cpp
    config_exchange_tests.cpp
    control_channel_tests.cpp
    data_channel_tests.cpp
    ip_pool_manager_tests.cpp
    ipv4_utils_tests.cpp
    key_derivation_tests.cpp
    log_subsystems_tests.cpp
    log_utils_tests.cpp
    openvpn_packet_tests.cpp
    ovpn_config_parser_tests.cpp
    routing_table_tests.cpp
    scoped_masquerade_tests.cpp
    session_manager_tests.cpp
    tls_context_tests.cpp
    tls_crypt_tests.cpp
    tun_device_tests.cpp
    udp_batch_tests.cpp
    vpn_client_tests.cpp
    vpn_config_tests.cpp
    vpn_server_integration_tests.cpp
    AsanVerification_tests.cpp
)

target_include_directories(test_vpncore
    PRIVATE
        ${ASIO_INCLUDE_DIR}
)

target_link_libraries(test_vpncore
    PRIVATE
        clv::vpncore
        clv::netcore
        clv::sslhelp
        clv::core
        gtest_main
)
apply_asan_flags(test_vpncore)

target_compile_definitions(test_vpncore
    PRIVATE
        TEST_TMP_DIR="${CMAKE_CURRENT_BINARY_DIR}/tmp"
)

# Copy test data directory
add_custom_command(TARGET test_vpncore POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CMAKE_SOURCE_DIR}/test_data
        ${CMAKE_CURRENT_BINARY_DIR}/test_data
)

# Register with CTest
include(GoogleTest)
gtest_discover_tests(test_vpncore)
