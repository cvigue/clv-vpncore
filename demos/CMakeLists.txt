# Demo executables

add_executable(simple_vpn simple_vpn.cpp)
target_include_directories(simple_vpn PRIVATE ${ASIO_INCLUDE_DIR})
target_link_libraries(simple_vpn
    PRIVATE
        clv::vpncore
        clv::netcore
        clv::sslhelp
        clv::core
)
apply_asan_flags(simple_vpn)

add_executable(generate_client_config generate_client_config.cpp)
target_include_directories(generate_client_config PRIVATE ${ASIO_INCLUDE_DIR})
target_link_libraries(generate_client_config
    PRIVATE
        clv::vpncore
        clv::netcore
        clv::sslhelp
        clv::core
)
apply_asan_flags(generate_client_config)

add_executable(ovpn_parser_demo ovpn_parser_demo.cpp)
target_include_directories(ovpn_parser_demo PRIVATE ${ASIO_INCLUDE_DIR})
target_link_libraries(ovpn_parser_demo
    PRIVATE
        clv::vpncore
        clv::netcore
        clv::sslhelp
        clv::core
)
apply_asan_flags(ovpn_parser_demo)
