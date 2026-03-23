cmake_minimum_required(VERSION 3.15)
project(clv-vpncore VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Probe whether the system kernel headers already define the OVPN IFLA enums
# (upstreamed in Linux 6.12).  A version-number check would miss backports;
# actually trying to compile is the only reliable test.
include(CheckCXXSourceCompiles)
check_cxx_source_compiles("
    #include <linux/if_link.h>
    int main() { int x = IFLA_OVPN_MODE; (void)x; return 0; }
" KERNEL_HEADERS_HAVE_OVPN_IFLA)

# C++23 Standard
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Build options
option(BUILD_TESTS "Build test programs" ON)
option(BUILD_DEMOS "Build demo programs" ON)

# Add clv-base (provides clv::core, clv::sslhelp, clv::netcore)
add_subdirectory(clv-base)

# Set ASIO include path (from clv-base)
set(ASIO_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/clv-base/extern/asio/asio/include")

# VpnCore library
add_library(clv_vpncore STATIC
    src/openvpn/client_config_generator.cpp
    src/openvpn/client_session.cpp
    src/openvpn/config_exchange.cpp
    src/openvpn/control_channel.cpp
    src/openvpn/control_plane_helpers.cpp
    src/openvpn/data_channel.cpp
    src/openvpn/dco_data_channel.cpp
    src/openvpn/key_derivation.cpp
    src/openvpn/ovpn_config_parser.cpp
    src/openvpn/packet.cpp
    src/openvpn/session_manager.cpp
    src/openvpn/tls_context.cpp
    src/openvpn/tls_crypt.cpp
    src/openvpn/userspace_data_channel.cpp
    src/openvpn/vpn_config.cpp
    src/transport/transport.cpp
    src/transport/listener.cpp
    src/transport/connector.cpp
    src/transport/udp_batch.cpp
    src/cpu_affinity.cpp
    src/vpn_client.cpp
    src/vpn_server.cpp
    src/log_subsystems.cpp
    src/ip_pool_manager.cpp
    src/routing_table.cpp
    src/scoped_masquerade.cpp
)

target_include_directories(clv_vpncore
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${ASIO_INCLUDE_DIR}
)

target_link_libraries(clv_vpncore
    PUBLIC
        clv::netcore
        clv::sslhelp
        clv::core
)

if(KERNEL_HEADERS_HAVE_OVPN_IFLA)
    target_compile_definitions(clv_vpncore PRIVATE KERNEL_HEADERS_HAVE_OVPN_IFLA=1)
endif()

# Apply ASAN flags if enabled
apply_asan_flags(clv_vpncore)

# Add alias for consistency
add_library(clv::vpncore ALIAS clv_vpncore)

# Tests
if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# Demos
if(BUILD_DEMOS)
    add_subdirectory(demos)
endif()

# # Installation rules
# install(TARGETS clv_vpncore
#     EXPORT clv-vpncore-targets
#     LIBRARY DESTINATION lib
#     ARCHIVE DESTINATION lib
#     RUNTIME DESTINATION bin
# )
#
# install(DIRECTORY src/openvpn
#     DESTINATION include
#     FILES_MATCHING PATTERN "*.h"
# )
#
# install(EXPORT clv-vpncore-targets
#     FILE clv-vpncore-targets.cmake
#     NAMESPACE clv::
#     DESTINATION lib/cmake/clv-vpncore
# )
