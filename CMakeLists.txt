cmake_minimum_required(VERSION 3.10.0)
project(udger-rust VERSION 0.1.0)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
include(macros)
include(projects)

add_custom_target(udger-rust ALL
    # COMMAND cd ${CMAKE_CURRENT_SOURCE_DIR} && cargo build
    COMMAND echo "All the dependencies of udger-rust are built successfully!"
)

find_library(libpcap_LIBRARY pcap
    HINTS "${CMAKE_CURRENT_BINARY_DIR}/install/lib"
    PATHS /usr/lib/x86_64-linux-gnu/
)

option(BUILD_LIBPCAP "build libpcap" OFF)
if(NOT libpcap_LIBRARY OR BUILD_LIBPCAP)
    add_dependencies(udger-rust libpcap)
endif()

add_dependencies(udger-rust hyperscan)

print_configuration()
