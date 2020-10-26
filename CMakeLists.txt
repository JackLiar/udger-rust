cmake_minimum_required(VERSION 3.10.0)
project(udger-rust VERSION 0.1.0)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
include(macros)
include(projects)

add_custom_target(udger-rust ALL
    # COMMAND cd ${CMAKE_CURRENT_SOURCE_DIR} && cargo build
    COMMAND echo "All the dependencies of udger-rust are built successfully!"
)

add_dependencies(udger-rust hyperscan)

print_configuration()
