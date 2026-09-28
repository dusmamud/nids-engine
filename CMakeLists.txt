cmake_minimum_required(VERSION 3.20)
project(nids-engine
    VERSION 0.1.0
    DESCRIPTION "High-throughput, cross-platform Network Intrusion Detection System in Modern C++20"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Configure output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Options
option(BUILD_TESTS "Build unit test suite" ON)
option(ENABLE_WERROR "Treat warnings as errors" OFF)

# Common compiler warning flags
if(MSVC)
    add_compile_options(/W4 /permissive-)
    if(ENABLE_WERROR)
        add_compile_options(/WX)
    endif()
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS WIN32_LEAN_AND_MEAN)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -Wconversion -Wshadow)
    if(ENABLE_WERROR)
        add_compile_options(-Werror)
    endif()
endif()

# Find PCAP (Optional for offline dissection and test builds)
find_package(PkgConfig QUIET)
find_path(PCAP_INCLUDE_DIR pcap.h PATHS /usr/include /usr/local/include "C:/Program Files/Npcap/Include")
find_library(PCAP_LIBRARY NAMES pcap wpcap PATHS /usr/lib /usr/local/lib "C:/Program Files/Npcap/Lib")

# Core Engine Static Library
add_library(nids_core STATIC
    src/protocol/ethernet.cpp
    src/protocol/ipv4.cpp
    src/protocol/tcp.cpp
    src/flow/flow_table.cpp
    src/detection/entropy_detector.cpp
    src/detection/port_scan_detector.cpp
    src/detection/syn_flood_detector.cpp
    src/output/alert_logger.cpp
)

target_include_directories(nids_core PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

if(PCAP_INCLUDE_DIR AND PCAP_LIBRARY)
    message(STATUS "Found PCAP: ${PCAP_LIBRARY} (Include: ${PCAP_INCLUDE_DIR})")
    target_include_directories(nids_core PRIVATE ${PCAP_INCLUDE_DIR})
    target_link_libraries(nids_core PUBLIC ${PCAP_LIBRARY})
    target_compile_definitions(nids_core PUBLIC NIDS_HAS_PCAP=1)
    if(WIN32)
        target_link_libraries(nids_core PUBLIC ws2_32)
    endif()
else()
    message(WARNING "PCAP library not found. Building with mock/offline capture support only.")
    target_compile_definitions(nids_core PUBLIC NIDS_HAS_PCAP=0)
    if(WIN32)
        target_link_libraries(nids_core PUBLIC ws2_32)
    endif()
endif()

# CLI Executable Target
add_executable(nids-engine
    src/main.cpp
)

target_link_libraries(nids-engine PRIVATE nids_core)

# Test Suite Target
if(BUILD_TESTS)
    enable_testing()
    add_executable(nids-tests
        tests/test_main.cpp
        tests/test_dissector.cpp
        tests/test_entropy.cpp
        tests/test_flow_table.cpp
    )
    target_link_libraries(nids-tests PRIVATE nids_core)
    add_test(NAME AllUnitTests COMMAND nids-tests)
endif()
