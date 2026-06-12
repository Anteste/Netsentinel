cmake_minimum_required(VERSION 3.16)

project(netsentinel
    VERSION 1.0.0
    DESCRIPTION "Terminal-only real-time intrusion detection system"
    LANGUAGES CXX
)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(ids_core
    src/Alert.cpp
    src/AlertManager.cpp
    src/DetectionEngine.cpp
    src/FileLogger.cpp
    src/IdsConfig.cpp
    src/NetworkEvent.cpp
    src/PortScanRule.cpp
    src/SecurityAnalyzer.cpp
    src/SshBruteForceRule.cpp
)

target_include_directories(ids_core PUBLIC include)

target_compile_options(ids_core PRIVATE
    $<$<CXX_COMPILER_ID:GNU,Clang,AppleClang>:-Wall -Wextra -Wpedantic>
)

add_executable(netsentinel
    src/main.cpp
    src/EventSimulator.cpp
    src/LiveCapture.cpp
)

find_library(PCAP_LIBRARY pcap REQUIRED)
target_link_libraries(netsentinel PRIVATE ids_core ${PCAP_LIBRARY})
target_include_directories(netsentinel PRIVATE include)

add_executable(netsentinel_tests
    tests/IdsTests.cpp
    src/EventSimulator.cpp
)

target_link_libraries(netsentinel_tests PRIVATE ids_core)
target_include_directories(netsentinel_tests PRIVATE include)

enable_testing()
add_test(NAME netsentinel_tests COMMAND netsentinel_tests)
