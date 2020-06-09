cmake_minimum_required(VERSION 3.16 FATAL_ERROR)
project(openssl-demo VERSION 1.0.0 LANGUAGES C CXX)

if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 17)

set(OPENSSL_DEMO_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
add_subdirectory(src)

if (ENABLE_TEST)
    enable_testing()
    add_subdirectory(test)
endif()
