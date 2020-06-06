find_package(Threads REQUIRED)

add_executable(openssl-demo-test test.cpp test.hpp color.hpp)
target_include_directories(openssl-demo-test PRIVATE ${OPENSSL_DEMO_SRC_DIR})
target_link_libraries(openssl-demo-test PRIVATE serverlib clientlib Threads::Threads)
