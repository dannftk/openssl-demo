find_package(OpenSSL REQUIRED)

add_library(serverlib STATIC server.c server.h)
target_link_libraries(serverlib PUBLIC OpenSSL::SSL)
target_link_libraries(serverlib PUBLIC OpenSSL::Crypto)

add_library(clientlib STATIC client.c client.h)
target_link_libraries(serverlib PUBLIC OpenSSL::SSL)
target_link_libraries(serverlib PUBLIC OpenSSL::Crypto)
