#ifndef SERVER_H_
#define SERVER_H_

#ifdef __cplusplus
#include <cstdint>
#else
#include <stdint.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef int (*cl_msg_handler_t)(char const*);

int server(char const *cert_path, char const *key_path, uint16_t port, cl_msg_handler_t handler);

#ifdef __cplusplus
}
#endif

#endif
