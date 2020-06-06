#ifndef CLIENT_H_
#define CLIENT_H_

#ifdef __cplusplus
#include <cstdint>
#else
#include <stdint.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*srv_ans_handler_t)(char const*);

int client(char const *cert_path, char const *host, uint16_t port, char const *msg, srv_ans_handler_t handler);

#ifdef __cplusplus
}
#endif

#endif
