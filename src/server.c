#include "server.h"

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

static int create_socket(uint16_t port)
{
    int s;
    struct sockaddr_in addr;

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Unable to bind");
        exit(EXIT_FAILURE);
    }

    if (listen(s, 1) < 0) {
        perror("Unable to listen");
        exit(EXIT_FAILURE);
    }

    return s;
}

static void init_openssl()
{
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

static void cleanup_openssl()
{
    EVP_cleanup();
}

static SSL_CTX *create_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = SSLv23_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

static void configure_context(SSL_CTX *ctx, char const *cert_path, char const *key_path)
{
    /* Set the key and cert */
    if (SSL_CTX_use_certificate_file(ctx, cert_path, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

int server(char const *cert_path, char const *key_path, uint16_t port, cl_msg_handler_t handler)
{
    if (!cert_path || !key_path || !handler)
    {
        errno = EINVAL;
        return -1;
    }

    int r = 0;

    int sock;
    SSL_CTX *ctx;

    init_openssl();
    ctx = create_context();

    configure_context(ctx, cert_path, key_path);

    sock = create_socket(port);

    /* Handle connections */
    int stop = 0;
    while (!stop)
    {
        struct sockaddr_in addr;
        uint len = sizeof(addr);
        SSL *ssl;
        const char replyNotOk[] = "not ok";
        const char replyOk[]    = "ok";

        int client = accept(sock, (struct sockaddr*)&addr, &len);
        if (client < 0)
        {
            r = -1;
            goto error;
        }

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);

        int const buffSize = 100;
        char buff[buffSize];

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
        }
        else {
            int const bytes = SSL_read(ssl, buff, buffSize);
            if (bytes > 0) {
                buff[bytes] = '\0';
                char const *ans = 0 == handler(buff) ? replyOk : replyNotOk;
                SSL_write(ssl, ans, strlen(ans));
                stop = 0 == strcmp(buff, "stop");
            }
            else {
                r    = -1;
                stop = 1;
            }
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client);

    }

error:
    close(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();

    return r;
}
