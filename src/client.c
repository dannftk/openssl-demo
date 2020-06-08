#include "client.h"

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <math.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#if (SSLEAY_VERSION_NUMBER >= 0x0907000L)
# include <openssl/conf.h>
#endif

static void init_openssl_library(void)
{
    (void)SSL_library_init();

    SSL_load_error_strings();

    /* ERR_load_crypto_strings(); */

    OPENSSL_config(NULL);

    /* Include <openssl/opensslconf.h> to get this define */
#if defined (OPENSSL_THREADS)
    printf("Warning: thread locking is not implemented\n");
#endif
}

static int verify_callback(int preverify, X509_STORE_CTX* x509_ctx)
{
    int depth = X509_STORE_CTX_get_error_depth(x509_ctx);
    int err = X509_STORE_CTX_get_error(x509_ctx);

    X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    X509_NAME* iname = cert ? X509_get_issuer_name(cert) : NULL;
    X509_NAME* sname = cert ? X509_get_subject_name(cert) : NULL;

  //add hwi   print_cn_name("Issuer (cn)", iname);
  //add hwi   print_cn_name("Subject (cn)", sname);

    if (depth == 0) {
        /* If depth is 0, its the server's certificate. Print the SANs too */
 //add hwi        print_san_name("Subject (san)", cert);
    }

    return preverify;
}

static void handleFailure(int reason)
{
    fprintf(stderr, "error:%d\n", reason);
}

int client(char const *cert_path, char const *host, uint16_t port, char const *msg, srv_ans_handler_t handler)
{
    if (!cert_path || !host || !msg)
    {
        errno = EINVAL;
        return -1;
    }

    setvbuf(stdout, NULL, _IONBF, 0);

    long res = 1;

    SSL_CTX* ctx = NULL;
    BIO *web = NULL, *out = NULL;
    SSL *ssl = NULL;

    init_openssl_library();

    const SSL_METHOD* method = SSLv23_client_method();
    if (!(NULL != method)) handleFailure(1);

    ctx = SSL_CTX_new(method);
    if (!(ctx != NULL)) handleFailure(2);

    /* Cannot fail ??? */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);

    /* Cannot fail ??? */
    SSL_CTX_set_verify_depth(ctx, 4);

    /* Cannot fail ??? */
    const long flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
    SSL_CTX_set_options(ctx, flags);

    res = SSL_CTX_load_verify_locations(ctx, cert_path, NULL);
    if (!(1 == res)) handleFailure(3);

    web = BIO_new_ssl_connect(ctx);
    if (!(web != NULL)) handleFailure(4);

    size_t const hostname_size = strlen(host) + static_cast<int>(log10(port)) + 3;
    char *hostname = malloc(hostname_size);
    sprintf(hostname, "%s:%" PRIu16, host, port);
    hostname[hostname_size - 1] = '\0';
    res = BIO_set_conn_hostname(web, hostname);
    free(hostname);
    if (!(1 == res)) handleFailure(5);

    BIO_get_ssl(web, &ssl);
    if (!(ssl != NULL)) handleFailure(6);

    const char* const PREFERRED_CIPHERS = "HIGH:!aNULL:!PSK:!SRP:!MD5:!RC4";
    res = SSL_set_cipher_list(ssl, PREFERRED_CIPHERS);
    if (!(1 == res)) handleFailure(7);

    res = SSL_set_tlsext_host_name(ssl, host);
    if (!(1 == res)) handleFailure(8);

    res = BIO_do_connect(web);
    if (!(1 == res)) handleFailure(10);

    res = BIO_do_handshake(web);
    if (!(1 == res)) handleFailure(11);

    /* Step 1: verify a server certificate was presented during the negotiation */
    X509* cert = SSL_get_peer_certificate(ssl);
    if (cert) {
        X509_free(cert);
    } /* Free immediately */

    if (NULL == cert)
        handleFailure(12);

    /* Step 2: verify the result of chain verification */
    /* Verification performed according to RFC 4158    */
    res = SSL_get_verify_result(ssl);
    if (!(X509_V_OK == res))
        handleFailure(13);

    /* Step 3: hostname verification */
    /* An exercise left to the reader */

    BIO_puts(web, msg);

    int len = 0;
    do
    {
        char buff[1536] = {};
        len = BIO_read(web, buff, sizeof(buff));
        if (len > 0 && handler)
        {
            buff[len] = '\0';
            handler(buff);
        }
    } while (len > 0 || BIO_should_retry(web));

    if (web != NULL)
        BIO_free_all(web);

    if (NULL != ctx)
        SSL_CTX_free(ctx);

    return 0;
}
