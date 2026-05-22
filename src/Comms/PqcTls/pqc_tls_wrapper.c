#include "pqc_tls_wrapper.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/provider.h>

struct pqc_tls_ctx_t {
    int sockfd;
    SSL_CTX* ssl_ctx;
    SSL* ssl;
    pqc_log_cb_t log_cb;
    void* user_data;
};

static int g_initialized = 0;

static void log_msg(pqc_tls_ctx_t* ctx, const char* msg) {
    if (ctx && ctx->log_cb) {
        ctx->log_cb(ctx->user_data, msg);
    }
}

void pqc_tls_init_library(void) {
    if (g_initialized) return;
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
    OSSL_PROVIDER_load(NULL, "default");
    OSSL_PROVIDER_load(NULL, "base");
    g_initialized = 1;
}

pqc_tls_ctx_t* pqc_tls_connect(const char* ip, int port, const char* client_pem, const char* ca_crt, pqc_log_cb_t log_cb, void* user_data) {
    pqc_tls_init_library();

    pqc_tls_ctx_t* ctx = (pqc_tls_ctx_t*)calloc(1, sizeof(pqc_tls_ctx_t));
    if (!ctx) return NULL;
    ctx->log_cb = log_cb;
    ctx->user_data = user_data;

    log_msg(ctx, "Initializing PQC mTLS connection...");

    ctx->ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx->ssl_ctx) goto error;

    SSL_CTX_set_min_proto_version(ctx->ssl_ctx, TLS1_3_VERSION);
    SSL_CTX_set1_groups_list(ctx->ssl_ctx, "mlkem768:x25519:p256");

    if (SSL_CTX_use_certificate_file(ctx->ssl_ctx, client_pem, SSL_FILETYPE_PEM) <= 0) {
        char errbuf[256];
        unsigned long err = ERR_get_error();
        snprintf(errbuf, sizeof(errbuf), "Error: Failed to load client certificate: %s", 
                 ERR_error_string(err, NULL));
        log_msg(ctx, errbuf);
        goto error;
    }
    
    if (SSL_CTX_use_PrivateKey_file(ctx->ssl_ctx, client_pem, SSL_FILETYPE_PEM) <= 0) {
        char errbuf[256];
        unsigned long err = ERR_get_error();
        snprintf(errbuf, sizeof(errbuf), "Error: Failed to load client private key: %s", ERR_error_string(err, NULL));
        log_msg(ctx, errbuf);
        goto error;
    }

    if (!SSL_CTX_check_private_key(ctx->ssl_ctx)) {
        log_msg(ctx, "Error: Client certificate and private key do not match!");
        goto error;
    }

    if (SSL_CTX_load_verify_locations(ctx->ssl_ctx, ca_crt, NULL) <= 0) {
        char errbuf[256];
        unsigned long err = ERR_get_error();
        snprintf(errbuf, sizeof(errbuf), "Error: Failed to Verify CA: %s", ERR_error_string(err, NULL));
        log_msg(ctx, errbuf);
        goto error;
    }

    SSL_CTX_set_verify(ctx->ssl_ctx, SSL_VERIFY_PEER, NULL);

    ctx->sockfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &serv_addr.sin_addr);

    log_msg(ctx, "Connecting to target socket...");
    if (connect(ctx->sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        char errbuf[256];
        snprintf(errbuf, sizeof(errbuf), "Error: Socket connection failed: %s (errno: %d)",
                 strerror(errno), errno);
        log_msg(ctx, errbuf);
        goto error;
    }

    ctx->ssl = SSL_new(ctx->ssl_ctx);
    SSL_set_fd(ctx->ssl, ctx->sockfd);
    
    log_msg(ctx, "Performing PQC TLS Handshake...");
    if (SSL_connect(ctx->ssl) <= 0) {
        char errbuf[512];
        unsigned long err = ERR_get_error();
        snprintf(errbuf, sizeof(errbuf), "Error: PQC TLS Handshake failed: %s",
                 ERR_error_string(err, NULL));
        log_msg(ctx, errbuf);
        goto error;
    }
    log_msg(ctx, "PQC mTLS Handshake Successful!");

    int flags = fcntl(ctx->sockfd, F_GETFL, 0);
    fcntl(ctx->sockfd, F_SETFL, flags | O_NONBLOCK);

    return ctx;

error:
    pqc_tls_close(ctx);
    return NULL;
}

int pqc_tls_get_fd(const pqc_tls_ctx_t* ctx) { return ctx ? ctx->sockfd : -1; }

int pqc_tls_read(pqc_tls_ctx_t* ctx, uint8_t* dec_buf, int max_len, int* encrypted_len) {
    if (!ctx || !ctx->ssl || !encrypted_len) return -1;
    
    *encrypted_len = 0;
    
    // TLS 레코드는 암호화되어 소켓에 있음. 읽기 전에 소켓 버퍼 크기 확인
    // (MSG_PEEK으로 TLS 레코드 크기 추정)
    uint8_t peek_buf[5];
    int peek_len = recv(ctx->sockfd, peek_buf, sizeof(peek_buf), MSG_PEEK | MSG_DONTWAIT);
    if (peek_len > 0) {
        // TLS 레코드 헤더: [ContentType(1)] [Version(2)] [Length(2)]
        // 길이는 빅엔디안으로 인코딩됨 (최대 16KB + 헤더 = 16389 바이트)
        if (peek_len >= 5) {
            int tls_record_len = (peek_buf[3] << 8) | peek_buf[4];
            *encrypted_len = tls_record_len + 5;  // 헤더 + 페이로드
        }
    }
    
    // SSL_read()로 복호화된 데이터를 읽음
    int r = SSL_read(ctx->ssl, dec_buf, max_len);
    if (r <= 0) {
        int err = SSL_get_error(ctx->ssl, r);
        if (err == SSL_ERROR_WANT_READ) {
            char logbuf[128];
            snprintf(logbuf, sizeof(logbuf), "SSL_read: Waiting for data (encrypted: %d bytes)", *encrypted_len);
            log_msg(ctx, logbuf);
            return 0;
        } else if (err == SSL_ERROR_WANT_WRITE) {
            log_msg(ctx, "SSL_read: Need to send pending data first");
            return 0;
        } else {
            char errbuf[256];
            unsigned long ssl_err = ERR_get_error();
            snprintf(errbuf, sizeof(errbuf), "SSL_read: Connection error: %s",
                     ERR_error_string(ssl_err, NULL));
            log_msg(ctx, errbuf);
            return -1;
        }
    }
    
    return r;
}

int pqc_tls_write(pqc_tls_ctx_t* ctx, const uint8_t* buf, int len) {
    if (!ctx || !ctx->ssl) return -1;
    
    int r = SSL_write(ctx->ssl, buf, len);
    if (r > 0) {
        char logbuf[256];
        snprintf(logbuf, sizeof(logbuf), "SSL_write: Sent %d bytes (requested %d)", r, len);
        log_msg(ctx, logbuf);
        return r;
    }
    
    if (r <= 0) {
        int err = SSL_get_error(ctx->ssl, r);
        if (err == SSL_ERROR_WANT_READ) {
            log_msg(ctx, "SSL_write: Need to read pending data first");
            return 0;
        } else if (err == SSL_ERROR_WANT_WRITE) {
            log_msg(ctx, "SSL_write: Buffer full, retry later");
            return 0;
        } else {
            char errbuf[256];
            unsigned long ssl_err = ERR_get_error();
            snprintf(errbuf, sizeof(errbuf), "SSL_write: Connection error: %s",
                     ERR_error_string(ssl_err, NULL));
            log_msg(ctx, errbuf);
            return -1;
        }
    }
    return r;
}

void pqc_tls_close(pqc_tls_ctx_t* ctx) {
    if (!ctx) return;
    if (ctx->sockfd >= 0) {
        int flags = fcntl(ctx->sockfd, F_GETFL, 0);
        fcntl(ctx->sockfd, F_SETFL, flags & ~O_NONBLOCK);
    }
    if (ctx->ssl) { SSL_shutdown(ctx->ssl); SSL_free(ctx->ssl); }
    if (ctx->sockfd >= 0) close(ctx->sockfd);
    if (ctx->ssl_ctx) SSL_CTX_free(ctx->ssl_ctx);
    free(ctx);
}
