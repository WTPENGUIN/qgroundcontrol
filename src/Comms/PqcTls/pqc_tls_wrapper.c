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
static OSSL_PROVIDER* g_default_provider = NULL;
static OSSL_PROVIDER* g_base_provider = NULL;

static void log_msg(pqc_tls_ctx_t* ctx, const char* msg) {
    if (ctx && ctx->log_cb) {
        ctx->log_cb(ctx->user_data, msg);
    }
}

void pqc_tls_init_library(void) {
    if (g_initialized) return;
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL);
    g_default_provider = OSSL_PROVIDER_load(NULL, "default");
    g_base_provider = OSSL_PROVIDER_load(NULL, "base");
    g_initialized = 1;
}

void pqc_tls_cleanup_library(void) {
    if (!g_initialized) return;
    
    if (g_default_provider) {
        OSSL_PROVIDER_unload(g_default_provider);
        g_default_provider = NULL;
    }
    
    if (g_base_provider) {
        OSSL_PROVIDER_unload(g_base_provider);
        g_base_provider = NULL;
    }
    
    g_initialized = 0;
}

pqc_tls_ctx_t* pqc_tls_connect(const char* ip, int port, const char* client_pem, const char* ca_crt, pqc_log_cb_t log_cb, void* user_data) {
    pqc_tls_init_library();

    pqc_tls_ctx_t* ctx = (pqc_tls_ctx_t*)calloc(1, sizeof(pqc_tls_ctx_t));
    if (!ctx) return NULL;
    ctx->sockfd = -1;
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

int pqc_tls_read(pqc_tls_ctx_t* ctx, 
                 uint8_t* dec_buf, int max_dec_len, 
                 uint8_t* enc_buf, int max_enc_len, int* out_enc_len) {
    
    if (!ctx || !ctx->ssl || !out_enc_len) return -1;
    
    *out_enc_len = 0;
    
    // 1. 헤더 5바이트를 Peek하여 TLS 레코드 전체 길이 추정
    uint8_t peek_buf[5];
    int peek_len = recv(ctx->sockfd, peek_buf, sizeof(peek_buf), MSG_PEEK | MSG_DONTWAIT);
    
    if (peek_len >= 5) {
        // TLS 레코드 헤더: [ContentType(1)] [Version(2)] [Length(2)]
        int tls_record_len = (peek_buf[3] << 8) | peek_buf[4];
        int total_enc_len = tls_record_len + 5;  // 헤더 + 페이로드
        
        // 사용자가 제공한 버퍼 크기(max_enc_len)를 초과하지 않도록 방어 로직 추가
        int copy_len = (total_enc_len > max_enc_len) ? max_enc_len : total_enc_len;
        
        // enc_buf가 유효하게 제공되었다면 암호화된 패킷 데이터를 추출하여 저장
        if (enc_buf && copy_len > 0) {
            int full_peek = recv(ctx->sockfd, enc_buf, copy_len, MSG_PEEK | MSG_DONTWAIT);
            if (full_peek > 0) {
                *out_enc_len = full_peek; // 실제로 읽어온 암호화 데이터 크기 기록
            }
        } else {
            // 버퍼가 제공되지 않은 경우, 길이 정보만 갱신
            *out_enc_len = total_enc_len;
        }
    }
    
    // 2. SSL_read()로 복호화된 데이터를 읽음 (여기서 소켓의 원본 암호화 데이터가 소모됨)
    int r = SSL_read(ctx->ssl, dec_buf, max_dec_len);
    
    if (r <= 0) {
        int err = SSL_get_error(ctx->ssl, r);
        if (err == SSL_ERROR_WANT_READ) {
            // 논블로킹 상태에서의 정상적인 대기
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
    
    return r; // 복호화된 평문 데이터의 길이 반환
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
