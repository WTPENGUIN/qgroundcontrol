#ifndef PQC_TLS_WRAPPER_H
#define PQC_TLS_WRAPPER_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct pqc_tls_ctx_t pqc_tls_ctx_t;

// C 라이브러리의 로그를 C++로 전달하기 위한 콜백 함수 포인터
typedef void (*pqc_log_cb_t)(void* user_data, const char* msg);

void pqc_tls_init_library(void);

// 컨텍스트 생성 (로깅 콜백 포함)
pqc_tls_ctx_t* pqc_tls_connect(const char* ip, int port, 
                               const char* client_pem, const char* ca_crt,
                               pqc_log_cb_t log_cb, void* user_data);

int pqc_tls_get_fd(const pqc_tls_ctx_t* ctx);

// 논블로킹 읽기: dec_buf에 복호화 데이터 반환, encrypted_len에 TLS 레코드 암호화 바이트 수 반환
// 반환값: 복호화된 바이트 수 (0=데이터 없음, -1=에러)
int pqc_tls_read(pqc_tls_ctx_t* ctx, uint8_t* dec_buf, int max_len, int* encrypted_len);
int pqc_tls_write(pqc_tls_ctx_t* ctx, const uint8_t* buf, int len);

void pqc_tls_close(pqc_tls_ctx_t* ctx);

#ifdef __cplusplus
}
#endif

#endif // PQC_TLS_WRAPPER_H
