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
void pqc_tls_cleanup_library(void);

// 컨텍스트 생성 (로깅 콜백 포함)
pqc_tls_ctx_t* pqc_tls_connect(const char* ip, int port, 
                               const char* client_pem, const char* ca_crt,
                               pqc_log_cb_t log_cb, void* user_data);

int pqc_tls_get_fd(const pqc_tls_ctx_t* ctx);

// dec_buf: 복호화된 평문 데이터가 저장될 버퍼
// max_dec_len: dec_buf의 최대 크기
// enc_buf: 암호화된 TLS 레코드 원본이 저장될 버퍼 (NULL 허용)
// max_enc_len: enc_buf의 최대 크기
// out_enc_len: 실제로 enc_buf에 복사된 암호화 데이터의 길이 반환
// 반환값: 복호화된 바이트 수 (0=데이터 없음, -1=에러)
int pqc_tls_read(pqc_tls_ctx_t* ctx, 
                 uint8_t* dec_buf, int max_dec_len, 
                 uint8_t* enc_buf, int max_enc_len, int* out_enc_len);

int pqc_tls_write(pqc_tls_ctx_t* ctx, const uint8_t* buf, int len);

void pqc_tls_close(pqc_tls_ctx_t* ctx);

// ===== TLS HandShake Information Structures =====

typedef struct {
    char name[128];      // e.g., "TLS_AES_256_GCM_SHA384"
    int bits;            // e.g., 256
} pqc_tls_cipher_t;

typedef struct {
    char version[32];    // e.g., "TLSv1.3"
} pqc_tls_version_t;

typedef struct {
    char group_name[128]; // e.g., "mlkem768"
    int nid;             // NID (e.g., 16781804)
} pqc_tls_key_exchange_t;

typedef struct {
    char algorithm[128]; // e.g., "id-ml-dsa-65"
    char long_name[256]; // Full algorithm name
} pqc_tls_signature_t;

typedef struct {
    char algorithm[128]; // e.g., "ML-DSA-65"
    int key_bits;        // e.g., 15616
    char long_name[256]; // Full algorithm name
} pqc_tls_public_key_t;

// 통합 구조체
typedef struct {
    pqc_tls_cipher_t cipher;
    pqc_tls_version_t version;
    pqc_tls_key_exchange_t key_exchange;
    pqc_tls_signature_t signature;
    pqc_tls_public_key_t public_key;
    int valid;  // 1=유효, 0=유효하지 않음 (NULL ctx 등)
} pqc_tls_handshake_info_t;

// ===== TLS HandShake Information Functions =====

// 통합 함수 (모든 정보 한 번에 조회)
pqc_tls_handshake_info_t pqc_tls_get_handshake_info(const pqc_tls_ctx_t* ctx);

// 개별 조회 함수 (선택적)
pqc_tls_cipher_t pqc_tls_get_cipher(const pqc_tls_ctx_t* ctx);
pqc_tls_version_t pqc_tls_get_version(const pqc_tls_ctx_t* ctx);
pqc_tls_key_exchange_t pqc_tls_get_key_exchange_group(const pqc_tls_ctx_t* ctx);
pqc_tls_signature_t pqc_tls_get_server_cert_signature(const pqc_tls_ctx_t* ctx);
pqc_tls_public_key_t pqc_tls_get_server_public_key(const pqc_tls_ctx_t* ctx);

#ifdef __cplusplus
}
#endif

#endif // PQC_TLS_WRAPPER_H
