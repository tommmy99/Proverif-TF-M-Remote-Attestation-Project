//! 09/03/26 17:50

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "psa/client.h"
#include "psa/initial_attestation.h"
#include "psa/crypto.h"

#include "tfm_plat_ns.h"
#include "cmsis_compiler.h"
#include "Driver_USART_RPI.h"

#include "qcbor/qcbor_spiffy_decode.h"
#include "qcbor/UsefulBuf.h"
#include "qcbor/qcbor_decode.h"

#include "t_cose/q_useful_buf.h"
#include "t_cose/t_cose_sign1_verify.h"

#define UART_TIMEOUT_SPIN   (3000000u)

#define NONCE_LEN           (32u)
#define PUB_UNCOMP_LEN      (65u)
#define HASH_LEN            (32u)
#define HMAC_LEN            (32u)
#define TOKEN_BUF_LEN       (0x400u)
#define ECDH_MAX            (128u)

#define IV_LEN            (12u)
#define TAG_LEN           (16u)

#define IAT_CHALLENGE_LEGACY      (-75008)
#define IAT_SW_COMPONENTS_LEGACY  (-75006)
#define IAT_MEAS_VALUE             2

#define ntohs(x) (uint16_t)((((x) & 0x00ff) << 8) | (((x) & 0xff00) >> 8))

extern ARM_DRIVER_USART driver_usart0;

__WEAK int32_t tfm_ns_platform_init(void)
{
    return 0;
}

// ECDSA 1024 Public Key (different format than openssl : raw uncompressed)
static const uint8_t Verif_V[] = {
0x04,
0x84,0x97,0x0C,0x36,0x36,0xBE,0xE8,0xC3,0x19,0xDE,0xDE,0x45,
0x86,0xF9,0xFA,0xC1,0x5E,0x08,0x77,0xC3,0x00,0x92,0x54,0xE6,
0xFD,0xC6,0x20,0x99,0x17,0x25,0x3C,0x93,0x4F,0xD2,0x4E,0xD2,
0x28,0x21,0xE9,0x53,0xD3,0xF4,0x70,0x2E,0x0D,0xB0,0x41,0x38,
0x47,0x1F,0x51,0x91,0x9A,0x4E,0x7D,0x8D,0xDB,0xB0,0x62,0x3B,
0xB5,0xBD,0x78,0xA8
};

//* ================================================================== 
//*                              ERRORS
//* ==================================================================   

typedef enum {
    ERR_OK = 0,
    ERR_UART_INIT       = 1,
    ERR_UART_POWER      = 2,
    ERR_UART_CTRL_TX    = 3,
    ERR_UART_CTRL_RX    = 4,
    ERR_SYNC_RX_LINE    = 5,
    ERR_SYNC_BAD_READY  = 6,

    ERR_RX_NONCE        = 7,
    ERR_RX_KPUV         = 8,

    ERR_TOKEN_SIZE      = 9,
    ERR_TOKEN_BUF_SMALL = 10,
    ERR_TOKEN_GET       = 11,

    ERR_TX_TOKEN        = 12,
    ERR_TX_KPUA         = 13,

    ERR_CRYPTO_INIT     = 14,
    ERR_KEY_GEN         = 15,
    ERR_PUB_EXPORT      = 16,

    ERR_HASH            = 17,
    ERR_ECDH            = 18,
    ERR_KSESS_DERIVE    = 19,

    ERR_HMAC_IMPORT     = 20,
    ERR_RX_MACV         = 21,
    ERR_HMAC_VERIFY     = 22,
    ERR_TX_MACA         = 23,

    ERR_RX_IV           = 24,
    ERR_RX_CT           = 25,
    ERR_TX_ECHO         = 26,

    ERR_TX_KSESS        = 27,
    ERR_AES_IMPORT      = 28,
    ERR_AES_DECRYPT     = 29,

    ERR_TX_REPLY        = 30,
    ERR_AES_ENCRYPT     = 31,
    
    ERR_PARSE_TOKEN1     = 32,
    ERR_PARSE_TOKEN2     = 33,
    ERR_PARSE_TOKEN3     = 34,
    ERR_TX_MEASB         = 35,
    ERR_RX_SIG_LEN       = 36,
    ERR_SIG_TOO_LARGE    = 37,
    ERR_RX_SIG           = 38,
    ERR_KEY_IMPORT       = 39,
    ERR_HASH_FAILED      = 40,
    ERR_AUTH_V_FAILED    = 41,
} app_err_t;

//forward declaration
static void uart_send_str(const char *s);


/**
 * @brief Sends a fatal error code over UART and halts the device.
 *
 * This helper is used for unrecoverable errors on the attester side.
 * It formats the provided application error code as an ASCII string
 * of the form "ERR:<code>\n" and transmits it over the UART so that
 * the remote verifier can diagnose the failure reason.
 *
 * After sending the error message, the function waits briefly to allow
 * the UART transmit buffer to flush, then enters an infinite loop to
 * stop further execution in a known and safe state.
 *
 * @param e Application-specific error code indicating the failure reason.
 */
static void fail(app_err_t e)
{
    char msg[24];
    int n = snprintf(msg, sizeof(msg), "ERR:%d\n", (int)e);
    if (n > 0) uart_send_str(msg);

    /* Allow time for UART transmission to complete */
    for (volatile uint32_t i = 0; i < 200000; i++) { __NOP(); }

    /* Halt execution permanently */
    while (1) { __NOP(); }
}


/**
 * @brief Sends a fatal application + PSA error code over UART and halts the device.
 *
 * This helper is used for unrecoverable errors that originate from PSA Crypto
 * API calls. It formats the provided application error code @p e together with
 * the PSA status value @p st as an ASCII string of the form:
 *
 *   "ERR:<app_code>:<psa_status>\n"
 *
 * and transmits it over the UART so that the remote verifier can diagnose both
 * the high-level protocol failure and the underlying cryptographic error.
 *
 * After sending the error message, the function enters an infinite loop to
 * permanently halt execution in a known and safe state.
 *
 * @param e  Application-specific error code indicating the failure reason.
 * @param st PSA status code returned by a PSA Crypto API function.
 */
static void fail_psa(app_err_t e, psa_status_t st)
{
    char msg[48];
    int n = snprintf(msg, sizeof(msg), "ERR:%d:%ld\n", (int)e, (long)st);
    if (n > 0) uart_send_str(msg);

    /* Halt execution permanently */
    while (1) { __NOP(); }
}


//* ================================================================== 
//*                              UART
//* ==================================================================   

/**
 * @brief Sends exactly @p len bytes over the UART (blocking with a spin timeout).
 *
 * This helper starts an asynchronous UART transmission using the CMSIS-Driver
 * USART interface and then busy-waits until the driver reports that the TX is
 * no longer busy. A simple decrementing guard counter is used to provide a
 * hard timeout and avoid blocking forever in case of driver/hardware issues.
 *
 * @param buf Pointer to the data to transmit.
 * @param len Number of bytes to send.
 *
 * @return 0 on success (TX completed),
 *         -1 on timeout while waiting for TX completion.
 */
static int uart_send_exact(const uint8_t *buf, size_t len)
{
    driver_usart0.Send(buf, len);
    volatile uint32_t guard = UART_TIMEOUT_SPIN;
    while (driver_usart0.GetStatus().tx_busy) {
        if (guard-- == 0) return -1;
    }
    return 0;
}

/**
 * @brief Receives exactly @p len bytes over the UART (blocking with a spin timeout).
 *
 * This helper starts an asynchronous UART reception using the CMSIS-Driver
 * USART interface and then busy-waits until the driver reports that the RX is
 * no longer busy. A decrementing guard counter is used to provide a hard
 * timeout and avoid blocking forever if data never arrives.
 *
 * @param[out] buf Output buffer that will receive the bytes.
 * @param len Number of bytes to receive.
 *
 * @return 0 on success (RX completed),
 *         -1 on timeout while waiting for RX completion.
 */
static int uart_receive_exact(uint8_t *buf, size_t len)
{
    driver_usart0.Receive(buf, len);
    volatile uint32_t guard = UART_TIMEOUT_SPIN;
    while (driver_usart0.GetStatus().rx_busy) {
        if (guard-- == 0) return -1;
    }
    return 0;
}

/**
 * @brief Sends a NUL-terminated C string over the UART.
 *
 * This helper transmits the bytes of the input string @p s using
 * uart_send_exact(). The terminating NUL byte is not transmitted.
 *
 * Errors are intentionally ignored (best-effort) because this function is
 * typically used for debug/status messages.
 *
 * @param s NUL-terminated string to send.
 */
static void uart_send_str(const char *s)
{
    (void)uart_send_exact((const uint8_t *)s, strlen(s));
}

/**
 * @brief Reads a newline-terminated ASCII line from the UART.
 *
 * This helper reads bytes one-by-one until either:
 *   - a newline character ('\n') is received, or
 *   - the output buffer is full (leaving space for the terminating NUL).
 *
 * Carriage returns ('\r') are skipped. On success, the output buffer is
 * always NUL-terminated so it can be treated as a C string. The newline
 * character, if received, is included in the buffer (before the terminating NUL).
 *
 * @param[out] out Output buffer that will receive the line.
 * @param maxlen Capacity of @p out in bytes. Must be >= 2.
 *
 * @return 0 on success,
 *         -1 on UART receive timeout/error.
 */
static int uart_read_line(uint8_t *out, size_t maxlen)
{
    size_t i = 0;
    while (i < maxlen - 1) {
        uint8_t c;
        if (uart_receive_exact(&c, 1) != 0) return -1;
        if (c == '\r') continue;
        out[i++] = c;
        if (c == '\n') break;
    }
    out[i] = 0;
    return 0;
}

/**
 * @brief Sends a binary buffer as a single uppercase hex-encoded line over UART.
 *
 * This helper converts each byte of @p buf into two ASCII hex characters
 * (uppercase) and transmits them using uart_send_exact(). After all bytes are
 * sent, it appends a newline character ('\n') to terminate the line.
 *
 * The output format is:
 *   - 2 * @p len hex characters (no separators),
 *   - followed by '\n'.
 *
 * @param buf Input binary data to encode and send.
 * @param len Number of bytes in @p buf.
 *
 * @return 0 on success,
 *         -1 on UART send timeout/error.
 */
static int uart_send_hex_line(const uint8_t *buf, size_t len)
{
    static const char hx[] = "0123456789ABCDEF";
    uint8_t out[2];

    for (size_t i = 0; i < len; i++) {
        out[0] = (uint8_t)hx[(buf[i] >> 4) & 0x0F];
        out[1] = (uint8_t)hx[(buf[i]     ) & 0x0F];
        if (uart_send_exact(out, 2) != 0) return -1;
    }
    const uint8_t nl = '\n';
    return uart_send_exact(&nl, 1);
}

/**
 * @brief Converts a single ASCII hex digit into its numeric value.
 *
 * Accepts '0'..'9', 'a'..'f', and 'A'..'F'. Any other character is rejected.
 *
 * @param c Input character.
 *
 * @return 0..15 on success,
 *         -1 if @p c is not a valid hex digit.
 */
static int hexn(int c){
    if(c>='0'&&c<='9') return c-'0';
    if(c>='a'&&c<='f') return 10+(c-'a');
    if(c>='A'&&c<='F') return 10+(c-'A');
    return -1;
}

/**
 * @brief Converts an ASCII hex string into binary.
 *
 * This helper converts exactly @p hexlen characters from @p hex into binary
 * bytes in @p out. The input length must be even (two hex characters per byte).
 *
 * @param hex    Pointer to ASCII hex characters (no NUL required).
 * @param hexlen Number of hex characters to parse.
 * @param[out] out Output buffer that will receive the binary bytes.
 * @param outcap Capacity of @p out in bytes.
 *
 * @return Number of bytes written to @p out on success,
 *         -1 on error (odd length, invalid characters, or output too small).
 */
static int hex2bin_str(const char *hex, size_t hexlen, uint8_t *out, size_t outcap){
    if(hexlen % 2) return -1;
    size_t outlen = hexlen / 2;
    if(outlen > outcap) return -1;

    for(size_t i=0;i<outlen;i++){
        int hi = hexn((unsigned char)hex[2*i]);
        int lo = hexn((unsigned char)hex[2*i+1]);
        if(hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi<<4) | lo);
    }
    return (int)outlen;
}

/**
 * @brief Reads a newline-terminated ASCII hex line from UART and converts it to binary.
 *
 * This helper reads a line using uart_read_line(), trims trailing newline,
 * carriage return, and whitespace characters, then converts the remaining
 * ASCII hex string into binary using hex2bin_str().
 *
 * The line must contain an even number of hex characters (two per byte).
 *
 * @param[out] out Output buffer that will receive the decoded bytes.
 * @param outcap Capacity of @p out in bytes.
 * @param[out] outlen Optional pointer that receives the number of decoded bytes.
 *                    May be NULL.
 *
 * @return 0 on success,
 *         -1 on UART read error or hex decode error.
 */
static int uart_read_hex_line(uint8_t *out, size_t outcap, size_t *outlen){
    uint8_t line_hex[256];
    if(uart_read_line(line_hex, sizeof(line_hex)) != 0) return -1;

    /* trim trailing '\n', '\r', spaces, tabs */
    size_t n = strlen((char*)line_hex);
    while(n && (line_hex[n-1]=='\n' || line_hex[n-1]=='\r' ||
                line_hex[n-1]==' '  || line_hex[n-1]=='\t')) {
        n--;
    }

    int blen = hex2bin_str((const char*)line_hex, n, out, outcap);
    if(blen < 0) return -1;
    if(outlen) *outlen = (size_t)blen;
    return 0;
}

//* ================================================================== 
//*                              CRYPTO_PSA
//* ==================================================================   

/**
 * @brief Global handle for the attester ephemeral ECDH key pair.
 *
 * This handle is populated by generate_ephemeral_keypair_and_pub() and then
 * reused by ecdh_agree() for raw ECDH key agreement.
 */

static psa_key_handle_t g_eph_key = 0;

/**
 * @brief Checks a PSA status code and aborts the protocol on failure.
 *
 * This helper verifies that the PSA Crypto function returned PSA_SUCCESS.
 * If not, it triggers a fatal error via fail() using the provided application
 * error code.
 *
 * @param st PSA status code to check.
 * @param e  Application-specific error code to report if @p st indicates failure.
 */

static void psa_check(psa_status_t st, app_err_t e)
{
    if (st != PSA_SUCCESS) fail(e);
}

/**
 * @brief Initializes the PSA Crypto subsystem.
 *
 * This helper calls psa_crypto_init() to initialize the PSA Crypto library.
 * It is safe to call multiple times in many PSA implementations; this code
 * uses it as a simple "init once" entrypoint before performing crypto
 * operations.
 */

static void crypto_init_once(void)
{
    psa_status_t st = psa_crypto_init();
    psa_check(st, ERR_CRYPTO_INIT);
}

/**
 * @brief Generates an ephemeral P-256 ECDH key pair and exports the public key.
 *
 * This helper:
 *   - initializes PSA Crypto (if needed),
 *   - configures key attributes for an ECC secp256r1 (P-256) key pair,
 *   - generates the key into the global handle @c g_eph_key,
 *   - exports the corresponding public key into @p kpuA.
 *
 * The key is intended for ECDH derivation and public-key export.
 *
 * @param[out] kpuA Output buffer that will receive the public key in the
 *                 expected uncompressed format (PUB_UNCOMP_LEN bytes).
 */

static void generate_ephemeral_keypair_and_pub(uint8_t kpuA[PUB_UNCOMP_LEN])
{
    crypto_init_once();

    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attr, 256);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DERIVE | PSA_KEY_USAGE_EXPORT);
    psa_set_key_algorithm(&attr, PSA_ALG_ECDH);

    psa_status_t st = psa_generate_key(&attr, &g_eph_key);
    psa_reset_key_attributes(&attr);
    psa_check(st, ERR_KEY_GEN);

    size_t pub_len = 0;
    st = psa_export_public_key(g_eph_key, kpuA, PUB_UNCOMP_LEN, &pub_len);
    if (st != PSA_SUCCESS || pub_len != PUB_UNCOMP_LEN) fail(ERR_PUB_EXPORT);
}

/**
 * @brief Computes the session challenge hash: SHA256(nonce || KpuV || KpuA).
 *
 * This helper hashes the concatenation of:
 *   - @p nonce (NONCE_LEN bytes),
 *   - @p kpuV  (PUB_UNCOMP_LEN bytes),
 *   - @p kpuA  (PUB_UNCOMP_LEN bytes),
 * producing a 32-byte SHA-256 digest in @p out_hash.
 *
 * This value is used to bind the attestation token and the key exchange
 * to the current session and prevent replay.
 *
 * @param nonce     Session nonce received from the verifier.
 * @param kpuV      Verifier public key (uncompressed).
 * @param kpuA      Attester public key (uncompressed).
 * @param[out] out_hash Output buffer that will receive the SHA-256 digest
 *                      (HASH_LEN bytes).
 */

static void sha256_n_kv_ka(const uint8_t nonce[NONCE_LEN],
                           const uint8_t kpuV[PUB_UNCOMP_LEN],
                           const uint8_t kpuA[PUB_UNCOMP_LEN],
                           uint8_t out_hash[HASH_LEN])
{
    psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;
    psa_status_t st;

    st = psa_hash_setup(&op, PSA_ALG_SHA_256);
    if (st != PSA_SUCCESS) fail(ERR_HASH);

    st = psa_hash_update(&op, nonce, NONCE_LEN);
    if (st != PSA_SUCCESS) { psa_hash_abort(&op); fail(ERR_HASH); }

    st = psa_hash_update(&op, kpuV, PUB_UNCOMP_LEN);
    if (st != PSA_SUCCESS) { psa_hash_abort(&op); fail(ERR_HASH); }

    st = psa_hash_update(&op, kpuA, PUB_UNCOMP_LEN);
    if (st != PSA_SUCCESS) { psa_hash_abort(&op); fail(ERR_HASH); }

    size_t out_len = 0;
    st = psa_hash_finish(&op, out_hash, HASH_LEN, &out_len);
    if (st != PSA_SUCCESS || out_len != HASH_LEN) fail(ERR_HASH);
}

/**
 * @brief Performs ECDH key agreement to derive the shared secret Z.
 *
 * This helper computes:
 *   Z = ECDH(KprA, KpuV)
 *
 * using the attester ephemeral private key stored in the global handle
 * @c g_eph_key and the verifier public key @p kpuV.
 *
 * The shared secret is written to @p z and its actual length is returned
 * via @p zlen.
 *
 * @param kpuV  Verifier public key (uncompressed, PUB_UNCOMP_LEN bytes).
 * @param[out] z Output buffer that will receive the derived shared secret.
 * @param zcap  Capacity of @p z in bytes.
 * @param[out] zlen Receives the number of bytes written to @p z.
 */

static void ecdh_agree(const uint8_t kpuV[PUB_UNCOMP_LEN],
                       uint8_t *z, size_t zcap, size_t *zlen)
{
    psa_status_t st = psa_raw_key_agreement(PSA_ALG_ECDH,
                                           g_eph_key,
                                           kpuV, PUB_UNCOMP_LEN,
                                           z, zcap, zlen);
    if (st != PSA_SUCCESS || *zlen == 0) fail(ERR_ECDH);
}

/**
 * @brief Derives the session key material Ksess: SHA256(Z || chal || "RA-KSESS").
 *
 * This helper computes a 32-byte session key material value by hashing:
 *   - the ECDH shared secret @p z,
 *   - the session challenge hash @p chal (HASH_LEN bytes),
 *   - the ASCII label "RA-KSESS" (domain separation).
 *
 * The resulting digest (HASH_LEN bytes) is stored in @p ksess.
 *
 * @param z      Pointer to the ECDH shared secret.
 * @param zlen   Length of @p z in bytes.
 * @param chal   Session challenge hash (HASH_LEN bytes).
 * @param[out] ksess Output buffer that receives the derived key material
 *                   (HASH_LEN bytes).
 */

static void derive_ksess(const uint8_t *z, size_t zlen,
                         const uint8_t chal[HASH_LEN],
                         uint8_t ksess[HASH_LEN])
{
    static const uint8_t info[] = "RA-KSESS";
    psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;
    psa_status_t st;

    st = psa_hash_setup(&op, PSA_ALG_SHA_256);
    if (st != PSA_SUCCESS) fail(ERR_KSESS_DERIVE);

    st = psa_hash_update(&op, z, zlen);
    if (st != PSA_SUCCESS) { psa_hash_abort(&op); fail(ERR_KSESS_DERIVE); }

    st = psa_hash_update(&op, chal, HASH_LEN);
    if (st != PSA_SUCCESS) { psa_hash_abort(&op); fail(ERR_KSESS_DERIVE); }

    st = psa_hash_update(&op, info, sizeof(info) - 1);
    if (st != PSA_SUCCESS) { psa_hash_abort(&op); fail(ERR_KSESS_DERIVE); }

    size_t out_len = 0;
    st = psa_hash_finish(&op, ksess, HASH_LEN, &out_len);
    if (st != PSA_SUCCESS || out_len != HASH_LEN) fail(ERR_KSESS_DERIVE);
}

/**
 * @brief Imports a 256-bit HMAC-SHA256 key derived from Ksess.
 *
 * This helper imports @p ksess (HASH_LEN bytes) as an HMAC key suitable for
 * signing and verifying messages using HMAC(SHA-256). The returned key handle
 * must be destroyed by the caller when no longer needed (psa_destroy_key()).
 *
 * @param ksess Key material (HASH_LEN bytes) to import as an HMAC key.
 *
 * @return A valid PSA key handle on success; aborts via fail() on error.
 */

static psa_key_handle_t import_hmac_key_ksess(const uint8_t ksess[HASH_LEN])
{
    psa_key_handle_t h = 0;

    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attr, PSA_KEY_TYPE_HMAC);
    psa_set_key_bits(&attr, 256);
    psa_set_key_algorithm(&attr, PSA_ALG_HMAC(PSA_ALG_SHA_256));
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_VERIFY_MESSAGE);

    psa_status_t st = psa_import_key(&attr, ksess, HASH_LEN, &h);
    psa_reset_key_attributes(&attr);

    if (st != PSA_SUCCESS || h == 0) fail(ERR_HMAC_IMPORT);
    return h;
}

/**
 * @brief Computes HMAC(Ksess, label || chal) where msg = [label][chal].
 *
 * This helper constructs a message consisting of:
 *   - one-byte @p label ('V' or 'A'),
 *   - followed by @p chal (HASH_LEN bytes),
 * then computes HMAC-SHA256 over that message using @p hmac_key.
 *
 * The resulting MAC is written to @p out and must be exactly HMAC_LEN bytes.
 *
 * @param hmac_key Imported HMAC key handle.
 * @param label    Single-byte label used for domain separation ('V' or 'A').
 * @param chal     Session challenge hash (HASH_LEN bytes).
 * @param[out] out Output buffer that will receive the MAC (HMAC_LEN bytes).
 */

static void hmac_label_chal(psa_key_handle_t hmac_key,
                            uint8_t label,
                            const uint8_t chal[HASH_LEN],
                            uint8_t out[HMAC_LEN])
{
    uint8_t msg[1 + HASH_LEN];
    msg[0] = label;
    memcpy(&msg[1], chal, HASH_LEN);

    size_t mac_len = 0;
    psa_status_t st = psa_mac_compute(hmac_key,
                                     PSA_ALG_HMAC(PSA_ALG_SHA_256),
                                     msg, sizeof(msg),
                                     out, HMAC_LEN, &mac_len);
    if (st != PSA_SUCCESS || mac_len != HMAC_LEN) fail(ERR_HMAC_VERIFY);
}

/**
 * @brief Imports an AES-128-GCM key derived from Ksess.
 *
 * This helper imports the first 16 bytes of @p ksess as an AES-128 key and
 * configures it for AES-GCM encryption/decryption.
 *
 * The returned key handle must be destroyed by the caller when no longer
 * needed (psa_destroy_key()).
 *
 * @param ksess 32-byte session key material; only the first 16 bytes are used.
 *
 * @return A valid PSA key handle on success; aborts via fail() on error.
 */

static psa_key_handle_t import_aes128_gcm_key_from_ksess(const uint8_t ksess[32])
{
    psa_key_handle_t h = 0;
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;

    psa_set_key_type(&attr, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attr, 128);
    psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_DECRYPT | PSA_KEY_USAGE_ENCRYPT);
    psa_set_key_algorithm(&attr, PSA_ALG_GCM);

    psa_status_t st = psa_import_key(&attr, ksess, 16, &h); /* use first 16 bytes */
    psa_reset_key_attributes(&attr);

    if (st != PSA_SUCCESS || h == 0) fail(ERR_AES_IMPORT);
    return h;
}

/* =============================== ATTESTATION TOKEN =============================== */

/**
 * @brief Builds an attestation token bound to the given challenge hash.
 *
 * This helper queries the required token size using
 * psa_initial_attest_get_token_size(), verifies that @p token_buf is large
 * enough, then obtains the token using psa_initial_attest_get_token().
 *
 * The token is bound to the provided @p chal (HASH_LEN bytes).
 *
 * @param chal          Challenge hash to embed/bind into the attestation token.
 * @param[out] token_buf Output buffer that will receive the token bytes.
 * @param token_buf_cap Capacity of @p token_buf in bytes.
 * @param[out] token_len Receives the actual token length in bytes.
 */
static void build_attestation_token(const uint8_t chal[HASH_LEN],
                                    uint8_t *token_buf, size_t token_buf_cap,
                                    size_t *token_len)
{
    size_t token_size = 0;
    psa_status_t st = psa_initial_attest_get_token_size(HASH_LEN, &token_size);
    psa_check(st, ERR_TOKEN_SIZE);

    if (token_size > token_buf_cap) fail(ERR_TOKEN_BUF_SMALL);

    size_t actual = 0;
    st = psa_initial_attest_get_token(chal, HASH_LEN, token_buf, token_buf_cap, &actual);
    if (st != PSA_SUCCESS || actual == 0 || actual > token_buf_cap) fail(ERR_TOKEN_GET);

    *token_len = actual;
}


//* ------------------------ ESTRAZIONE TOKEN -------------------


int cose_sign1_extract_payload_only(UsefulBufC cose,
                                   UsefulBufC *payload_out)
{
    QCBORDecodeContext dc;
    QCBORItem item;

    *payload_out = NULLUsefulBufC;

    QCBORDecode_Init(&dc, cose, QCBOR_DECODE_MODE_NORMAL);

    // COSE_Sign1 è un array CBOR di 4 elementi
    QCBORDecode_EnterArray(&dc, NULL);

    // 0: protected (bstr)
    QCBORDecode_GetNext(&dc, &item);
    // 1: unprotected (map)
    QCBORDecode_GetNext(&dc, &item);
    // 2: payload (bstr o null)
    QCBORDecode_GetNext(&dc, &item);

    if (QCBORDecode_GetError(&dc) != QCBOR_SUCCESS) {
        return -1;
    }
    if (item.uDataType != QCBOR_TYPE_BYTE_STRING) {
        return -2;
    }

    payload_out->ptr = item.val.string.ptr;
    payload_out->len = item.val.string.len;

    QCBORDecode_ExitArray(&dc);
    if (QCBORDecode_Finish(&dc) != QCBOR_SUCCESS) {
        return -3;
    }
    return 0;
}

//* ------------------------ ESTRAZIONE MEASB -------------------

static int extract_measB_second_from_payload(UsefulBufC payload,
                                             const uint8_t **measB,
                                             size_t *measB_len)
{
    QCBORDecodeContext dc;
    QCBORItem it;

    *measB = NULL;
    *measB_len = 0;

    QCBORDecode_Init(&dc, payload, QCBOR_DECODE_MODE_NORMAL);

    
    QCBORDecode_EnterMap(&dc, NULL);

    int in_sw = 0;
    uint8_t sw_nesting = 0;
    int meas_count = 0;

    while (1) {
        QCBORDecode_GetNext(&dc, &it);

        if (it.uDataType == QCBOR_TYPE_NONE) {
            break;
        }
        if (QCBORDecode_GetError(&dc) != QCBOR_SUCCESS) {
            QCBORDecode_ExitMap(&dc);
            return -1;
        }

        
        if (!in_sw &&
            it.uLabelType == QCBOR_TYPE_INT64 &&
            it.label.int64 == IAT_SW_COMPONENTS_LEGACY &&
            it.uDataType == QCBOR_TYPE_ARRAY) {

            in_sw = 1;
            sw_nesting = it.uNestingLevel; 
            continue;
        }


        if (in_sw) {

            if (it.uNestingLevel <= sw_nesting) {
                in_sw = 0;
                continue;
            }

            if (it.uLabelType == QCBOR_TYPE_INT64 &&
                it.label.int64 == IAT_MEAS_VALUE &&
                it.uDataType == QCBOR_TYPE_BYTE_STRING) {

                meas_count++;
                if (meas_count == 2) { 
                    *measB = it.val.string.ptr;
                    *measB_len = it.val.string.len;

                    QCBORDecode_ExitMap(&dc);
                    if (QCBORDecode_Finish(&dc) != QCBOR_SUCCESS) {
                        return -2;
                    }
                    return 0;
                }
            }
        }
    }

    QCBORDecode_ExitMap(&dc);
    if (QCBORDecode_Finish(&dc) != QCBOR_SUCCESS) {
        return -3;
    }

    return -4; 
}

/* =============================== MAIN =============================== */

int main(void)
{
    tfm_ns_platform_init();

    if (driver_usart0.Initialize(NULL) != ARM_DRIVER_OK) fail(ERR_UART_INIT);
    if (driver_usart0.PowerControl(ARM_POWER_FULL) != ARM_DRIVER_OK) fail(ERR_UART_POWER);
    if (driver_usart0.Control(ARM_USART_CONTROL_TX, 1) != ARM_DRIVER_OK) fail(ERR_UART_CTRL_TX);
    if (driver_usart0.Control(ARM_USART_CONTROL_RX, 1) != ARM_DRIVER_OK) fail(ERR_UART_CTRL_RX);

    uint8_t line[16];

    //* Ver --> READY --> Att
    if (uart_read_line(line, sizeof(line)) != 0) fail(ERR_SYNC_RX_LINE);
    if (strcmp((char *)line, "READY\n") != 0) fail(ERR_SYNC_BAD_READY);

    /* RX: nonce (32) + KpuV (65) */
    uint8_t nonce[NONCE_LEN];
    uint8_t kpuV[PUB_UNCOMP_LEN];

    //* Ver --> nonce --> Att
    if (uart_receive_exact(nonce, sizeof(nonce)) != 0) fail(ERR_RX_NONCE);

    //* Ver --> KpuV --> Att
    if (uart_receive_exact(kpuV, sizeof(kpuV)) != 0) fail(ERR_RX_KPUV);

    //* Ver --> E_Kpr(H(Nonce || KpuV)) --> Att
    //Received Sign
    uint16_t sig_len_net;
    if (uart_receive_exact((uint8_t*)&sig_len_net, 2) != 0) fail(ERR_RX_SIG_LEN);
    uint16_t sig_len = ntohs(sig_len_net);

    uint8_t signature[128]; 
    if (sig_len > sizeof(signature)) fail(ERR_SIG_TOO_LARGE);
    if (uart_receive_exact(signature, sig_len) != 0) fail(ERR_RX_SIG);

    // 2. Import VerifV
    psa_key_attributes_t v_attr = PSA_KEY_ATTRIBUTES_INIT;
    psa_key_id_t Verif_V_id;
    psa_status_t status;

    psa_set_key_type(&v_attr, PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&v_attr, 256);
    psa_set_key_algorithm(&v_attr, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
    psa_set_key_usage_flags(&v_attr, PSA_KEY_USAGE_VERIFY_HASH);

    status = psa_import_key(&v_attr,
                            Verif_V,
                            sizeof(Verif_V),
                            &Verif_V_id);

    if (status != PSA_SUCCESS) {
        return -1;
    }

    // 3. verify Hash (Nonce || KpuV)
    uint8_t local_hash[32];
    size_t hash_out_len;
    uint8_t local_data[NONCE_LEN + PUB_UNCOMP_LEN];
    memcpy(local_data, nonce, NONCE_LEN);
    memcpy(local_data + NONCE_LEN, kpuV, PUB_UNCOMP_LEN);

    status = psa_hash_compute(PSA_ALG_SHA_256, 
                            local_data, sizeof(local_data), 
                            local_hash, sizeof(local_hash), &hash_out_len);
    if (status != PSA_SUCCESS) fail_psa(ERR_HASH_FAILED, status);

    // 4. Verify sign
    status = psa_verify_hash(Verif_V_id, 
                            PSA_ALG_ECDSA(PSA_ALG_SHA_256), 
                            local_hash, sizeof(local_hash), 
                            signature, sig_len);

    if (status != PSA_SUCCESS) {
        psa_destroy_key(Verif_V_id);
        fail_psa(ERR_AUTH_V_FAILED, status);
    }

    psa_destroy_key(Verif_V_id);

    //* Generate KpuA
    uint8_t kpuA[PUB_UNCOMP_LEN];
    generate_ephemeral_keypair_and_pub(kpuA);

    /* chal = SHA256(nonce||KpuV||KpuA) */
    //* Calculate CHAL
    uint8_t chal[HASH_LEN];
    sha256_n_kv_ka(nonce, kpuV, kpuA, chal);

    /* Token PSA received */
    uint8_t token[TOKEN_BUF_LEN];
    size_t token_len = 0;

    //* Att --> challp --> H
    //* H -- SignH(challP,measB) --> Att 
    build_attestation_token(chal, token, sizeof(token), &token_len);


    // Extract MeasB
    //* Att --> MeasB --> Ver
    UsefulBufC payload;
    if (cose_sign1_extract_payload_only((UsefulBufC){token, token_len}, &payload) != 0) {
        fail(ERR_PARSE_TOKEN3);
    }

    const uint8_t *measB = NULL;
    size_t measB_len = 0;

    int rc = extract_measB_second_from_payload(payload, &measB, &measB_len);
    if (rc != 0) { fail(ERR_PARSE_TOKEN1); }

    if (measB_len != 32) { fail(ERR_PARSE_TOKEN2); }

    // Send MeasB
    if (uart_send_hex_line(measB, measB_len) != 0) {
        fail(ERR_TX_MEASB);
    }


    /* TX: token hex line and KpuA hex line */
    //* Att --> Token || KpuA --> Ver
    if (uart_send_hex_line(token, token_len) != 0) fail(ERR_TX_TOKEN);
    if (uart_send_hex_line(kpuA, PUB_UNCOMP_LEN) != 0) fail(ERR_TX_KPUA);

    /* ECDH: Z = ECDH(KprA, KpuV) */
    uint8_t z[ECDH_MAX];
    size_t zlen = 0;
    ecdh_agree(kpuV, z, sizeof(z), &zlen);

    /* Ksess */
    uint8_t ksess[HASH_LEN];
    derive_ksess(z, zlen, chal, ksess);

    /* HMAC key from Ksess */
    psa_key_handle_t hmac_key = import_hmac_key_ksess(ksess);

    /* RX: MAC_V (32) */
    uint8_t macV_rx[HMAC_LEN];

    //* Att <-- MAC_V <-- Ver
    if (uart_receive_exact(macV_rx, sizeof(macV_rx)) != 0) fail(ERR_RX_MACV);

    /* Verify MAC_V */
    uint8_t macV_exp[HMAC_LEN];
    hmac_label_chal(hmac_key, (uint8_t)'V', chal, macV_exp);
    if (memcmp(macV_rx, macV_exp, HMAC_LEN) != 0) fail(ERR_HMAC_VERIFY);

    /* TX: MAC_A */
    uint8_t macA[HMAC_LEN];
    hmac_label_chal(hmac_key, (uint8_t)'A', chal, macA);

    //* Att --> MAC_A --> Ver
    if (uart_send_exact(macA, sizeof(macA)) != 0) fail(ERR_TX_MACA);

        /* RX: IV (12) + CT (16) + TAG (16)  [AES-256-GCM] */
    uint8_t iv[IV_LEN];
    uint8_t ct[16];
    uint8_t tag[TAG_LEN];

    /* RX: label + HEX line (IV/CT/TAG) */
    uint8_t line_lbl[32];
    size_t got = 0;

    //* Att <-- IV_V <-- Ver
    if(uart_read_line(line_lbl, sizeof(line_lbl)) != 0) fail(ERR_RX_IV);     /* "IV:\n" */
    if(uart_read_hex_line(iv, sizeof(iv), &got) != 0 || got != IV_LEN) fail(ERR_RX_IV);

    //* Att <-- CT_V <-- Ver
    if(uart_read_line(line_lbl, sizeof(line_lbl)) != 0) fail(ERR_RX_CT);     /* "CT:\n" */
    if(uart_read_hex_line(ct, sizeof(ct), &got) != 0 || got != sizeof(ct)) fail(ERR_RX_CT);
    
    //* Att <-- TAG_V <-- Ver
    if(uart_read_line(line_lbl, sizeof(line_lbl)) != 0) fail(ERR_RX_CT);     /* "TAG:\n" */
    if(uart_read_hex_line(tag, sizeof(tag), &got) != 0 || got != TAG_LEN) fail(ERR_RX_CT);

    //Debug
    uart_send_str("IV:\n");  if(uart_send_hex_line(iv, sizeof(iv)) != 0) fail(ERR_TX_ECHO);
    uart_send_str("CT:\n");  if(uart_send_hex_line(ct, sizeof(ct)) != 0) fail(ERR_TX_ECHO);
    uart_send_str("TAG:\n"); if(uart_send_hex_line(tag, sizeof(tag)) != 0) fail(ERR_TX_ECHO);


    /* DEBUG: invio Ksess (32B) al verifier (come già fai tu) */
    uart_send_str("KSESS:\n");
    if(uart_send_hex_line(ksess, sizeof(ksess)) != 0) fail(ERR_TX_KSESS);

    /* AES-GCM key import */
   psa_key_handle_t aes_key = import_aes128_gcm_key_from_ksess(ksess);

    uint8_t in[sizeof(ct) + sizeof(tag)];
    memcpy(in, ct, sizeof(ct));
    memcpy(in + sizeof(ct), tag, sizeof(tag));

    uint8_t pt[16];
    size_t pt_len = 0;

    // decipher CT_V
    psa_status_t st = psa_aead_decrypt(aes_key,
                                    PSA_ALG_GCM,
                                    iv, sizeof(iv),
                                    NULL, 0,
                                    in, sizeof(in),
                                    pt, sizeof(pt), &pt_len);

    if (st != PSA_SUCCESS || pt_len != sizeof(pt)) {
        fail_psa(ERR_AES_DECRYPT, st);
    }

    //Debug
    uart_send_str("PT:");
    if (uart_send_hex_line(pt, pt_len) != 0) fail(ERR_TX_ECHO);

    /* ===== DEMO: cifra e invia risposta "Ricevuto" con la stessa chiave AES-GCM ===== */
    const uint8_t *reply = (const uint8_t*)"Ricevuto";
    size_t reply_len = strlen((const char*)reply);  /* 8 */

    uint8_t IV_A[IV_LEN];
    psa_status_t st2 = psa_generate_random(IV_A, sizeof(IV_A));
    if (st2 != PSA_SUCCESS) fail_psa(ERR_AES_ENCRYPT, st2);

    /* CT(reply_len) + TAG(16) */
    uint8_t out2[8 + TAG_LEN];  
    size_t out2_len = 0;

    st2 = psa_aead_encrypt(aes_key,
                        PSA_ALG_GCM,
                        IV_A, sizeof(IV_A),
                        NULL, 0,              /* AAD none */
                        reply, reply_len,     /* <-- USA reply_len */
                        out2, sizeof(out2), &out2_len);

    if (st2 != PSA_SUCCESS || out2_len != (reply_len + TAG_LEN)) {
        fail_psa(ERR_AES_ENCRYPT, st2);
    }

    //* Att --> IV_A --> Ver
    uart_send_str("IV_A:\n");
    if(uart_send_hex_line(IV_A, sizeof(IV_A)) != 0) fail(ERR_TX_REPLY);

    //* Att --> CT_A --> Ver
    uart_send_str("CT_A:\n");
    if(uart_send_hex_line(out2, reply_len) != 0) fail(ERR_TX_REPLY);

    //* Att --> TAG_A --> Ver
    uart_send_str("TAG_A:\n");
    if(uart_send_hex_line(out2 + reply_len, TAG_LEN) != 0) fail(ERR_TX_REPLY);

    (void)psa_destroy_key(aes_key);
    (void)psa_destroy_key(hmac_key);
    (void)psa_destroy_key(g_eph_key);

    while (1) { __NOP();}
}       


