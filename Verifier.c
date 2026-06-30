//! 09/03/26 17:50

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

#include "qcbor/qcbor_spiffy_decode.h"
#include "qcbor/qcbor_decode.h"
#include "t_cose/t_cose_sign1_verify.h"
#include "t_cose/q_useful_buf.h"

#define OPENSSL_SUPPRESS_DEPRECATED
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/hmac.h>
#include <openssl/crypto.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/ecdsa.h>

#define NONCE_LEN       32
#define PUB_UNCOMP_LEN  65
#define HASH_LEN        32
#define HMAC_LEN        32
#define ECDH_MAX        128
#define IV_LEN          12
#define TAG_LEN         16

#define IAT_CHALLENGE_LEGACY      (-75008)
#define IAT_SW_COMPONENTS_LEGACY  (-75006)
#define IAT_MEAS_VALUE             2

/* ---- Serial timeouts ---- */
#define SERIAL_READLINE_TIMEOUT_MS  4000u   
#define SERIAL_READ_POLL_SLEEP_MS   1u      
#define SERIAL_READ_EXACT_TIMEOUT_MS  2000u

static uint8_t PSA_PUB_LOADED[PUB_UNCOMP_LEN];
static int g_manifest_ok = 0;

// Signing Private Key - It is possible to insert in the manifest

static const char SignV[] =
"-----BEGIN PRIVATE KEY-----\n"
"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg4yPMMmbIVTFPqK8U\n"
"Q+/uKMwcrgNaplduh/U13dK2PR6hRANCAASElww2Nr7owxne3kWG+frBXgh3wwCS\n"
"VOb9xiCZFyU8k0/STtIoIelT0/RwLg2wQThHH1GRmk59jduwYju1vXio\n"
"-----END PRIVATE KEY-----\n";

//* ================================================================== 
//*                              ERRORS
//* ==================================================================         

/**
 * @brief Prints a fatal error message to stderr and terminates the program.
 *
 * This helper is used for unrecoverable errors: it writes the provided message
 * to the standard error stream and immediately exits the process with a non-zero
 * status code.
 *
 * @param m Null-terminated string containing the error message to print.
 */
static void die(const char *m){ fprintf(stderr,"%s\n", m); exit(1); }

//* ================================================================== 
//*                              HEX/DUMPS
//* ================================================================== 

/**
 * @brief Converts a single hexadecimal character to its numeric value.
 *
 * This helper function takes an ASCII character representing a hexadecimal
 * digit ('0'–'9', 'a'–'f', or 'A'–'F') and returns the corresponding integer
 * value in the range 0–15. If the input character is not a valid hexadecimal
 * digit, the function returns -1 to signal an error.
 *
 * @param c ASCII character to convert.
 * @return Integer value of the hexadecimal digit (0–15), or -1 if invalid.
 */
static int hexn(int c){
    if(c>='0'&&c<='9') return c-'0';
    if(c>='a'&&c<='f') return 10+(c-'a');
    if(c>='A'&&c<='F') return 10+(c-'A');
    return -1;
}

/**
 * @brief Converts a hexadecimal string into a binary byte array.
 *
 * This helper function decodes an ASCII hexadecimal string into its raw
 * binary representation. The input length must be even (two hex characters
 * per byte), and the output buffer must be large enough to hold the result.
 * If any invalid hexadecimal character is encountered or a size check fails,
 * the function returns -1 to signal an error.
 *
 * @param hex     Pointer to the input hexadecimal string (not null-terminated).
 * @param hexlen  Length of the hexadecimal string in characters.
 * @param out     Output buffer where decoded bytes will be written.
 * @param outcap  Capacity of the output buffer in bytes.
 *
 * @return Number of bytes written to the output buffer on success,
 *         or -1 on error (invalid input or insufficient output capacity).
 */
static int hex2bin_str(const char *hex, size_t hexlen, uint8_t *out, size_t outcap){
    if(hexlen%2) return -1;
    size_t outlen = hexlen/2;
    if(outlen > outcap) return -1;
    for(size_t i=0;i<outlen;i++){
        int hi = hexn((unsigned char)hex[2*i]);
        int lo = hexn((unsigned char)hex[2*i+1]);
        if(hi<0||lo<0) return -1;
        out[i] = (uint8_t)((hi<<4)|lo);
    }
    return (int)outlen;
}

/**
 * @brief Prints a hexadecimal dump of a byte buffer to stdout.
 *
 * This helper function formats and prints the contents of a binary buffer
 * in hexadecimal form, prefixed by a label string. If @p per_line is zero,
 * the output is printed on a single line. Otherwise, the function breaks
 * the output into multiple lines, printing @p per_line bytes per line.
 *
 * @param lab       Null-terminated label string printed before the dump.
 * @param b         Pointer to the byte buffer to be printed.
 * @param n         Number of bytes in the buffer.
 * @param per_line  Number of bytes per output line, or 0 to print all bytes
 *                  on a single line.
 */
static void hexdump(const char *lab, const uint8_t *b, size_t n, size_t per_line){
    if(per_line == 0){
        printf("%s", lab);
        for(size_t i=0;i<n;i++) printf("%02X", b[i]);
        printf("\n");
        return;
    }
    printf("%s (%zu bytes):\n", lab, n);
    for(size_t i=0;i<n;i++){
        printf("%02X", b[i]);
        if(((i+1)%per_line)==0 || (i+1)==n) printf("\n");
    }
}

//* ================================================================== 
//*                              MANIFEST
//* ================================================================== 

/**
 * @brief Trims leading and trailing whitespace from a string in place.
 *
 * This helper removes whitespace characters from both the beginning and
 * the end of the given null-terminated string. The operation is performed
 * in place by shifting the contents of the string as needed.
 *
 * @param s Null-terminated string to be trimmed. The string is modified
 *          directly; its contents are shifted and possibly shortened.
 */

static void trim(char *s){
    /* trim left */
    char *p = s;
    while(*p==' ' || *p=='\t') p++;
    if(p != s) memmove(s, p, strlen(p) + 1);

    /* trim right */
    size_t n = strlen(s);
    while(n && (s[n-1]==' ' || s[n-1]=='\t' || s[n-1]=='\r' || s[n-1]=='\n'))
        s[--n] = 0;
}


/**
 * @brief Parses a hexadecimal string from the manifest into a binary buffer.
 *
 * Decodes a hex-encoded string value associated with a given
 * manifest key and writes the resulting bytes into the provided output buffer.
 * An optional "0x" or "0X" prefix in the input string is automatically skipped.
 *
 * The function validates that the input string has exactly the expected length
 * (two hex characters per output byte) and reports descriptive errors if the
 * length or decoding is invalid.
 *
 * @param key         Null-terminated string containing the manifest key name.
 *                    Used only for error reporting.
 * @param val         Null-terminated string containing the hex-encoded value.
 *                    May optionally start with "0x" or "0X".
 * @param want_bytes  Expected number of decoded bytes.
 * @param out         Output buffer where the decoded bytes will be stored.
 *                    Must have capacity for at least want_bytes bytes.
 *
 * @return 0 on success, or -1 on error (invalid length or decode failure).
 */

static int parse_manifest_hex(const char *key, const char *val,
                              size_t want_bytes, uint8_t *out){
    size_t len = strlen(val);
    if(len >= 2 && val[0] == '0' && (val[1] == 'x' || val[1] == 'X')) {
        val += 2;
        len -= 2;
    }

    if(len != want_bytes * 2){
        printf("Errore manifest: %s deve essere %zu caratteri hex (%zu byte)\n",
               key, want_bytes * 2, want_bytes);
        return -1;
    }

    if(hex2bin_str(val, len, out, want_bytes) != (int)want_bytes){
        printf("Errore manifest: decode %s fallito\n", key);
        return -1;
    }

    return 0;
}


/**
 * @brief Loads and parses a manifest file containing hex-encoded parameters.
 *
 * This function opens the specified manifest file and parses it line by line.
 * Each non-empty, non-comment line is expected to be in the form:
 *
 *     KEY = VALUE
 *
 * where VALUE is a hex-encoded string (optionally prefixed with "0x").
 * 
 * For each recognized key, the value is decoded from hex into the appropriate
 * global buffer. The function validates:
 *   - the exact length of each value,
 *   - successful hex decoding,
 *   - for PSA_PUB, that the first byte is 0x04 (uncompressed EC point format).
 *
 * Lines that are empty, start with '#', lack an '=', or contain empty keys or
 * values are silently ignored.
 *
 *
 * @param path Null-terminated string containing the filesystem path to the
 *             manifest file.
 *
 * @return 0 on success, or -1 on error (file open failure, parse error,
 *         missing required keys, or invalid values).
 */

static int load_manifest(const char *path){
    FILE *f = fopen(path, "rb");
    if(!f){
        printf("Errore: impossibile aprire manifest '%s'\n", path);
        return -1;
    }

    char line[512];
    int got_pub = 0;

    while(fgets(line, sizeof(line), f)){
        trim(line);
        if(line[0] == 0 || line[0] == '#') continue;

        char *eq = strchr(line, '=');
        if(!eq) continue;
        *eq = 0;

        char *k = line;
        char *v = eq + 1;
        trim(k);
        trim(v);
        if(k[0] == 0 || v[0] == 0) continue;

        if(strcmp(k, "PSA_PUB") == 0){
            if(parse_manifest_hex("PSA_PUB", v, PUB_UNCOMP_LEN, PSA_PUB_LOADED) != 0){
                fclose(f);
                return -1;
            }
            if(PSA_PUB_LOADED[0] != 0x04){
                printf("Errore manifest: PSA_PUB non è un punto EC uncompressed (byte0 != 0x04)\n");
                fclose(f);
                return -1;
            }
            got_pub = 1;
        }
    }

    fclose(f);

    if(!got_pub){
        printf("Errore manifest: manca PSA_PUB\n");
        return -1;
    }

    g_manifest_ok = 1;
    printf("Manifest caricato: PSA_PUB OK\n");
    return 0;
}



//* ================================================================== 
//*                             OPENSSL KEYS
//* ================================================================== 

/**
 * @brief Creates an OpenSSL EVP_PKEY from a raw uncompressed EC public key.
 *
 * This helper builds an OpenSSL EVP_PKEY structure from a raw elliptic-curve
 * public key encoded in uncompressed point format. The curve used is
 * prime256v1 (also known as NIST P-256).
 *
 * The function performs the following steps:
 *   - Allocates a new EC_KEY for curve prime256v1.
 *   - Creates a new EC_POINT associated with the curve group.
 *   - Converts the raw octet string into an EC_POINT.
 *   - Sets the EC_POINT as the public key of the EC_KEY.
 *   - Wraps the EC_KEY into a newly allocated EVP_PKEY.
 *
 * On success, ownership of the EC_KEY is transferred to the EVP_PKEY object.
 * On failure, all intermediate resources are freed.
 *
 * @param raw    Pointer to the raw EC public key bytes (uncompressed format).
 *               The first byte is expected to be 0x04.
 * @param rawlen Length of the raw public key in bytes.
 *
 * @return Pointer to a newly allocated EVP_PKEY on success,
 *         or NULL on error.
 */

static EVP_PKEY *pub_from_raw(const uint8_t *raw, size_t rawlen){
    EVP_PKEY *p = NULL;
    EC_KEY *e = NULL;
    EC_POINT *pt = NULL;

    if(!(e = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1))) goto err;
    if(!(pt = EC_POINT_new(EC_KEY_get0_group(e)))) goto err;
    if(!EC_POINT_oct2point(EC_KEY_get0_group(e), pt, raw, rawlen, NULL)) goto err;
    if(!EC_KEY_set_public_key(e, pt)) goto err;
    if(!(p = EVP_PKEY_new())) goto err;
    if(!EVP_PKEY_assign_EC_KEY(p, e)) goto err;

    e = NULL;
    EC_POINT_free(pt);
    return p;

err:
    if(pt) EC_POINT_free(pt);
    if(e)  EC_KEY_free(e);
    if(p)  EVP_PKEY_free(p);
    return NULL;
}


/**
 * @brief Generates an EC P-256 keypair and exports the public key in uncompressed format.
 *
 * This helper generates a fresh elliptic-curve keypair on curve prime256v1
 * (NIST P-256) using OpenSSL high-level EVP APIs. The generated
 * public key is exported to the caller-provided buffer in uncompressed point
 * format (0x04 || X || Y) with length PUB_UNCOMP_LEN.
 *
 * The returned EVP_PKEY contains the full keypair (private + public). The caller
 * owns the returned object and must release it with EVP_PKEY_free() when done.
 *
 * @param[out] kpuV Buffer where the uncompressed public key will be written.
 *                  Must have capacity PUB_UNCOMP_LEN bytes.
 *
 * @return A newly allocated EVP_PKEY containing the generated keypair on success,
 *         or NULL on failure.
 */

static EVP_PKEY* gen_v_keypair_and_export(uint8_t kpuV[PUB_UNCOMP_LEN]){
    if(!kpuV) return NULL;

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if(!pctx) return NULL;

    if(EVP_PKEY_keygen_init(pctx) != 1) {
        EVP_PKEY_CTX_free(pctx);
        return NULL;
    }

    if(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) != 1) {
        EVP_PKEY_CTX_free(pctx);
        return NULL;
    }

    EVP_PKEY *pkey = NULL;
    if(EVP_PKEY_keygen(pctx, &pkey) != 1) {
        EVP_PKEY_CTX_free(pctx);
        return NULL;
    }
    EVP_PKEY_CTX_free(pctx);

    const EC_KEY *eck = EVP_PKEY_get0_EC_KEY(pkey);
    if(!eck) {
        EVP_PKEY_free(pkey);
        return NULL;
    }

    const EC_POINT *pt = EC_KEY_get0_public_key(eck);
    const EC_GROUP *grp = EC_KEY_get0_group(eck);
    if(!pt || !grp) {
        EVP_PKEY_free(pkey);
        return NULL;
    }

    size_t outlen = EC_POINT_point2oct(grp, pt, POINT_CONVERSION_UNCOMPRESSED,
                                       kpuV, PUB_UNCOMP_LEN, NULL);
    if(outlen != PUB_UNCOMP_LEN) {
        EVP_PKEY_free(pkey);
        return NULL;
    }

    return pkey;
}


/**
 * @brief Derives an ECDH shared secret using a local private key and a peer public key.
 *
 * This helper performs an ECDH key agreement using OpenSSL EVP APIs.
 * The peer public key is provided in raw uncompressed point format
 * (0x04 || X || Y) with length PUB_UNCOMP_LEN and is converted to an EVP_PKEY
 * via pub_from_raw().
 *
 * The derived shared secret (ECDH "Z" value) is written to the caller-provided
 * output buffer. The function first queries the required output length, checks
 * capacity, then performs the actual derivation.
 *
 * @param[in]  privV   Local private key (EVP_PKEY) used for ECDH.
 * @param[in]  kpuA    Peer public key bytes in uncompressed EC point format
 *                     (length PUB_UNCOMP_LEN).
 * @param[out] out     Output buffer where the derived secret will be written.
 * @param[in]  out_cap Capacity of the output buffer in bytes.
 * @param[out] out_len Receives the number of bytes written to @p out on success.
 *
 * @return 0 on success, or -1 on error (invalid peer key, OpenSSL failure, or
 *         insufficient output capacity).
 */

static int ecdh_derive(EVP_PKEY *privV, const uint8_t kpuA[PUB_UNCOMP_LEN],
                       uint8_t *out, size_t out_cap, size_t *out_len){
    int ret = -1;
    EVP_PKEY *peer = pub_from_raw(kpuA, PUB_UNCOMP_LEN);
    EVP_PKEY_CTX *ctx = NULL;
    size_t zlen = 0;

    if(!peer) goto done;

    ctx = EVP_PKEY_CTX_new(privV, NULL);
    if(!ctx) goto done;

    if(EVP_PKEY_derive_init(ctx) != 1) goto done;
    if(EVP_PKEY_derive_set_peer(ctx, peer) != 1) goto done;

    /* Query required shared-secret length */
    if(EVP_PKEY_derive(ctx, NULL, &zlen) != 1) goto done;
    if(zlen > out_cap) goto done;

    /* Derive the shared secret into out */
    if(EVP_PKEY_derive(ctx, out, &zlen) != 1) goto done;

    *out_len = zlen;
    ret = 0;

done:
    if(ctx)  EVP_PKEY_CTX_free(ctx);
    if(peer) EVP_PKEY_free(peer);
    return ret;
}


//* ================================================================== 
//*                              HASH / HMAC 
//* ================================================================== 


/**
 * @brief Computes SHA-256 over the concatenation of three input buffers.
 *
 * This helper calculates the SHA-256 digest of the byte sequence formed by
 * concatenating the three provided input buffers (a || b || c), using OpenSSL
 * EVP APIs. The resulting hash is written to the output buffer.
 *
 * The function validates that the final digest length matches HASH_LEN
 * (expected to be 32 bytes for SHA-256).
 *
 * @param[in]  a     Pointer to the first input buffer.
 * @param[in]  alen  Length of the first input buffer in bytes.
 * @param[in]  b     Pointer to the second input buffer.
 * @param[in]  blen  Length of the second input buffer in bytes.
 * @param[in]  c     Pointer to the third input buffer.
 * @param[in]  clen  Length of the third input buffer in bytes.
 * @param[out] out   Output buffer that will receive the SHA-256 digest.
 *                   Must have capacity for HASH_LEN bytes.
 *
 * @return 0 on success, or -1 on error (OpenSSL failure or unexpected
 *         digest length).
 */

static int sha256_multi_3(const uint8_t *a, size_t alen,
                          const uint8_t *b, size_t blen,
                          const uint8_t *c, size_t clen,
                          uint8_t out[HASH_LEN])
{
    int ok = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if(!ctx) return -1;

    if(EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) goto done;
    if(EVP_DigestUpdate(ctx, a, alen) != 1) goto done;
    if(EVP_DigestUpdate(ctx, b, blen) != 1) goto done;
    if(EVP_DigestUpdate(ctx, c, clen) != 1) goto done;

    unsigned int olen = 0;
    if(EVP_DigestFinal_ex(ctx, out, &olen) != 1) goto done;
    if(olen != HASH_LEN) goto done;

    ok = 1;

done:
    EVP_MD_CTX_free(ctx);
    return ok ? 0 : -1;
}


/**
 * @brief Computes SHA-256 over (nonce || kpuV || kpuA) and aborts on failure.
 *
 * This helper derives a SHA-256 hash over the concatenation of:
 *   - the verifier nonce,
 *   - the verifier public key (kpuV),
 *   - the attester public key (kpuA).
 *
 * It is a thin wrapper around sha256_multi_3() that enforces the expected
 * input lengths and treats any hashing failure as a fatal error by invoking
 * die().
 *
 * @param[in]  nonce Verifier nonce (length NONCE_LEN).
 * @param[in]  kpuV  Verifier public key in uncompressed EC format
 *                   (length PUB_UNCOMP_LEN).
 * @param[in]  kpuA  Attester public key in uncompressed EC format
 *                   (length PUB_UNCOMP_LEN).
 * @param[out] out   Output buffer that will receive the SHA-256 digest.
 *                   Must have capacity for HASH_LEN bytes.
 */

static void sha256_n_kv_ka(const uint8_t nonce[NONCE_LEN],
                           const uint8_t kpuV[PUB_UNCOMP_LEN],
                           const uint8_t kpuA[PUB_UNCOMP_LEN],
                           uint8_t out[HASH_LEN])
{
    if(sha256_multi_3(nonce, NONCE_LEN,
                      kpuV, PUB_UNCOMP_LEN,
                      kpuA, PUB_UNCOMP_LEN,
                      out) != 0){
        die("Errore: SHA256(nonce||kpuV||kpuA) fallita");
    }
}


/**
 * @brief Derives the session key ksess as SHA-256(Z || chal || "RA-KSESS").
 *
 * This helper computes the session key material by hashing the concatenation
 * of:
 *   - the ECDH shared secret Z,
 *   - the challenge hash chal,
 *   - a fixed ASCII context string "RA-KSESS".
 *
 * It is a thin wrapper around sha256_multi_3() and treats any hashing failure
 * as a fatal error by invoking die().
 *
 * The context string provides domain separation so that the same inputs are
 * not reused across different cryptographic purposes.
 *
 * @param[in]  z     Pointer to the ECDH shared secret buffer.
 * @param[in]  zlen  Length of the shared secret buffer in bytes.
 * @param[in]  chal  Challenge hash (length HASH_LEN).
 * @param[out] ksess Output buffer that will receive the derived session key.
 *                   Must have capacity for HASH_LEN bytes.
 */

static void derive_ksess(const uint8_t *z, size_t zlen,
                         const uint8_t chal[HASH_LEN],
                         uint8_t ksess[HASH_LEN])
{
    static const uint8_t info[] = "RA-KSESS";

    if(sha256_multi_3(z, zlen,
                      chal, HASH_LEN,
                      info, sizeof(info) - 1,
                      ksess) != 0){
        die("Errore: SHA256(Z||chal||info) fallita");
    }
}


/**
 * @brief Computes an HMAC-SHA256 over (label || chal) using the session key ksess.
 *
 * This helper builds a message consisting of a one-byte label followed by the
 * challenge hash and computes an HMAC-SHA256 over it using the provided session
 * key ksess. The result is written to the output buffer.
 *
 * The function treats any HMAC failure or unexpected output length as a fatal
 * error by invoking die().
 *
 * @param[in]  ksess      Session key used as the HMAC key (length HASH_LEN).
 * @param[in]  label_char Single-byte label prepended to the message. This is
 *                        used for domain separation between different HMACs.
 * @param[in]  chal       Challenge hash (length HASH_LEN).
 * @param[out] out        Output buffer that will receive the HMAC value.
 *                        Must have capacity for HMAC_LEN bytes.
 */
static void hmac_label_chal(const uint8_t ksess[HASH_LEN],
                            uint8_t label_char,
                            const uint8_t chal[HASH_LEN],
                            uint8_t out[HMAC_LEN])
{
    uint8_t msg[1 + HASH_LEN];
    msg[0] = label_char;
    memcpy(&msg[1], chal, HASH_LEN);

    unsigned int len = 0;
    unsigned char *res = HMAC(EVP_sha256(),
                              ksess, HASH_LEN,
                              msg, sizeof(msg),
                              out, &len);
    if(!res || len != HMAC_LEN){
        die("Errore: HMAC fallita");
    }
}


//* ================================================================== 
//*                              COSE VERIFY
//* ================================================================== 

/**
 * @brief Verifies a COSE_Sign1 token using the PSA public key from the manifest.
 *
 * This helper verifies the digital signature of a COSE_Sign1 token using the
 * public key (PSA_PUB) previously loaded from the manifest. The public key is
 * expected to be an uncompressed EC point on curve prime256v1 and is converted
 * into an OpenSSL EVP_PKEY via pub_from_raw().
 *
 * The function initializes a t_cose verification context, configures it to use
 * the OpenSSL crypto backend, and performs signature verification on the input
 * token. On success, the decoded payload is returned via @p out_payload.
 *
 * @param[in]  token       Pointer to the COSE_Sign1 token bytes.
 * @param[in]  tlen        Length of the token in bytes.
 * @param[out] out_payload Pointer to a UsefulBufC that will receive the decoded
 *                         payload on successful verification.
 *
 * @return 0 on success, or -1 on error (manifest not loaded, key conversion
 *         failure, or COSE signature verification failure).
 */

static int verify_cose(const uint8_t *token, size_t tlen, UsefulBufC *out_payload){
    if(!g_manifest_ok){
        printf("Errore: manifest non caricato\n");
        return -1;
    }

    EVP_PKEY *pub = pub_from_raw(PSA_PUB_LOADED, PUB_UNCOMP_LEN);
    if(!pub) return -1;

    struct t_cose_sign1_verify_ctx v;
    struct t_cose_key k = {
        .crypto_lib = T_COSE_CRYPTO_LIB_OPENSSL,
        .k.key_ptr  = pub
    };

    t_cose_sign1_verify_init(&v, 0);
    t_cose_sign1_set_verification_key(&v, k);

    enum t_cose_err_t rc =
        t_cose_sign1_verify(&v, (UsefulBufC){ token, tlen }, out_payload, NULL);

    EVP_PKEY_free(pub);

    if(rc != T_COSE_SUCCESS){
        printf("Firma COSE NON valida (err=%d)\n", rc);
        return -1;
    }

    printf("[V] FIRMA COSE VERIFICATA: OK\n");
    return 0;
}


//* ================================================================== 
//*                              CLAIMS PARSE
//* ================================================================== 

/**
 * @brief Parses selected claims from a CBOR/CCA token payload.
 *
 * This helper decodes a CBOR payload (as returned from a verified COSE_Sign1
 * token) and extracts:
 *   - the legacy challenge claim (IAT_CHALLENGE_LEGACY) as a byte string,
 *   - up to two software measurement values (IAT_MEAS_VALUE) found inside the
 *     legacy software components array (IAT_SW_COMPONENTS_LEGACY).
 *
 * The function is tolerant to common wrapping patterns in attestation tokens:
 *   - If the outermost item is a CBOR tag, it is skipped.
 *   - If the payload is a CBOR byte string containing embedded CBOR, it is
 *     treated as an encoded CBOR object and decoding restarts from the embedded
 *     bytes (optionally skipping an initial tag again).
 *
 * Returned pointers (@p chal, @p m1, @p m2) reference memory inside the input
 * @p payload buffer; they are valid only as long as the payload buffer remains
 * valid.
 *
 * @param[in]  payload   CBOR payload buffer to decode.
 * @param[out] chal      Receives a pointer to the challenge byte string, or NULL
 *                       if not found.
 * @param[out] chal_len  Receives the length of the challenge in bytes (0 if not found).
 * @param[out] m1        Receives a pointer to the first measurement byte string, or NULL.
 * @param[out] m1_len    Receives the length of the first measurement in bytes (0 if not found).
 * @param[out] m2        Receives a pointer to the second measurement byte string, or NULL.
 * @param[out] m2_len    Receives the length of the second measurement in bytes (0 if not found).
 *
 * @return 0 on success (CBOR decoded successfully), or -1 on error (decode failure).
 *
 * @note This function does not enforce that the extracted fields exist; it only
 *       extracts them if present. The caller should validate that @p chal and
 *       the expected measurements were found and have the required lengths.
 */

static int parse_claims(UsefulBufC payload,
                        const uint8_t **chal, size_t *chal_len,
                        const uint8_t **m1, size_t *m1_len,
                        const uint8_t **m2, size_t *m2_len)
{
    QCBORDecodeContext c;
    QCBORItem it, first;

    *chal = NULL; *chal_len = 0;
    *m1 = *m2 = NULL; *m1_len = *m2_len = 0;

    QCBORDecode_Init(&c, payload, QCBOR_DECODE_MODE_NORMAL);

    /* Skip an outer CBOR tag if present */
    if(QCBORDecode_PeekNext(&c, &first) != QCBOR_SUCCESS) return -1;
    if(first.uDataType == QCBOR_TYPE_TAG) QCBORDecode_GetNext(&c, &first);

    /* If the payload is a byte string containing embedded CBOR, unwrap it */
    if(QCBORDecode_PeekNext(&c, &first) == QCBOR_SUCCESS &&
       first.uDataType == QCBOR_TYPE_BYTE_STRING){
        QCBORDecode_GetNext(&c, &first);
        QCBORDecode_Init(&c, first.val.string, QCBOR_DECODE_MODE_NORMAL);

        if(QCBORDecode_PeekNext(&c, &first) == QCBOR_SUCCESS &&
           first.uDataType == QCBOR_TYPE_TAG)
            QCBORDecode_GetNext(&c, &first);
    }

    QCBORDecode_EnterMap(&c, NULL);
    int in_sw = 0;
    uint8_t sw_level = 0;

    while(QCBORDecode_GetNext(&c, &it) == QCBOR_SUCCESS){

        /* Enter legacy SW components array */
        if(it.uLabelType == QCBOR_TYPE_INT64 &&
           it.label.int64 == IAT_SW_COMPONENTS_LEGACY &&
           it.uDataType == QCBOR_TYPE_ARRAY){
            in_sw = 1;
            sw_level = it.uNestingLevel;
            continue;
        }

        /* Collect up to two measurement values within SW components */
        if(in_sw){
            if(it.uLabelType == QCBOR_TYPE_INT64 &&
               it.label.int64 == IAT_MEAS_VALUE &&
               it.uDataType == QCBOR_TYPE_BYTE_STRING){
                if(!*m1){ *m1 = it.val.string.ptr; *m1_len = it.val.string.len; }
                else if(!*m2){ *m2 = it.val.string.ptr; *m2_len = it.val.string.len; }
            }
            if(it.uNestingLevel <= sw_level) in_sw = 0;
        }

        /* Extract legacy challenge */
        if(it.uLabelType == QCBOR_TYPE_INT64 &&
           it.label.int64 == IAT_CHALLENGE_LEGACY &&
           it.uDataType == QCBOR_TYPE_BYTE_STRING){
            *chal = it.val.string.ptr;
            *chal_len = it.val.string.len;
        }
    }

    QCBORDecode_ExitMap(&c);

    return (QCBORDecode_Finish(&c) == QCBOR_SUCCESS) ? 0 : -1;
}


//* ================================================================== 
//*                              SERIAL I/O
//* ================================================================== 


/**
 * @brief Configures a Windows serial port handle with standard UART settings.
 *
 * This helper initializes and applies serial port parameters on an already
 * opened Windows COM port handle. The configuration applied is:
 *   - Baud rate: 115200 bps
 *   - Data bits: 8
 *   - Stop bits: 1
 *   - Parity:    none
 *
 * It also sets read timeouts to avoid indefinite blocking on serial reads,
 * using moderate timeout values suitable for line-based protocols.
 *
 * @param h Handle to an open serial port (as returned by CreateFile()).
 *
 * @return 0 on success, or -1 on error (failure to get or set port state or
 *         timeouts).
 */

static int serial_configure(HANDLE h){
    DCB dcb = {0};
    COMMTIMEOUTS to = {0};

    dcb.DCBlength = sizeof(dcb);
    if(!GetCommState(h, &dcb)) return -1;

    dcb.BaudRate = CBR_115200;
    dcb.ByteSize = 8;
    dcb.StopBits = ONESTOPBIT;
    dcb.Parity   = NOPARITY;
    if(!SetCommState(h, &dcb)) return -1;

    to.ReadIntervalTimeout = 50;
    to.ReadTotalTimeoutConstant = 200;
    to.ReadTotalTimeoutMultiplier = 10;
    if(!SetCommTimeouts(h, &to)) return -1;

    return 0;
}

/**
 * @brief Reads a newline-terminated line from a Windows serial port with a hard timeout.
 *
 * This helper reads bytes one-by-one from the serial port until either:
 *   - a newline character ('\n') is received, or
 *   - the output buffer is full (leaving space for the NUL terminator), or
 *   - the overall timeout expires.
 *
 * The function implements an application-level timeout using GetTickCount()
 * in addition to the COM port timeouts, and it performs a short sleep when
 * ReadFile returns 0 bytes (polling behavior).
 *
 * On success, the received data is NUL-terminated so it can be treated as a C
 * string (note that the newline character, if received, is included in the
 * buffer before the terminating NUL).
 *
 * @param h     Handle to an open serial port (CreateFile()).
 * @param[out] b Output buffer that will receive the line. The buffer is always
 *               NUL-terminated on success.
 * @param cap   Capacity of @p b in bytes. Must be >= 2 to store at least one
 *              character plus the NUL terminator.
 * @param[out] outn Optional pointer that receives the number of bytes read
 *                  (excluding the terminating NUL). May be NULL.
 *
 * @return 0 on success,
 *         -2 on timeout (no complete line received within SERIAL_READLINE_TIMEOUT_MS),
 *         -1 on I/O error (ReadFile failure).
 */

static int serial_read_line(HANDLE h, uint8_t *b, size_t cap, size_t *outn){
    size_t n = 0;
    DWORD r = 0;
    uint8_t c = 0;
    DWORD start = GetTickCount();

    while(n + 1 < cap){
        if((GetTickCount() - start) > SERIAL_READLINE_TIMEOUT_MS){
            return -2; /* timeout */
        }

        if(!ReadFile(h, &c, 1, &r, NULL)) return -1;
        if(!r){
            Sleep(SERIAL_READ_POLL_SLEEP_MS);
            continue;
        }

        b[n++] = c;
        if(c == '\n') break;
    }

    b[n] = 0;
    if(outn) *outn = n;
    return 0;
}

/**
 * @brief Reads an exact number of bytes from a Windows serial port.
 *
 * This helper reads bytes from the serial port until either:
 *   - exactly @p n bytes have been received, or
 *   - a ReadFile error occurs.
 *
 * The function loops until the requested number of bytes is collected.
 * If ReadFile returns 0 bytes, it performs a short sleep (polling behavior)
 * before retrying.
 *
 * Unlike serial_read_line(), this function does not look for any delimiter
 * and does not append a NUL terminator; it simply fills the provided buffer
 * with raw data.
 *
 * @param h     Handle to an open serial port (CreateFile()).
 * @param[out] buf Output buffer that will receive exactly @p n bytes.
 *                 Must be at least @p n bytes long.
 * @param n     Number of bytes to read.
 *
 * @return 0 on success (exactly @p n bytes read),
 *         -1 on I/O error (ReadFile failure).
 */
static int serial_read_exact(HANDLE h, uint8_t *buf, size_t n){
    size_t got = 0;
    DWORD start = GetTickCount();

    while(got < n){
        if((GetTickCount() - start) > SERIAL_READ_EXACT_TIMEOUT_MS){
            return -2; // timeout
        }

        DWORD r = 0;
        if(!ReadFile(h, buf + got, (DWORD)(n - got), &r, NULL)) return -1;
        if(r == 0){
            Sleep(SERIAL_READ_POLL_SLEEP_MS);
            continue;
        }
        got += (size_t)r;
    }
    return 0;
}

static int serial_read_mac_or_errline(HANDLE h, uint8_t mac[HMAC_LEN]){
    uint8_t hdr[4];

    int rc = serial_read_exact(h, hdr, 4);
    if(rc != 0) return rc; // -1 I/O, -2 timeout

    if(hdr[0]=='E' && hdr[1]=='R' && hdr[2]=='R' && hdr[3]==':'){
        // leggo il resto della riga errore
        uint8_t line[128];
        size_t ln = 0;
        int r2 = serial_read_line(h, line, sizeof(line), &ln); // legge fino a '\n'
        if(r2 == 0){
            // line contiene il resto dopo "ERR:"
            printf("[V] Attester ha risposto con ERRORE: ERR:%s", line);
        } else {
            printf("[V] Attester ha risposto con ERRORE: ERR:(impossibile leggere dettaglio)\n");
        }
        return -3; // protocol error
    }

    // non è ERR:, quindi i primi 4 byte sono parte del MAC
    memcpy(mac, hdr, 4);
    rc = serial_read_exact(h, mac + 4, HMAC_LEN - 4);
    return rc;
}

static void serial_drain_rx(HANDLE h, DWORD ms){
    DWORD start = GetTickCount();
    COMSTAT st;
    DWORD err;
    uint8_t tmp[256];

    while((GetTickCount() - start) < ms){
        ClearCommError(h, &err, &st);
        if(st.cbInQue == 0){
            Sleep(5);
            continue;
        }
        DWORD toRead = st.cbInQue > sizeof(tmp) ? (DWORD)sizeof(tmp) : st.cbInQue;
        DWORD rd = 0;
        ReadFile(h, tmp, toRead, &rd, NULL); // butto via
    }
}

/**
 * @brief Writes an exact number of bytes to a Windows serial port.
 *
 * This helper writes bytes to the serial port until either:
 *   - exactly @p n bytes have been transmitted, or
 *   - a WriteFile error occurs.
 *
 * The function loops until the requested number of bytes is sent.
 * If WriteFile reports that 0 bytes were written, it performs a short
 * sleep (polling behavior) before retrying.
 *
 * Unlike higher-level helpers, this function does not add any framing,
 * delimiters, or terminators; it simply sends the raw bytes contained
 * in the provided buffer.
 *
 * @param h     Handle to an open serial port (CreateFile()).
 * @param[in]  buf Input buffer containing the data to send.
 *                 Must be at least @p n bytes long.
 * @param n     Number of bytes to write.
 *
 * @return 0 on success (exactly @p n bytes written),
 *         -1 on I/O error (WriteFile failure).
 */
static int serial_write_exact(HANDLE h, const uint8_t *buf, size_t n){
    size_t sent=0;
    while(sent<n){
        DWORD w=0;
        if(!WriteFile(h, buf+sent, (DWORD)(n-sent), &w, NULL)) return -1;
        if(w==0){
            Sleep(SERIAL_READ_POLL_SLEEP_MS);
            continue;
        }
        sent += (size_t)w;
    }
    return 0;
}

/**
 * @brief Reads a line from the device, interprets it as hex data or an error, and converts it to binary.
 *
 * This helper reads a newline-terminated line from the serial port using
 * serial_read_line(), then processes it as follows:
 *   - Skips any leading NUL ('\0') or carriage return ('\r') characters.
 *   - If the line begins with "ERR:", it parses and prints the device error
 *     code (and optional status) and returns an error.
 *   - Verifies that the line is properly terminated with a newline ('\n').
 *   - Filters the line in-place to keep only hexadecimal characters,
 *     ignoring spaces, tabs, and carriage returns.
 *   - Converts the resulting hex string into binary form using hex2bin_str().
 *
 * The converted binary data is written into @p out_bin, up to @p out_cap
 * bytes. On success, the number of bytes produced is returned via @p out_len
 * (if non-NULL).
 *
 * Any protocol or format violation (missing newline, non-hex characters,
 * odd-length hex string, conversion failure) is reported to stdout and
 * results in an error return.
 *
 * @param h        Handle to an open serial port (CreateFile()).
 * @param[out] out_bin Output buffer that will receive the decoded binary data.
 *                     Must be at least @p out_cap bytes long.
 * @param out_cap  Capacity of @p out_bin in bytes.
 * @param[out] out_len Optional pointer that receives the number of bytes
 *                     written to @p out_bin. May be NULL.
 * @param what     Human-readable description of the expected content
 *                 (used only for error messages).
 *
 * @return 0 on success (hex line read and converted to binary),
 *         -2 if the device reported an "ERR:" line,
 *         -1 on I/O error, timeout, or format/parse error.
 */
static int read_device_hex_line_or_err(HANDLE h,
                                       uint8_t *out_bin, size_t out_cap, size_t *out_len,
                                       const char *what)
{
    uint8_t line[20000];
    size_t ln=0;

    int rc = serial_read_line(h, line, sizeof(line), &ln);
    if(rc != 0){
        if(rc == -2) printf("Errore: timeout lettura linea %s da device\n", what);
        else         printf("Errore lettura linea %s da device\n", what);
        return -1;
    }

    /* skip leading NUL/CR */
    size_t off=0;
    while(off<ln && (line[off]==0 || line[off]=='\r')) off++;

    uint8_t *p=line+off;
    size_t plen=ln-off;

    if(plen>=4 && !memcmp(p,"ERR:",4)){
        int code=0; long st=0;
        int n = sscanf((char*)p, "ERR:%d:%ld", &code, &st);
        if(n==2) printf("Device: ERR:%d:%ld\n", code, st);
        else     printf("Device: ERR:%d\n", code);
        return -2;
    }

    if(!plen || p[plen-1] != '\n'){
        printf("Errore: linea %s non terminata con newline\n", what);
        return -1;
    }
    plen--; /* drop '\n' */

    /* Filter to pure hex characters in-place (skip \r, spaces, tabs) */
    size_t w=0;
    for(size_t i=0;i<plen;i++){
        uint8_t c = p[i];
        if(c=='\r' || c==' ' || c=='\t') continue;
        if(hexn(c) < 0){
            printf("Errore: %s contiene carattere non-hex (0x%02X)\n", what, (unsigned)c);
            return -1;
        }
        p[w++] = c;
    }

    if(w==0 || (w%2)!=0){
        printf("Errore: %s hex vuoto o con lunghezza dispari\n", what);
        return -1;
    }

    int blen = hex2bin_str((const char*)p, w, out_bin, out_cap);
    if(blen <= 0){
        printf("Errore conversione %s hex->bin\n", what);
        return -1;
    }

    if(out_len) *out_len = (size_t)blen;
    return 0;
}


/**
 * @brief Writes a NUL-terminated C string to a Windows serial port.
 *
 * This helper sends the contents of the input string @p s to the serial
 * port using serial_write_exact(). The terminating NUL character is
 * not transmitted; only the visible characters in the string are written.
 *
 * The function does not append any line terminator (such as '\n' or '\r');
 * callers that need line-oriented output must include it explicitly in
 * the string.
 *
 * @param h   Handle to an open serial port (CreateFile()).
 * @param s   NUL-terminated input string to send.
 *
 * @return 0 on success (entire string written),
 *         -1 on I/O error (serial_write_exact() failure).
 */
static int serial_write_str(HANDLE h, const char *s){
    return serial_write_exact(h, (const uint8_t*)s, strlen(s));
}


/**
 * @brief Writes a binary buffer to a Windows serial port as a hex-encoded line.
 *
 * This helper converts each byte of the input buffer @p buf into two
 * uppercase hexadecimal characters and writes them sequentially to the
 * serial port using serial_write_exact(). After all bytes have been sent,
 * it appends a newline character ('\n') to terminate the line.
 *
 * The output format is therefore:
 *   - 2 * @p len ASCII hex characters (most significant nibble first),
 *   - followed by a single newline character.
 *
 * No spaces, carriage returns, or other delimiters are inserted between
 * bytes—only a continuous hex string plus the final newline.
 *
 * @param h    Handle to an open serial port (CreateFile()).
 * @param buf  Input buffer containing the binary data to send.
 * @param len  Number of bytes in @p buf to encode and write.
 *
 * @return 0 on success (all bytes and the terminating newline written),
 *         -1 on I/O error (any serial_write_exact() failure).
 */
static int serial_write_hex_line(HANDLE h, const uint8_t *buf, size_t len){
    static const char hx[] = "0123456789ABCDEF";
    for(size_t i=0;i<len;i++){
        char out[2];
        out[0] = hx[(buf[i] >> 4) & 0xF];
        out[1] = hx[(buf[i]     ) & 0xF];
        if(serial_write_exact(h, (const uint8_t*)out, 2)!=0) return -1;
    }
    return serial_write_exact(h, (const uint8_t*)"\n", 1);
}



//* ================================================================== 
//*                             AES-128-GCM
//* ================================================================== 


/**
 * @brief Encrypts plaintext using AES-128-GCM.
 *
 * This helper encrypts the input plaintext buffer @p pt using AES in GCM
 * mode with a 128-bit key. The caller must provide:
 *   - a 16-byte encryption key,
 *   - an initialization vector (IV) of length IV_LEN,
 *   - an output buffer large enough to hold the ciphertext,
 *   - a buffer to receive the authentication tag (TAG_LEN bytes).
 *
 * The function performs the following steps using the OpenSSL EVP API:
 *   - Initializes an AES-128-GCM cipher context.
 *   - Sets the IV length to IV_LEN.
 *   - Initializes the context with the provided key and IV.
 *   - Encrypts the plaintext into the ciphertext buffer.
 *   - Finalizes encryption and retrieves the GCM authentication tag.
 *
 * No additional authenticated data (AAD) is used.
 *
 * @param key     16-byte AES encryption key.
 * @param iv      Initialization vector of length IV_LEN.
 * @param pt      Input plaintext buffer.
 * @param pt_len  Length of the plaintext in bytes.
 * @param[out] ct Output buffer that will receive the ciphertext.
 *                Must be at least @p pt_len bytes long.
 * @param ct_cap  Capacity of @p ct in bytes.
 * @param[out] tag Output buffer that will receive the authentication tag.
 *                 Must be TAG_LEN bytes long.
 *
 * @return 0 on success (plaintext encrypted and tag produced),
 *         -1 on error (invalid buffer size, allocation failure,
 *             or any OpenSSL EVP call failure).
 */
static int aes128gcm_encrypt(const uint8_t key[16],
                             const uint8_t iv[IV_LEN],
                             const uint8_t *pt, size_t pt_len,
                             uint8_t *ct, size_t ct_cap,
                             uint8_t tag[TAG_LEN])
{
    if(ct_cap < pt_len) return -1;

    EVP_CIPHER_CTX *cctx = EVP_CIPHER_CTX_new();
    if(!cctx) return -1;

    int ok=0, outl=0;

    if(EVP_EncryptInit_ex(cctx, EVP_aes_128_gcm(), NULL, NULL, NULL) != 1) goto done;
    if(EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL) != 1) goto done;
    if(EVP_EncryptInit_ex(cctx, NULL, NULL, key, iv) != 1) goto done;

    if(EVP_EncryptUpdate(cctx, ct, &outl, pt, (int)pt_len) != 1) goto done;
    if((size_t)outl != pt_len) goto done;

    if(EVP_EncryptFinal_ex(cctx, ct+outl, &outl) != 1) goto done;
    if(EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag) != 1) goto done;

    ok=1;
done:
    EVP_CIPHER_CTX_free(cctx);
    return ok ? 0 : -1;
}

/**
 * @brief Decrypts ciphertext using AES-128-GCM and verifies its authentication tag.
 *
 * This helper decrypts the input ciphertext buffer @p ct using AES in GCM
 * mode with a 128-bit key. The caller must provide:
 *   - a 16-byte decryption key,
 *   - an initialization vector (IV) of length IV_LEN,
 *   - a buffer containing the authentication tag (TAG_LEN bytes),
 *   - an output buffer large enough to hold the plaintext.
 *
 * The function performs the following steps using the OpenSSL EVP API:
 *   - Initializes an AES-128-GCM cipher context.
 *   - Sets the IV length to IV_LEN.
 *   - Initializes the context with the provided key and IV.
 *   - Decrypts the ciphertext into the plaintext buffer.
 *   - Sets the expected GCM authentication tag.
 *   - Finalizes decryption, which also verifies the tag.
 *
 * No additional authenticated data (AAD) is used.
 *
 * If the authentication tag does not match, EVP_DecryptFinal_ex() fails and
 * the function returns an error without producing valid plaintext.
 *
 * @param key     16-byte AES decryption key.
 * @param iv      Initialization vector of length IV_LEN.
 * @param ct      Input ciphertext buffer.
 * @param ct_len  Length of the ciphertext in bytes.
 * @param tag     Authentication tag buffer (TAG_LEN bytes).
 * @param[out] pt Output buffer that will receive the decrypted plaintext.
 *                Must be at least @p ct_len bytes long.
 * @param pt_cap  Capacity of @p pt in bytes.
 *
 * @return 0 on success (ciphertext decrypted and tag verified),
 *         -1 on error (invalid buffer size, allocation failure,
 *             authentication failure, or any OpenSSL EVP call failure).
 */
static int aes128gcm_decrypt(const uint8_t key[16],
                             const uint8_t iv[IV_LEN],
                             const uint8_t *ct, size_t ct_len,
                             const uint8_t tag[TAG_LEN],
                             uint8_t *pt, size_t pt_cap)
{
    if (pt_cap < ct_len) return -1;

    EVP_CIPHER_CTX *cctx = EVP_CIPHER_CTX_new();
    if (!cctx) return -1;

    int ok = 0;
    int outl = 0;

    if (EVP_DecryptInit_ex(cctx, EVP_aes_128_gcm(), NULL, NULL, NULL) != 1) goto done;
    if (EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL) != 1) goto done;
    if (EVP_DecryptInit_ex(cctx, NULL, NULL, key, iv) != 1) goto done;

    if (EVP_DecryptUpdate(cctx, pt, &outl, ct, (int)ct_len) != 1) goto done;
    if ((size_t)outl != ct_len) goto done;

    if (EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, (void *)tag) != 1) goto done;
    if (EVP_DecryptFinal_ex(cctx, pt + outl, &outl) != 1) goto done;

    ok = 1;
done:
    EVP_CIPHER_CTX_free(cctx);
    return ok ? 0 : -1;
}

static void print_hex(const char *label, const uint8_t *buf, size_t len)
{
    printf("%s (%zu bytes):\n", label, len);
    for (size_t i = 0; i < len; i++) {
        printf("%02X", buf[i]);
        if ((i + 1) % 32 == 0) printf("\n");  // a righe da 32 byte
    }
    if (len % 32 != 0) printf("\n");
}


//* ================================================================== 
//*                             MAIN
//* ================================================================== 

int main(void){
    HANDLE h = INVALID_HANDLE_VALUE;
    EVP_PKEY *kprV = NULL;
    int ret = 1;

    // Open port
    char port[20];
    printf("Inserisci porta COM (es. COM8): ");
    if(scanf("%19s", port) != 1) die("Input porta fallito");

    h = CreateFileA(port, GENERIC_READ|GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    if(h == INVALID_HANDLE_VALUE) die("Errore apertura porta COM");

    if(serial_configure(h)!=0) die("Errore configurazione porta COM");
    PurgeComm(h, PURGE_RXCLEAR | PURGE_TXCLEAR);
    serial_drain_rx(h, 200);

    // Load manifest.txt (PSA_PUB)
    if(load_manifest("manifest.txt")!=0){
        printf("Impossibile proseguire senza manifest valido.\n");
        goto cleanup;
    }

    hexdump("[M] PSA_PUB (from manifest)", PSA_PUB_LOADED, PUB_UNCOMP_LEN, 32);

    //* Ver --> READY --> Att
    printf("\n [V] STEP 0: invio READY \n \n");
    if(serial_write_exact(h, (const uint8_t*)"READY\n", 6)!=0) die("Errore invio READY");

    
    printf("\n [V] STEP 1: genero NONCE e KpuV\n");
    uint8_t nonce[NONCE_LEN];

    // Generation Nonce
    if(BCryptGenRandom(NULL, nonce, sizeof(nonce), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0){
        printf("Errore: BCryptGenRandom fallita\n");
        goto cleanup;
    }
    hexdump("[V] NONCE: ", nonce, NONCE_LEN, 0);

    //Generation KpuV
    uint8_t kpuV[PUB_UNCOMP_LEN];
    kprV = gen_v_keypair_and_export(kpuV);
    if(!kprV){
        printf("Errore: keygen V fallita\n");
        goto cleanup;
    }
    hexdump("[V] KpuV", kpuV, PUB_UNCOMP_LEN, 32);
    printf("\n");
    
    //* Ver --> Nonce || KpuV --> Att
    printf("\n [V] STEP 2: invio NONCE (32B) + KpuV (65B) in binario + Contenuto firmato con SignV da Verifier \n");
    if(serial_write_exact(h, nonce, sizeof(nonce))!=0) die("Errore invio NONCE");
    if(serial_write_exact(h, kpuV, sizeof(kpuV))!=0) die("Errore invio KpuV");

    //* Ver --> E_Kpr(H(Nonce || KpuV)) --> Att
    printf("[V] Generazione firma ECDSA (P-256)...\n");

    // Load SignV from memory buffer 
    BIO *bio_priv = BIO_new_mem_buf(SignV, -1);
    EVP_PKEY *evp_privkey = PEM_read_bio_PrivateKey(bio_priv, NULL, NULL, NULL);
    BIO_free(bio_priv);

    if (!evp_privkey) {
        printf("Errore critico: caricamento chiave privata fallito.\n");
        exit(1);
    }

    // 2. Signing data: (Nonce || KpuV)
    uint8_t data_to_sign[NONCE_LEN + PUB_UNCOMP_LEN];
    memcpy(data_to_sign, nonce, NONCE_LEN);
    memcpy(data_to_sign + NONCE_LEN, kpuV, PUB_UNCOMP_LEN);

    // 3. Signing
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    size_t sig_len = 0;
    uint8_t *signature = NULL;

    if (EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, evp_privkey) <= 0) die("Init fallito");
    if (EVP_DigestSignUpdate(md_ctx, data_to_sign, sizeof(data_to_sign)) <= 0) die("Update fallito");

    // Allocation and obtain length
    EVP_DigestSignFinal(md_ctx, NULL, &sig_len);
    signature = malloc(sig_len);

    if (EVP_DigestSignFinal(md_ctx, signature, &sig_len) <= 0) die("Firma fallita");

    const unsigned char *p = signature;
    ECDSA_SIG *ecdsa_sig = d2i_ECDSA_SIG(NULL, &p, sig_len);

    if (!ecdsa_sig) die("Errore parsing DER");

    const BIGNUM *r;
    const BIGNUM *s;

    ECDSA_SIG_get0(ecdsa_sig, &r, &s);

    uint8_t sig_raw[64];

    BN_bn2binpad(r, sig_raw, 32);
    BN_bn2binpad(s, sig_raw + 32, 32);

    ECDSA_SIG_free(ecdsa_sig);

    printf("[V] Firma generata (LUNGHEZZA: %zu byte):\n", sig_len);
    for (size_t i = 0; i < sig_len; i++) {
        printf("%02X", signature[i]);
        if ((i + 1) % 16 == 0) printf("\n"); 
        else printf(" ");
    }

    // 4. Sending Signing on UART
    uint16_t sig_len_net = htons(64);
    DWORD dwWritten;

    WriteFile(h, &sig_len_net, 2, &dwWritten, NULL);
    WriteFile(h, sig_raw, 64, &dwWritten, NULL);

    printf("[V] Firma RAW inviata: 64 bytes.\n");

    free(signature);
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(evp_privkey);

    //* Ver <-- MEASB <--- Att
    printf("\n [A] STEP 3a: ricevo MEASB (hex line)\n");

    static uint8_t MEASB[67]; 
    size_t MEASB_len = 0;

    int rc = serial_read_line(h, MEASB, sizeof(MEASB), &MEASB_len);
    if(rc != 0) {
        printf("Errore lettura linea MEASB\n");
        goto cleanup;
    }

    /* Stampa raw */
    printf("RAW MEASB line len=%zu chars\n", MEASB_len);
    fwrite(MEASB, 1, MEASB_len, stdout);
    printf("\n");

    /* 1️) TRIM CR/LF */
    while (MEASB_len > 0 &&
        (MEASB[MEASB_len-1] == '\r' ||
            MEASB[MEASB_len-1] == '\n' ||
            MEASB[MEASB_len-1] == ' '  ||
            MEASB[MEASB_len-1] == '\t')) {
        MEASB_len--;
    }

    /* Ora deve essere 64 caratteri hex */
    printf("Trimmed MEASB len=%zu\n", MEASB_len);

    if (MEASB_len != 64) {
        printf("MEASB hex length wrong (expected 64)\n");
        goto cleanup;
    }

    /* 2️) HEX → BIN */
    uint8_t measb_bin[32];

    int out = hex2bin_str((char*)MEASB, MEASB_len,
                        measb_bin, sizeof(measb_bin));

    if (out != 32) {
        printf("hex2bin failed (out=%d)\n", out);
        goto cleanup;
    }

    printf("MEASB converted to %d bytes\n", out);

    //* Ver <-- Token <-- Att
    printf("\n [A] STEP 3b: ricevo TOKEN (hex line)\n");
    uint8_t token[4096]; size_t token_len=0;
    rc = read_device_hex_line_or_err(h, token, sizeof(token), &token_len, "TOKEN");
    if(rc!=0) goto cleanup;

    //stampo il token -- 
    printf("[V] Token ricevuto: %zu bytes\n", token_len);
    print_hex("[V] TOKEN", token, token_len);

    //* Ver <-- KpuA <-- Att
    printf("\n [A] STEP 4: ricevo KpuA (hex line)\n");
    uint8_t kpuA[PUB_UNCOMP_LEN]; size_t kpuA_len=0;
    rc = read_device_hex_line_or_err(h, kpuA, sizeof(kpuA), &kpuA_len, "KPUA");
    if(rc!=0 || kpuA_len!=PUB_UNCOMP_LEN){
        printf("[V] Errore KpuA len=%zu (atteso %u)\n", kpuA_len, (unsigned)PUB_UNCOMP_LEN);
        goto cleanup;
    }
    hexdump("[V] KpuA", kpuA, PUB_UNCOMP_LEN, 32);


    printf("\n [V] STEP 5: verifico firma COSE\n");
    
    UsefulBufC payload;
    
    //Verify cose sign
    if(verify_cose(token, token_len, &payload)!=0){
        printf("[V] Token rifiutato: firma non valida\n");
        goto cleanup;
    }

    // Token received from Parsing
    printf("\n [V] STEP 6: parse claims (challenge + meas)\n");
    const uint8_t *chal_tok=NULL,*m1=NULL,*m2=NULL;
    size_t chal_len=0,m1l=0,m2l=0;
    if(parse_claims(payload, &chal_tok, &chal_len, &m1, &m1l, &m2, &m2l)!=0){
        printf("[V] Errore parsing token\n");
        goto cleanup;
    }

    // Compare Measure Values
    printf("\n [V] STEP 7: controllo coerenza MEASB (linea UART) vs token\n");
    if(m1 && m1l==32) hexdump("[V] MEAS1: ", m1, 32, 0);
    if(m2 && m2l==32) hexdump("[V] MEAS2: ", m2, 32, 0);

    if(!m2 || m2l != 32){
        printf("[V] MEAS: attesa almeno MEAS2 da 32 byte nel token -> RIFIUTO\n");
        goto cleanup;
    }
    if(memcmp(m2, measb_bin, 32) != 0){
        printf("[V] MEASB: MISMATCH (UART != token) -> RIFIUTO\n");
        goto cleanup;
    }
    printf("[V] MEASB: OK (UART == token)\n");

    // Extract Challenge
    if(!chal_tok || chal_len!=HASH_LEN){
        printf("[V] CHALLENGE: atteso %u bytes, trovato %zu\n", (unsigned)HASH_LEN, chal_len);
        goto cleanup;
    }
    hexdump("[V] CHAL_TOK: ", chal_tok, HASH_LEN, 0);

    // Compare Challenge
    printf("\n [V] STEP 8: ricalcolo chal = SHA256(N||KpuV||KpuA) e confronto\n");
    uint8_t chal_calc[HASH_LEN];
    sha256_n_kv_ka(nonce, kpuV, kpuA, chal_calc);
    hexdump("[V] CHAL_CALC: ", chal_calc, HASH_LEN, 0);

    if(memcmp(chal_calc, chal_tok, HASH_LEN)!=0){
        printf("[V] CHALLENGE BINDING: MISMATCH -> RIFIUTO\n");
        goto cleanup;
    }
    printf("[V] CHALLENGE BINDING: OK\n");

    // Derivation shared secret Z with KprV and KpuA
    printf("\n [V] STEP 9: ECDH derive Z = ECDH(KprV, KpuA)\n");
    uint8_t z[ECDH_MAX]; size_t zlen=0;
    if(ecdh_derive(kprV, kpuA, z, sizeof(z), &zlen)!=0){
        printf("[V] Errore ECDH derive\n");
        goto cleanup;
    }
    printf("[V] Z len=%zu\n", zlen);
    hexdump("[V] Z", z, zlen, 32);

    // Derivation Ksess
    printf("\n [V] STEP 10: derivazione Ksess = SHA256(Z||chal||\"RA-KSESS\")\n");
    uint8_t ksess[HASH_LEN];
    derive_ksess(z, zlen, chal_calc, ksess);
    hexdump("[V] Ksess: ", ksess, HASH_LEN, 0);

    //* Ver --> MAC_V --> Att
    printf("\n [V] STEP 11: invio MAC_V = HMAC(Ksess, 'V'||chal)\n");
    uint8_t macV[HMAC_LEN];
    hmac_label_chal(ksess, 'V', chal_calc, macV);
    hexdump("[V] MAC_V: ", macV, HMAC_LEN, 0);
    if(serial_write_exact(h, macV, HMAC_LEN)!=0) die("Errore invio MAC_V");

    //* Ver <-- MAC_A <-- Att
    printf("\n [A] STEP 12: ricevo MAC_A (32B) e verifico (read_exact)\n");
    uint8_t macA_rx[HMAC_LEN];
    rc = serial_read_mac_or_errline(h, macA_rx);
    if(rc != 0){
        if(rc == -2) printf("[V] Timeout ricezione MAC_A\n");
        else         printf("[V] Errore ricezione MAC_A (rc=%d)\n", rc);
        goto cleanup;
    }
    hexdump("[V] MAC_A_RX: ", macA_rx, HMAC_LEN, 0);

    uint8_t macA_exp[HMAC_LEN];
    hmac_label_chal(ksess, 'A', chal_calc, macA_exp);
    hexdump("[V] MAC_A_EX: ", macA_exp, HMAC_LEN, 0);

    if(CRYPTO_memcmp(macA_rx, macA_exp, HMAC_LEN)!=0){
        printf("[V] MAC_A: MISMATCH -> RIFIUTO\n");
        goto cleanup;
    }
    printf("[V] MAC_A: OK (mutual key confirmation completata)\n");

    //* Ver --> Sec1 --> Att
    printf("\n [V] STEP 13: cifro e invio secret (AES-128-GCM)\n");

    uint8_t secret[16] = { 0xDE,0xAD,0xBE,0xEF,0xCA,0xFE,0xBA,0xBE,
                        0x12,0x34,0x56,0x78,0xAA,0xBB,0xCC,0xDD };

    uint8_t iv[IV_LEN];
    if(BCryptGenRandom(NULL, iv, sizeof(iv), BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0){
        printf("Errore: BCryptGenRandom IV fallita\n");
        goto cleanup;
    }
    hexdump("[V] IV_GCM: ", iv, IV_LEN, 0);

    uint8_t aes_key_128[16];
    memcpy(aes_key_128, ksess, 16);

    uint8_t ct[16], tag[TAG_LEN];
    if(aes128gcm_encrypt(aes_key_128, iv, secret, sizeof(secret), ct, sizeof(ct), tag)!=0){
        printf("Errore: AES-128-GCM encrypt fallita\n");
        goto cleanup;
    }

    hexdump("[V] SECRET_CT: ", ct, sizeof(ct), 0);
    hexdump("[V] TAG_GCM:   ", tag, sizeof(tag), 0);

    if(serial_write_str(h, "IV:\n")!=0) die("Errore invio IV label");
    if(serial_write_hex_line(h, iv, sizeof(iv))!=0) die("Errore invio IV hex");

    if(serial_write_str(h, "CT:\n")!=0) die("Errore invio CT label");
    if(serial_write_hex_line(h, ct, sizeof(ct))!=0) die("Errore invio CT hex");

    if(serial_write_str(h, "TAG:\n")!=0) die("Errore invio TAG label");
    if(serial_write_hex_line(h, tag, sizeof(tag))!=0) die("Errore invio TAG hex");

    //* Ver <-- IV||CT||TAG <-- Att
    printf("\n [V] STEP 14: ricevo echo IV/CT/TAG s\n");

    uint8_t iv_rx[IV_LEN], ct_rx[16], tag_rx[TAG_LEN];

    uint8_t lab[32];
    size_t labn = 0;
    size_t got = 0;

    /* IV echo */
    if(serial_read_line(h, lab, sizeof(lab), &labn)!=0) die("Errore lettura label IV echo");
    if(read_device_hex_line_or_err(h, iv_rx, sizeof(iv_rx), &got, "IV_ECHO")!=0 || got!=IV_LEN)
        die("Errore echo IV");

    /* CT echo */
    if(serial_read_line(h, lab, sizeof(lab), &labn)!=0) die("Errore lettura label CT echo");
    if(read_device_hex_line_or_err(h, ct_rx, sizeof(ct_rx), &got, "CT_ECHO")!=0 || got!=16)
        die("Errore echo CT");

    /* TAG echo */
    if(serial_read_line(h, lab, sizeof(lab), &labn)!=0) die("Errore lettura label TAG echo");
    if(read_device_hex_line_or_err(h, tag_rx, sizeof(tag_rx), &got, "TAG_ECHO")!=0 || got!=TAG_LEN)
        die("Errore echo TAG");

    hexdump("[A] IV_RX:    ", iv_rx, sizeof(iv_rx), 0);
    hexdump("[A] CT_RX:    ", ct_rx, sizeof(ct_rx), 0);
    hexdump("[A] TAG_RX:   ", tag_rx, sizeof(tag_rx), 0);

    if(memcmp(iv_rx, iv, sizeof(iv))!=0)  printf("[A] WARNING: IV echo diverso da IV inviato!\n");
    if(memcmp(ct_rx, ct, sizeof(ct))!=0)  printf("[A] WARNING: CT echo diverso da CT inviato!\n");
    if(memcmp(tag_rx, tag, sizeof(tag))!=0)printf("[A] WARNING: TAG echo diverso da TAG inviato!\n");

    // DEBUG
    printf("\n [A] STEP 15: ricevo Ksess (debug) \n");

    if(serial_read_line(h, lab, sizeof(lab), &labn) != 0)
        die("Errore lettura label KSESS");

    /* opzionale: controlla che inizi con "KSESS:" (tollerante a CR/LF) */
    if(memcmp(lab, "KSESS:", 6) != 0){
        printf("[A] WARNING: label inattesa prima di KSESS: '%s'\n", lab);
    }

    uint8_t ksess_rx[HASH_LEN];
    size_t kslen = 0;
    rc = read_device_hex_line_or_err(h, ksess_rx, HASH_LEN, &kslen, "KSESS_RX");
    if(rc != 0 || kslen != HASH_LEN)
        die("Errore ricezione Ksess hex");

    hexdump("[V] Ksess_RX: ", ksess_rx, HASH_LEN, 0);

    if(memcmp(ksess_rx, ksess, HASH_LEN) != 0)
        printf("[V] WARNING: Ksess_RX != Ksess calcolata dal verifier\n");
    else
        printf("[V] Ksess RX match: OK\n");

    //DEBUG
    printf("\n [V] STEP 16: ricevo PT (line)\n");
    uint8_t pt_line[256]; size_t pt_ln=0;
    rc = serial_read_line(h, pt_line, sizeof(pt_line), &pt_ln);
    if(rc!=0) die("Errore/timeout lettura linea PT");

    if(pt_ln >= 4 && memcmp(pt_line, "ERR:", 4)==0){
        printf("[V] Device ha risposto: %s\n", pt_line);
        goto cleanup;
    }
    if(pt_ln < 4 || memcmp(pt_line, "PT:", 3)!=0){
        printf("[V] Errore: linea PT non valida: %s\n", pt_line);
        goto cleanup;
    }

    char hexpt[64]; size_t hlen=0;
    for(size_t i=3;i<pt_ln;i++){
        uint8_t c = pt_line[i];
        if(c=='\r'||c=='\n'||c==' '||c=='\t') continue;
        if(hexn(c)<0) die("Errore: PT contiene carattere non-hex");
        if(hlen >= sizeof(hexpt)) die("Errore: PT hex troppo lungo");
        hexpt[hlen++] = (char)c;
    }
    if(hlen != 32){
        printf("[V] Errore: PT hex len=%zu (atteso 32)\n", hlen);
        printf("[V] Linea PT raw: %s\n", pt_line);
        goto cleanup;
    }

    uint8_t pt_bin[16];
    if(hex2bin_str(hexpt, hlen, pt_bin, sizeof(pt_bin)) != 16){
        printf("[V] Errore: PT decode fallita\n");
        printf("[V] Linea PT raw: %s\n", pt_line);
        goto cleanup;
    }

    hexdump("[V] PT_RX: ", pt_bin, 16, 0);
    hexdump("[V] SECRET: ", secret, 16, 0);

    if(memcmp(pt_bin, secret, 16)!=0) printf("[V] PLAINTEXT MISMATCH!\n");
    else printf("[V] PLAINTEXT MATCH: OK\n");

    ret = 0;

    //* Ver <-- Sec2 <-- Att
    printf("\n [V] STEP 17: ricevo reply cifrata (IV_A/CT_A/TAG_A) e decifro\n");

    uint8_t IV_A[IV_LEN];
    uint8_t CT_A[8];          
    uint8_t TAG_A[TAG_LEN];

    uint8_t lab2[32];
    size_t lab2n = 0;
    size_t got2 = 0;

    // IV_A 
    if(serial_read_line(h, lab2, sizeof(lab2), &lab2n) != 0) die("Errore lettura label IV_A");
    if(read_device_hex_line_or_err(h, IV_A, sizeof(IV_A), &got2, "IV_A") != 0 || got2 != IV_LEN)
        die("Errore ricezione IV_A hex");

    // CT_A 
    if(serial_read_line(h, lab2, sizeof(lab2), &lab2n) != 0) die("Errore lettura label CT_A");
    if(read_device_hex_line_or_err(h, CT_A, sizeof(CT_A), &got2, "CT_A") != 0 || got2 != sizeof(CT_A))
        die("Errore ricezione CT_A hex");

    // TAG_A 
    if(serial_read_line(h, lab2, sizeof(lab2), &lab2n) != 0) die("Errore lettura label TAG_A");
    if(read_device_hex_line_or_err(h, TAG_A, sizeof(TAG_A), &got2, "TAG_A") != 0 || got2 != TAG_LEN)
        die("Errore ricezione TAG_A hex");

    hexdump("[V] IV_A:  ", IV_A, sizeof(IV_A), 0);
    hexdump("[V] CT_A:  ", CT_A, sizeof(CT_A), 0);
    hexdump("[V] TAG_A: ", TAG_A, sizeof(TAG_A), 0);

    uint8_t reply_pt[9]; /* 8 + terminatore */
    if(aes128gcm_decrypt(aes_key_128, IV_A, CT_A, sizeof(CT_A), TAG_A, reply_pt, sizeof(reply_pt)) != 0) {
        printf("[V] Reply decrypt FAILED (tag mismatch?)\n");
    } else {
        reply_pt[8] = 0;
        printf("[V] Reply decrypted: '%s'\n", (char*)reply_pt);
    }

    printf("\n[V] Remote Attestation Completed !!\n");

cleanup:
    if(kprV) EVP_PKEY_free(kprV);
    if(h != INVALID_HANDLE_VALUE) CloseHandle(h);
    return ret;
}
