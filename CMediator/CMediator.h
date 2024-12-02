#pragma once

#include <stddef.h>
#include <stdint.h>
// Wrap
#include "CMediatorPrivate/Prefixing.h"

// libsodium
extern const uint16_t Wrap(const_crypto_core_ristretto255_BYTES);
extern const uint16_t Wrap(const_crypto_scalarmult_SCALARBYTES);
extern const uint16_t Wrap(const_crypto_secretbox_KEYBYTES);
extern const uint16_t Wrap(const_crypto_secretbox_MACBYTES);
extern const uint16_t Wrap(const_crypto_secretbox_NONCEBYTES);

// libopaque
extern const uint16_t Wrap(const_OPAQUE_REGISTER_PUBLIC_LEN);
extern const uint16_t Wrap(const_OPAQUE_REGISTER_SECRET_LEN);
extern const uint16_t Wrap(const_OPAQUE_REGISTRATION_RECORD_LEN);
extern const uint16_t Wrap(const_OPAQUE_USER_RECORD_LEN);
extern const uint16_t Wrap(sizeof_Opaque_Ids);
extern const uint16_t Wrap(alignof_Opaque_Ids);

// initializer for libsodium
int Wrap(sodium_init)(void);

// securely erase memory
void Wrap(sodium_memzero)(void* const pnt, const size_t len);

// keygen
const char* Wrap(Ex01_crypto_secretbox_keygen)(unsigned char k[], unsigned long long klen)
    __attribute__((warn_unused_result));

// nonce generation
const char* Wrap(Ex01_randombytes_buf)(void* const buf, const size_t size) __attribute__((warn_unused_result));

// authenticated encryption
const char* Wrap(Ex01_crypto_secretbox_easy)(
    unsigned char* c,
    const unsigned char* m,
    const unsigned char* n,
    const unsigned char* k,
    unsigned long long clen,
    unsigned long long mlen,
    unsigned long long nlen,
    unsigned long long klen) __attribute__((warn_unused_result));

// decryption for authenticated encryption
const char* Wrap(Ex01_crypto_secretbox_open_easy)(
    unsigned char* m,
    const unsigned char* c,
    const unsigned char* n,
    const unsigned char* k,
    unsigned long long mlen,
    unsigned long long clen,
    unsigned long long nlen,
    unsigned long long klen) __attribute__((warn_unused_result));

// libopaque registration step 2
const char* Wrap(Ex01_opaque_CreateRegistrationResponse)(
    const uint8_t request[/*crypto_core_ristretto255_BYTES*/],
    const uint8_t skS[/*crypto_scalarmult_SCALARBYTES*/],
    uint8_t sec_out[/*OPAQUE_REGISTER_SECRET_LEN*/],
    uint8_t pub_out[/*OPAQUE_REGISTER_PUBLIC_LEN*/],
    // length checks
    uint64_t request_len, /* user controlled */
    uint64_t skS_len,
    uint64_t sec_len,
    uint16_t pub_len) __attribute__((warn_unused_result));

// libopaque registration step 4
const char* Wrap(Ex01_opaque_StoreUserRecord)(
    const uint8_t sec[/*OPAQUE_REGISTER_SECRET_LEN*/],
    const uint8_t recU[/*OPAQUE_REGISTRATION_RECORD_LEN*/],
    uint8_t rec_out[/*OPAQUE_USER_RECORD_LEN*/],
    // length checks
    uint64_t sec_len,
    uint64_t recU_len, /* user controlled */
    uint64_t rec_len) __attribute__((warn_unused_result));

// pointer-firewalled definition for `Opaque_Ids` struct
typedef struct Wrap(Opaque_Ids_st) Wrap(Opaque_Ids);

// initializer (non-allocating constructor) for Opaque_Ids
const char* Wrap(Opaque_Ids_init_nostrcopy)(
    void* selfVoidP,
    uint16_t idU_len_u16,
    uint8_t* idU,
    uint16_t idS_len_u16,
    uint8_t* idS) __attribute__((warn_unused_result));

// libopaque key exchange step 2
const char* Wrap(Ex01_opaque_CreateCredentialResponse)(
    const Wrap(Opaque_Ids)* ids,
    const uint8_t ke1[/*OPAQUE_USER_SESSION_PUBLIC_LEN*/], /* user controlled */
    const uint8_t rec[/*OPAQUE_USER_RECORD_LEN*/],
    const uint8_t* ctx, /* unsigned 16-bit */
    uint8_t ke2_out[/*OPAQUE_SERVER_SESSION_LEN*/],
    uint8_t sk_out[/*OPAQUE_SHARED_SECRETBYTES*/],
    uint8_t authU_out[/*crypto_auth_hmacsha512_BYTES*/],
    // input length checks
    uint64_t ke1_len_u64,
    uint64_t rec_len_u64,
    uint64_t ctx_len_u64,
    // output length checks
    uint64_t ke2_len_u64,
    uint64_t sk_len_u64,
    uint64_t authU_len_u64) __attribute__((warn_unused_result));

// libopaque key exchange step 4
const char* Wrap(Ex01_opaque_UserAuth)(
    const uint8_t authU0[/*crypto_auth_hmacsha512_BYTES*/],
    const uint8_t authU[/*crypto_auth_hmacsha512_BYTES*/], /* user controlled */
    // length checks
    uint64_t authU0_len,
    uint64_t authU_len) __attribute__((warn_unused_result));
