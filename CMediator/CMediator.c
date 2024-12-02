// standard headers
#include <stddef.h>
#include <stdalign.h>
#include <string.h>
// dependency headers
#include <sodium.h>
#include <opaque.h>
// private headers
#include "CMediator.h"
// test-time headers
#ifdef UNIT_TESTING
    #include <stdio.h>
    // cmocka stuff
    #include <stdarg.h>
    #include <stddef.h>
    #include <setjmp.h>
    #include <cmocka.h>
#endif

#if __STDC_VERSION__ != 201710L
    #error "This file uses the C17 standard"
#endif

#ifdef UNIT_TESTING

// libsodium basic usage
static void
CMediator_test_basic_encryption_decryption(void** state)
{
    /* clang-format off */
    const char* test_plaintext =
        "SPDX-License-Identifier: GPL-3.0-or-later"
        "\n"
        "GNU General Public License v3.0 or later";
    /* clang-format on */

    int temp_result = -1;
    const char* emsg = "5";

    temp_result = Wrap(sodium_init)();
    // 0 - ok; 1 - already initialized
    assert_true(temp_result == 0 || temp_result == 1);

    // generate a secret key
    unsigned int secret_key_size = Wrap(const_crypto_secretbox_KEYBYTES);
    unsigned char* secret_key = malloc(secret_key_size);
    emsg = Wrap(Ex01_crypto_secretbox_keygen)(secret_key, secret_key_size);
    if (emsg != NULL) {
        fprintf(stderr, "Could not generate secret key: %s\n", emsg);
    }
    assert_null(emsg);

    // generate nonce
    unsigned int nonce_size = Wrap(const_crypto_secretbox_NONCEBYTES);
    unsigned char* nonce = malloc(nonce_size);
    emsg = Wrap(Ex01_randombytes_buf)(nonce, nonce_size);
    if (emsg != NULL) {
        fprintf(stderr, "Could not generate nonce: %s\n", emsg);
    }
    assert_null(emsg);

    unsigned int plaintext_size = strlen(test_plaintext);
    unsigned int ciphertext_size = plaintext_size + Wrap(const_crypto_secretbox_MACBYTES);
    assert_true(ciphertext_size > plaintext_size);

    // encryption
    unsigned char* ciphertext = malloc(ciphertext_size);
    emsg = Wrap(Ex01_crypto_secretbox_easy)(
        /* ciphertext out */ ciphertext,
        /* plaintext */ (const unsigned char*)test_plaintext,
        /* nonce */ nonce,
        /* secret_key */ secret_key,
        // length checks
        ciphertext_size,
        plaintext_size,
        nonce_size,
        secret_key_size);
    if (emsg != NULL) {
        fprintf(stderr, "Could not encrypt: %s\n", emsg);
    }
    assert_null(emsg);

    // decryption
    unsigned char* plaintext_result = malloc(plaintext_size);
    emsg = Wrap(Ex01_crypto_secretbox_open_easy)(
        /* plaintext out */ plaintext_result,
        /* ciphertext */ ciphertext,
        /* nonce */ nonce,
        /* secret_key */ secret_key,
        // length checks
        plaintext_size,
        ciphertext_size,
        nonce_size,
        secret_key_size);
    if (emsg != NULL) {
        fprintf(stderr, "Could not decrypt: %s\n", emsg);
    }
    assert_null(emsg);

    assert_memory_equal(plaintext_result, test_plaintext, plaintext_size);

    // zero memory
    Wrap(sodium_memzero)(secret_key, secret_key_size);
    Wrap(sodium_memzero)(plaintext_result, plaintext_size);

    // release memory
    free(secret_key);
    free(nonce);
    free(ciphertext);
    free(plaintext_result);

    (void)state; /* unused */
}

#endif // ifdef UNIT_TESTING

// libsodium constants

_Static_assert(UINT16_MAX > crypto_core_ristretto255_BYTES, "ristretto255_BYTES could not be fit into 16 bits");
_Static_assert(UINT16_MAX > crypto_scalarmult_SCALARBYTES, "scalarmult_SCALARBYTES could not be fit into 16 bits");
_Static_assert(UINT16_MAX > crypto_secretbox_KEYBYTES, "KEYBYTES could not be fit into 16 bits");
_Static_assert(UINT16_MAX > crypto_secretbox_MACBYTES, "MACBYTES could not be fit into 16 bits");
_Static_assert(UINT16_MAX > crypto_secretbox_NONCEBYTES, "NONCEBYTES could not be fit into 16 bits");

const uint16_t Wrap(const_crypto_core_ristretto255_BYTES) = crypto_core_ristretto255_BYTES;
const uint16_t Wrap(const_crypto_scalarmult_SCALARBYTES) = crypto_scalarmult_SCALARBYTES;
const uint16_t Wrap(const_crypto_secretbox_KEYBYTES) = crypto_secretbox_KEYBYTES;
const uint16_t Wrap(const_crypto_secretbox_MACBYTES) = crypto_secretbox_MACBYTES;
const uint16_t Wrap(const_crypto_secretbox_NONCEBYTES) = crypto_secretbox_NONCEBYTES;

// libopaque struct wrappers

struct Wrap(Opaque_Ids_st)
{
    Opaque_Ids data;
};

// libopaque constants

_Static_assert(UINT16_MAX > OPAQUE_REGISTER_PUBLIC_LEN, "REGISTER_PUBLIC_LEN could not be fit into 16 bits");
_Static_assert(UINT16_MAX > OPAQUE_REGISTER_SECRET_LEN, "REGISTER_SECRET_LEN could not be fit into 16 bits");
_Static_assert(UINT16_MAX > OPAQUE_REGISTRATION_RECORD_LEN, "REGISTRATION_RECORD_LEN could not be fit into 16 bits");
_Static_assert(UINT16_MAX > OPAQUE_USER_RECORD_LEN, "USER_RECORD_LEN could not be fit into 16 bits");
_Static_assert(UINT16_MAX > sizeof(Wrap(Opaque_Ids)), "sizeof(Opaque_Ids) could not be fit into 16 bits");
_Static_assert(UINT16_MAX > alignof(Wrap(Opaque_Ids)), "alignof(Opaque_Ids) could not be fit into 16 bits");

const uint16_t Wrap(const_OPAQUE_REGISTER_PUBLIC_LEN) = OPAQUE_REGISTER_PUBLIC_LEN;
const uint16_t Wrap(const_OPAQUE_REGISTER_SECRET_LEN) = OPAQUE_REGISTER_SECRET_LEN;
const uint16_t Wrap(const_OPAQUE_REGISTRATION_RECORD_LEN) = OPAQUE_REGISTRATION_RECORD_LEN;
const uint16_t Wrap(const_OPAQUE_USER_RECORD_LEN) = OPAQUE_USER_RECORD_LEN;
const uint16_t Wrap(sizeof_Opaque_Ids) = sizeof(Wrap(Opaque_Ids));
const uint16_t Wrap(alignof_Opaque_Ids) = alignof(Wrap(Opaque_Ids));

// libsodium functions

int Wrap(sodium_init)(void)
{
    return sodium_init();
}

void Wrap(sodium_memzero)(void* const pnt, const size_t len)
{
    sodium_memzero(pnt, len);
}

const char* Wrap(Ex01_crypto_secretbox_keygen)(unsigned char k[], unsigned long long klen)
{
    // null checks
    if (NULL == k) {
        return "5: k is null";
    }
    // length checks
    if (klen != crypto_secretbox_KEYBYTES) {
        return "5: Wrong key size: klen != KEYBYTES";
    }
    crypto_secretbox_keygen(k);
    return NULL;
}

const char* Wrap(Ex01_randombytes_buf)(void* const buf, const size_t size)
{
    // null checks
    if (NULL == buf) {
        return "5: buf is null";
    }
    randombytes_buf(buf, size);
    return NULL;
}

const char* Wrap(Ex01_crypto_secretbox_easy)(
    unsigned char* c,
    const unsigned char* m,
    const unsigned char* n,
    const unsigned char* k,
    unsigned long long clen,
    unsigned long long mlen,
    unsigned long long nlen,
    unsigned long long klen)
{
    // null checks
    if ((NULL == c) | (NULL == m) | (NULL == n) | (NULL == k)) {
        return "5: One of {c, m, n, k} is null";
    }
    // length checks
    if (clen < mlen || clen - mlen < crypto_secretbox_MACBYTES) {
        return "5: clen should be at least MACBYTES + mlen";
    }
    if (nlen != crypto_secretbox_NONCEBYTES) {
        return "5: Wrong nonce size: nlen != NONCEBYTES";
    }
    if (klen != crypto_secretbox_KEYBYTES) {
        return "5: Wrong key size: klen != KEYBYTES";
    }

    int result = crypto_secretbox_easy(c, m, mlen, n, k);
    if (0 == result) {
        return NULL;
    } else {
        return "5: Encryption failed!";
    }
}

const char* Wrap(Ex01_crypto_secretbox_open_easy)(
    unsigned char* m,
    const unsigned char* c,
    const unsigned char* n,
    const unsigned char* k,
    unsigned long long mlen,
    unsigned long long clen,
    unsigned long long nlen,
    unsigned long long klen)
{
    // null checks
    if ((NULL == m) | (NULL == c) | (NULL == n) | (NULL == k)) {
        return "5: One of {m, c, n, k} is null";
    }
    // checks if crypto_secretbox_MACBYTES + mlen != clen
    if (clen < mlen || clen - mlen != crypto_secretbox_MACBYTES) {
        return "4: Wrong ciphertext size: clen != MACBYTES + mlen";
    }
    if (nlen != crypto_secretbox_NONCEBYTES) {
        return "5: Wrong nonce size: nlen != NONCEBYTES";
    }
    if (klen != crypto_secretbox_KEYBYTES) {
        return "5: Wrong key size: klen != KEYBYTES";
    }

    int result = crypto_secretbox_open_easy(m, c, clen, n, k);
    if (0 == result) {
        return NULL;
    } else {
        return "4: Decryption failed!";
    }
}

// libopaque functions

const char* Wrap(Ex01_opaque_CreateRegistrationResponse)(
    const uint8_t request[/*crypto_core_ristretto255_BYTES*/],
    const uint8_t skS[/*crypto_scalarmult_SCALARBYTES*/],
    uint8_t sec_out[/*OPAQUE_REGISTER_SECRET_LEN*/],
    uint8_t pub_out[/*OPAQUE_REGISTER_PUBLIC_LEN*/],
    // length checks
    uint64_t request_len, /* user controlled */
    uint64_t skS_len,
    uint64_t sec_len,
    uint16_t pub_len)
{
    // null checks
    if ((NULL == request) | (NULL == skS) | (NULL == sec_out) | (NULL == pub_out)) {
        return "5: One of {request, skS, sec_out, pub_out} is null";
    }
    // length checks
    if (request_len != crypto_core_ristretto255_BYTES) {
        return "4: Wrong size for blinded request: request_len != ristretto255_BYTES";
    }
    if (skS_len != crypto_scalarmult_SCALARBYTES) {
        return "5: Wrong size for server context: skS_len != scalarmult_SCALARBYTES";
    }
    if (sec_len != OPAQUE_REGISTER_SECRET_LEN) {
        return "5: sec_len";
    }
    if (pub_len != OPAQUE_REGISTER_PUBLIC_LEN) {
        return "5: pub_len";
    }

    int result = opaque_CreateRegistrationResponse(request, skS, sec_out, pub_out);
    if (0 == result) {
        return NULL;
    } else {
        return "4: Failed to create registration response";
    }
}

const char* Wrap(Ex01_opaque_StoreUserRecord)(
    const uint8_t sec[/*OPAQUE_REGISTER_SECRET_LEN*/],
    const uint8_t recU[/*OPAQUE_REGISTRATION_RECORD_LEN*/],
    uint8_t rec_out[/*OPAQUE_USER_RECORD_LEN*/],
    // length checks
    uint64_t sec_len,
    uint64_t recU_len, /* user controlled */
    uint64_t rec_len)
{
    // null checks
    if ((NULL == sec) | (NULL == recU) | (NULL == rec_out)) {
        return "5: One of {sec, recU, rec_out} is null";
    }
    // length checks
    if (sec_len != OPAQUE_REGISTER_SECRET_LEN) {
        return "5: Wrong size for server secret: sec_len";
    }
    if (recU_len != OPAQUE_REGISTRATION_RECORD_LEN) {
        return "4: Wrong size for registration record: recU_len";
    }
    if (rec_len != OPAQUE_USER_RECORD_LEN) {
        return "5: rec_len";
    }

    opaque_StoreUserRecord(sec, recU, rec_out);
    return NULL;
}

const char* Wrap(Opaque_Ids_init_nostrcopy)(
    void* selfVoidP,
    uint16_t idU_len_u16,
    uint8_t* idU,
    uint16_t idS_len_u16,
    uint8_t* idS)
{
    if ((NULL == selfVoidP) | (NULL == idU) | (NULL == idS)) {
        return "5: One of {selfVoidP, idU, idS} is null";
    }
    if (0 == idU_len_u16) {
        return "5: idU cannot be empty";
    }
    if (0 == idS_len_u16) {
        return "5: idS cannot be empty";
    }
    // create a shallow copy
    Wrap(Opaque_Ids)* self = (Wrap(Opaque_Ids)*)selfVoidP;
    memset(self, 0, sizeof(Wrap(Opaque_Ids)));
    Opaque_Ids* data = &(self->data);

    data->idU_len = idU_len_u16;
    data->idU = idU;

    data->idS_len = idS_len_u16;
    data->idS = idS;
    // end of shallow copy

    return NULL;
}

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
    uint64_t authU_len_u64)
{
    if (
        /* input */ ((NULL == ids) | (NULL == ke1) | (NULL == rec) | (NULL == ctx)) |
        /* output */ ((NULL == ke2_out) | (NULL == sk_out) | (NULL == authU_out))) {
        return "5: One of {ids, ke1, rec, ctx, ke2_out, sk_out, authU_out} is null";
    }
    // input lengths
    if (ke1_len_u64 != OPAQUE_USER_SESSION_PUBLIC_LEN) {
        return "4: Wrong size for credential request: ke1_len_u64";
    }
    if (rec_len_u64 != OPAQUE_USER_RECORD_LEN) {
        return "5: rec_len_u64, OPAQUE_USER_RECORD_LEN";
    }
    if (ctx_len_u64 > 0xFFFF) {
        return "5: ctx_len could not be fit into 16 bits";
    }
    // output lengths
    if (ke2_len_u64 != OPAQUE_SERVER_SESSION_LEN) {
        return "5: ke2_len_u64, OPAQUE_SERVER_SESSION_LEN";
    }
    if (sk_len_u64 != OPAQUE_SHARED_SECRETBYTES) {
        return "5: sk_len_u64, OPAQUE_SHARED_SECRETBYTES";
    }
    if (authU_len_u64 != crypto_auth_hmacsha512_BYTES) {
        return "5: authU_len_u64, crypto_auth_hmacsha512_BYTES";
    }

    int result = opaque_CreateCredentialResponse(
        /* in */
        ke1,
        rec,
        &(ids->data),
        ctx,
        (uint16_t)ctx_len_u64,
        /* out */
        ke2_out,
        sk_out,
        authU_out);
    if (result != 0) {
        return "4: Could not create credential response";
    }
    return NULL;
}

const char* Wrap(Ex01_opaque_UserAuth)(
    const uint8_t authU0[/*crypto_auth_hmacsha512_BYTES*/],
    const uint8_t authU[/*crypto_auth_hmacsha512_BYTES*/], /* user controlled */
    // length checks
    uint64_t authU0_len,
    uint64_t authU_len)
{
    if ((NULL == authU0) | (NULL == authU)) {
        return "5: One of {authU0, authU} is null";
    }
    if (authU0_len != crypto_auth_hmacsha512_BYTES) {
        return "5: Wrong size for authU0: authU0_len != hmacsha512_BYTES";
    }
    if (authU_len != crypto_auth_hmacsha512_BYTES) {
        return "4: Wrong size for user-sent authU: authU_len != hmacsha512_BYTES";
    }

    int result = opaque_UserAuth(authU0, authU);
    if (result != 0) {
        return "4: Could not authenticate user";
    }
    return NULL;
}

#ifdef UNIT_TESTING

// register all unit tests
int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(CMediator_test_basic_encryption_decryption),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}

#endif // ifdef UNIT_TESTING
