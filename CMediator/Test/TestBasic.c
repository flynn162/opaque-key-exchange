#include <stdio.h>
#include <string.h>
#include "../CMediator.h"
#include "AllTests.h"
#include "UseCMocka.h" // last header

void
CMediator_test_basic_encryption_decryption(void** state)
{
    /* clang-format off */
    const char* test_plaintext =
        "GPL-3.0-or-later"
        " is the SPDX identifier for "
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
