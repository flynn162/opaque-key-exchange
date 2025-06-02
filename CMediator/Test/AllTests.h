#pragma once

#if __STDC_VERSION__ != 201710L
    #error "This file uses the C17 standard"
#endif

int main(void) __attribute__((visibility("default")));
void CMediator_test_basic_encryption_decryption(void** state);
