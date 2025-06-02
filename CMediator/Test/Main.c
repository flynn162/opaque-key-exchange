#include "AllTests.h"
#include "UseCMocka.h" // last header

// register all unit tests
int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(CMediator_test_basic_encryption_decryption),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
