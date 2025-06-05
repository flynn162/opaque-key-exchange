// IWYU pragma: private
// IWYU pragma: friend "Interface\.h"
#pragma once
#include <assert.h>

/* clang-format off */

#define __cythwrap_dev_export_const \
    __attribute__((externally_visible)) \
    __attribute__((visibility("protected"))) /* end */

#define __cythwrap_dev_export \
    __attribute__((noinline)) \
    __attribute__((externally_visible)) \
    __attribute__((visibility("protected"))) /* end */

#define __cythwrap_client_import_const /* end */

#define __cythwrap_client_import __attribute__((noinline)) /* end */

#if CYTHWRAP_DEV_MODE == 1
    #define CythWrap_public_const      __cythwrap_dev_export_const
    #define CythWrap_public            __cythwrap_dev_export
    #define __cythwrap_vis_in_dev_mode 1
#elif CYTHWRAP_DEV_MODE == 0
    #define CythWrap_public_const      __cythwrap_client_import_const
    #define CythWrap_public            __cythwrap_client_import
    #define __cythwrap_vis_in_dev_mode 0
#else
    #error "CYTHWRAP_DEV_MODE has an unknown value"
#endif

#define CythWrap_assert_is_dev_mode() \
    static_assert(1 == __cythwrap_vis_in_dev_mode, \
        "Vis.h should be in dev mode");

#define CythWrap_assert_is_client_mode() \
    static_assert(0 == __cythwrap_vis_in_dev_mode, \
        "Vis.h should be in client mode");

/* clang-format on */
