#pragma once
#ifndef CYTHWRAP_DEV_MODE
    #define CYTHWRAP_DEV_MODE 1
#endif

#include "Interface.h" // IWYU pragma: export

CythWrap_assert_is_dev_mode();

#define CythWrap_likely(x) __builtin_expect(!!(x), 1)
#define CythWrap_unlikely(x) __builtin_expect(!!(x), 0)
