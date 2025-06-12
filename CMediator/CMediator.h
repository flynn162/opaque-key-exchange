#pragma once

#ifdef CYTHWRAP_DEV_MODE
    #undef CYTHWRAP_DEV_MODE
    #error "CYTH_WRAP_DEV_MODE cannot be used by the client"
#endif
#define CYTHWRAP_DEV_MODE 0

#include "CMediatorPrivate/Interface.h" // IWYU pragma: export
