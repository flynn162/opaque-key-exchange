#pragma once

#ifdef CythWrapMyConcat2
    #error "Macro `CythWrapMyConcat2` has been defined somewhere else."
#endif

#ifdef CythWrapMyConcat
    #error "Macro `CythWrapMyConcat` has been defined somewhere else."
#endif

#ifdef Wrap
    #error "Macro `Wrap` has been defined somewhere else."
#endif

#define CythWrapMyConcat2(X, Y) X ## Y
#define CythWrapMyConcat(X, Y) CythWrapMyConcat2(X, Y)

// Latest internal major ABI version
#define Wrap(x) CythWrapMyConcat2(CythWrapV01_, x)

#define CYTH_WRAP_EXPORT __attribute__((visibility("protected")))
