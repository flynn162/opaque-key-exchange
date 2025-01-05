# The C Mediator Library

Linting:

```
clang-format -i file.c
```

Building:

```
ninja -v
```

Unit tests:

```
./build/test_libCMediator
```

ASan, UBSan:

```
./build/sanitize_libCMediator
```

## Function Versioning

Function names are prefixed by the project namespace (`CythWrap`), a two-digit version number (`V88`) and optionally a two-digit extension number (`_Ex88`). A function's **Binary** Interface (not Programming Interface) is guaranteed to never change under the same V number **and** Ex number.

- V (version) number: documents a backward-INcompatible change
- Ex (extension) number: documents a backward-compatible **and** forward-INcompatible change
- The entire library has one shared V number. Ex numbers are function-specific.

**Definitions:**

- Backward compatibility: old client code may be linked against a new library.
- Forward compatibility: new client code may be linked against an old library.

**Examples:**

- a) V01 clients **should not** be linked against V02 libraries. (Attempting to do so will result in a linker error.)
- b) V01 clients using the Ex01 extension of a function **may** be linked against V01 libraries providing both Ex01 and Ex02 extensions of the same function.
- c) V03 clients using the Ex02 extension of a function cannot be linked against a V03 library that only provides the Ex01 extension of the same function.

Not all functions have Ex numbers at the current moment. (Mathematically, their Ex numbers are 0.) An "Ex" prefix will be added in case the ABI changes, along with a new extension number counting from 1.

## ABI Checking Tools

- [icheck](https://manpages.ubuntu.com/manpages/noble/en/man1/icheck.1.html)
- [ABI Compliance Checker](https://lvc.github.io/abi-compliance-checker/) and [ABI Dumper](https://github.com/lvc/abi-dumper)
- [abigail-tools](https://sourceware.org/libabigail/manual/libabigail-tools.html)
