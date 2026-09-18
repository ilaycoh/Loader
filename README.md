# Loader

A simple x86-64 ELF loader written in C.

### Current support

* PIE and non-PIE executables
* Basic shared library (`.so`) loading
* `libc`(musl) support is not implemented yet

### Exploit

The Python exploit will work **only when the mapping address check is disabled**.

