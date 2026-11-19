/* Shared setup for the tbox fuzz harnesses.
 *
 * tbox is initialised once per process with the native allocator: every tbox allocation then goes
 * straight to libc malloc/free, so ASan sees exact block bounds instead of tbox's pooled chunks.
 * tb_init() only sets up process-wide environments (trace, singletons, libc/libm/network/object
 * tables); none of them is changed by the inputs, so the state kept across iterations is read-only.
 */
#ifndef TBOX_FUZZ_COMMON_H
#define TBOX_FUZZ_COMMON_H

#include "tbox/tbox.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerInitialize(int* argc, char*** argv)
{
    (void)argc; (void)argv;
    if (!tb_init(tb_null, tb_native_allocator())) abort();
    return 0;
}

/* NUL-terminated heap copy of the input (string-taking APIs need one). Caller frees. */
static char* fuzz_cstr(uint8_t const* data, size_t size)
{
    char* s = (char*)malloc(size + 1);
    if (!s) abort();
    if (size) memcpy(s, data, size);
    s[size] = '\0';
    return s;
}

#endif
