/* The native large allocator (the default allocator's backing for big blocks): an op sequence of
 * malloc / ralloc / free on 8 slots against a fresh tb_large_allocator_init(tb_null, 0) per input.
 * Sizes span 0..512 KiB so blocks move between libc malloc and virtual memory
 * (TB_VIRTUAL_MEMORY_DATA_MINN = 128 KiB) in both directions. Each block is filled with a pattern and
 * ralloc must keep the common prefix intact. */
#include "fuzz_common.h"

#define SLOTS 8

typedef struct { tb_byte_t* p; tb_size_t n; tb_byte_t tag; } slot_t;

static tb_size_t size_of(uint8_t hi, uint8_t lo)
{
    tb_size_t v = ((tb_size_t)hi << 8) | lo;
    /* 0..512 KiB in 8-byte steps; high bit set = within +-2 KiB of 128 KiB */
    if (v & 0x8000) return TB_VIRTUAL_MEMORY_DATA_MINN - 2048 + (v & 0xfff);
    return (v & 0xffff) << 3;
}

int LLVMFuzzerTestOneInput(uint8_t const* data, size_t size)
{
    tb_allocator_ref_t a = tb_large_allocator_init(tb_null, 0);
    if (!a) return 0;
    slot_t slots[SLOTS] = {{0}};
    for (size_t i = 0; i + 4 <= size && i < 4 * 64; i += 4)
    {
        uint8_t op = data[i] & 3, k = data[i + 1] % SLOTS;
        tb_size_t n = size_of(data[i + 2], data[i + 3]);
        slot_t* s = &slots[k];
        if (op == 0 || (op == 1 && !s->p))
        {
            if (s->p) tb_allocator_free(a, s->p);
            s->p = (tb_byte_t*)tb_allocator_malloc(a, n ? n : 1);
            s->n = s->p ? (n ? n : 1) : 0;
            s->tag = data[i + 2] ^ (uint8_t)i;
            if (s->p) memset(s->p, s->tag, s->n);
        }
        else if (op == 1)
        {
            tb_size_t keep = s->n < (n ? n : 1) ? s->n : (n ? n : 1);
            tb_byte_t* q = (tb_byte_t*)tb_allocator_ralloc(a, s->p, n ? n : 1);
            if (!q) continue;   /* failed ralloc keeps the old block */
            for (tb_size_t j = 0; j < keep; j++) if (q[j] != s->tag) abort();
            s->p = q; s->n = n ? n : 1;
            memset(s->p, s->tag, s->n);
        }
        else if (s->p)
        {
            tb_allocator_free(a, s->p);
            s->p = tb_null; s->n = 0;
        }
    }
    for (int k = 0; k < SLOTS; k++) if (slots[k].p) tb_allocator_free(a, slots[k].p);
    tb_allocator_exit(a);
    return 0;
}
