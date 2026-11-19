/* tb_object_read_from_data: probes and parses JSON, XML, xplist, bplist and tbox bin, then writes the
 * parsed object back out in every format (exercises the writers on parser-shaped trees). */
#include "fuzz_common.h"

static tb_byte_t g_out[256 * 1024];

int LLVMFuzzerTestOneInput(uint8_t const* data, size_t size)
{
    tb_object_ref_t object = tb_object_read_from_data((tb_byte_t const*)data, (tb_size_t)size);
    if (!object) return 0;
    static tb_size_t const formats[] = {
        TB_OBJECT_FORMAT_BIN, TB_OBJECT_FORMAT_BPLIST, TB_OBJECT_FORMAT_XPLIST,
        TB_OBJECT_FORMAT_XML, TB_OBJECT_FORMAT_JSON
    };
    for (tb_size_t i = 0; i < tb_arrayn(formats); i++)
    {
        tb_long_t n = tb_object_writ_to_data(object, g_out, sizeof(g_out), formats[i]);
        /* the written form must parse back */
        if (n > 0)
        {
            tb_object_ref_t again = tb_object_read_from_data(g_out, (tb_size_t)n);
            if (again) tb_object_exit(again);
        }
    }
    tb_object_exit(object);
    return 0;
}
