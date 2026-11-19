/* tb_charset_conv_data between every charset pair (incl. LE/BE), into an ample and a tight buffer.
 * Bytes 0-1 select from/to charsets, byte 2 the tight output size; the rest is the text. */
#include "fuzz_common.h"

static tb_size_t charset_of(uint8_t b)
{
    static tb_size_t const types[] = {
        TB_CHARSET_TYPE_ASCII, TB_CHARSET_TYPE_GB2312, TB_CHARSET_TYPE_GBK, TB_CHARSET_TYPE_ISO8859,
        TB_CHARSET_TYPE_UCS2, TB_CHARSET_TYPE_UCS4, TB_CHARSET_TYPE_UTF16, TB_CHARSET_TYPE_UTF32,
        TB_CHARSET_TYPE_UTF8
    };
    return types[(b & 0x7f) % tb_arrayn(types)] | ((b & 0x80) ? TB_CHARSET_TYPE_LE : TB_CHARSET_TYPE_BE);
}

int LLVMFuzzerTestOneInput(uint8_t const* data, size_t size)
{
    if (size < 3) return -1;
    tb_size_t ft = charset_of(data[0]), tt = charset_of(data[1]);
    tb_size_t tight = data[2];
    data += 3; size -= 3;

    /* exact-size heap buffers so ASan catches any write past osize */
    tb_size_t big = size * 4 + 16;
    tb_byte_t* out = (tb_byte_t*)malloc(big);
    if (!out) return 0;
    tb_charset_conv_data(ft, tt, (tb_byte_t const*)data, (tb_size_t)size, out, big);
    free(out);

    out = (tb_byte_t*)malloc(tight ? tight : 1);
    if (!out) return 0;
    tb_charset_conv_data(ft, tt, (tb_byte_t const*)data, (tb_size_t)size, out, tight);
    free(out);
    return 0;
}
