/* Stream filters over a data stream: HTTP chunked decoding, charset conversion and the cache filter.
 * Byte 0 selects the filter (and line vs block reads), bytes 1-2 the charsets; the rest is the stream. */
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
    uint8_t mode = data[0];
    tb_size_t fr = charset_of(data[1]), to = charset_of(data[2]);
    data += 3; size -= 3;

    tb_stream_ref_t base = tb_stream_init_from_data((tb_byte_t const*)data, (tb_size_t)size);
    if (!base) return 0;
    tb_stream_ref_t filter = tb_null;
    switch (mode % 3)
    {
    case 0: filter = tb_stream_init_filter_from_chunked(base, tb_true); break;
    case 1: filter = tb_stream_init_filter_from_charset(base, fr, to); break;
    default: filter = tb_stream_init_filter_from_cache(base, (mode >> 4) * 16); break;
    }
    if (filter && tb_stream_open(filter))
    {
        if (mode & 0x08)
        {
            tb_char_t line[512];
            while (tb_stream_bread_line(filter, line, sizeof(line)) >= 0) ;
        }
        else
        {
            tb_byte_t buf[1024];
            while (!tb_stream_beof(filter))
            {
                tb_long_t real = tb_stream_read(filter, buf, sizeof(buf));
                if (real > 0) continue;
                if (real < 0) break;
                real = tb_stream_wait(filter, TB_STREAM_WAIT_READ, tb_stream_timeout(filter));
                if (real <= 0 || !(real & TB_STREAM_WAIT_READ)) break;
            }
        }
    }
    if (filter) tb_stream_exit(filter);
    tb_stream_exit(base);
    return 0;
}
