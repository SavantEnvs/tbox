/* URL parsing (tb_url_cstr_set: protocol, host / IPv4 / IPv6 literal, port, path, args, file paths)
 * and reformatting, plus the protocol prober. */
#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(uint8_t const* data, size_t size)
{
    char* s = fuzz_cstr(data, size);
    volatile tb_size_t sink = tb_url_protocol_probe(s);
    tb_url_t url;
    if (tb_url_init(&url))
    {
        if (tb_url_cstr_set(&url, s))
        {
            tb_char_t const* p;
            if ((p = tb_url_cstr(&url))) sink += tb_strlen(p);
            if ((p = tb_url_host(&url))) sink += tb_strlen(p);
            if ((p = tb_url_path(&url))) sink += tb_strlen(p);
            if ((p = tb_url_args(&url))) sink += tb_strlen(p);
            if ((p = tb_url_protocol_cstr(&url))) sink += tb_strlen(p);
            sink += tb_url_port(&url);
            tb_url_t copy;
            if (tb_url_init(&copy))
            {
                tb_url_copy(&copy, &url);
                if ((p = tb_url_cstr(&copy))) sink += tb_strlen(p);
                tb_url_exit(&copy);
            }
        }
        tb_url_exit(&url);
    }
    (void)sink;
    free(s);
    return 0;
}
