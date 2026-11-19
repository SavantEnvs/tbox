/* Set-Cookie parsing and cookie matching: input = "<url>\n<Set-Cookie value>[\n<lookup url>]".
 * Each input gets its own cookie jar (tb_cookies_init/exit), so nothing carries over. */
#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(uint8_t const* data, size_t size)
{
    char* buf = fuzz_cstr(data, size);
    char* url = buf;
    char* value = strchr(buf, '\n');
    if (!value) { free(buf); return -1; }
    *value++ = '\0';
    char* lookup = strchr(value, '\n');
    if (lookup) *lookup++ = '\0';
    else lookup = url;

    tb_cookies_ref_t cookies = tb_cookies_init();
    if (cookies)
    {
        tb_cookies_set_from_url(cookies, url, value);
        tb_string_t v;
        if (tb_string_init(&v))
        {
            tb_cookies_get_from_url(cookies, url, &v);
            tb_string_clear(&v);
            tb_cookies_get_from_url(cookies, lookup, &v);
            tb_string_exit(&v);
        }
        tb_cookies_exit(cookies);
    }
    free(buf);
    return 0;
}
