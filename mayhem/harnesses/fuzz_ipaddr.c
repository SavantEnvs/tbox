/* IPv4 / IPv6 / unix address and MAC address parsing (tb_ipaddr_ip_cstr_set, tb_hwaddr_cstr_set) and
 * their string formatting. Byte 0 selects the requested family. */
#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(uint8_t const* data, size_t size)
{
    if (size < 1) return -1;
    static tb_uint8_t const families[] = {
        TB_IPADDR_FAMILY_NONE, TB_IPADDR_FAMILY_IPV4, TB_IPADDR_FAMILY_IPV6, TB_IPADDR_FAMILY_NONE
    };
    tb_uint8_t family = families[data[0] & 3];
    char* s = fuzz_cstr(data + 1, size - 1);
    tb_char_t buf[TB_IPADDR_CSTR_MAXN];

    tb_ipaddr_t addr;
    tb_ipaddr_clear(&addr);
    if (tb_ipaddr_ip_cstr_set(&addr, s, family))
    {
        tb_ipaddr_port_set(&addr, (tb_uint16_t)(data[0] << 4));
        tb_ipaddr_cstr(&addr, buf, sizeof(buf));
        tb_ipaddr_ip_cstr(&addr, buf, sizeof(buf));
    }
    tb_ipaddr_clear(&addr);
    if (tb_ipaddr_unix_set_cstr(&addr, s, (data[0] & 4) != 0))
        tb_ipaddr_cstr(&addr, buf, sizeof(buf));

    tb_hwaddr_t hw;
    tb_hwaddr_clear(&hw);
    tb_char_t hbuf[TB_HWADDR_CSTR_MAXN];
    if (tb_hwaddr_cstr_set(&hw, s)) tb_hwaddr_cstr(&hw, hbuf, sizeof(hbuf));

    free(s);
    return 0;
}
