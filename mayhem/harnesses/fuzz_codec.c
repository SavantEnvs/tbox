/* base64 / base32 / URL (and URL-args) decoders and encoders writing into caller buffers.
 * Byte 0 selects the codec and an output size; outputs are exact-size heap blocks so ASan sees any
 * write past the size the caller passed. Encoded data must decode back to the original. */
#include "fuzz_common.h"

int LLVMFuzzerTestOneInput(uint8_t const* data, size_t size)
{
    if (size < 1) return -1;
    uint8_t sel = data[0];
    tb_char_t const* in = (tb_char_t const*)(data + 1);
    tb_size_t n = (tb_size_t)(size - 1);
    tb_size_t on = (sel & 0x80) ? (n * 4 + 16) : (n / 2 + 1);
    tb_char_t* out = (tb_char_t*)malloc(on);
    if (!out) return 0;

    switch (sel & 7)
    {
    case 0: tb_base64_decode(in, n, (tb_byte_t*)out, on); break;
    case 1: tb_base32_decode((tb_byte_t const*)in, n, out, on); break;
    case 2: tb_url_decode(in, n, out, on); break;
    case 3: tb_url_decode2(in, n, out, on); break;
    case 4: tb_url_decode_args(in, n, out, on); break;
    case 5: tb_base64_encode((tb_byte_t const*)in, n, out, on); break;
    case 6: tb_base32_encode((tb_byte_t const*)in, n, out, on); break;
    default: tb_url_encode_args(in, n, out, on); break;
    }
    free(out);

    /* base64 round trip with ample buffers */
    tb_size_t en = n * 2 + 8;
    tb_char_t* enc = (tb_char_t*)malloc(en);
    tb_byte_t* dec = (tb_byte_t*)malloc(n + 8);
    if (enc && dec)
    {
        tb_size_t e = tb_base64_encode((tb_byte_t const*)in, n, enc, en);
        if (e)
        {
            tb_size_t d = tb_base64_decode(enc, e, dec, n + 8);
            if (d != n || (n && memcmp(dec, in, n))) abort();
        }
    }
    free(enc);
    free(dec);
    return 0;
}
