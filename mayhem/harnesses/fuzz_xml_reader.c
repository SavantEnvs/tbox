/* tb_xml_reader over a data stream: the DOM loader (tb_xml_reader_load) followed by the pull API
 * (tb_xml_reader_next + getters) on a fresh reader, and the loaded tree re-serialised by the writer. */
#include "fuzz_common.h"

static void pull(uint8_t const* data, size_t size)
{
    tb_xml_reader_ref_t reader = tb_xml_reader_init();
    if (!reader) return;
    tb_stream_ref_t stream = tb_stream_init_from_data((tb_byte_t const*)data, (tb_size_t)size);
    if (stream && tb_xml_reader_open(reader, stream, tb_true))
    {
        tb_size_t event;
        volatile tb_size_t sink = 0;
        while ((event = tb_xml_reader_next(reader)))
        {
            tb_char_t const* s = tb_null;
            switch (event)
            {
            case TB_XML_READER_EVENT_DOCUMENT:      s = tb_xml_reader_version(reader); tb_xml_reader_charset(reader); break;
            case TB_XML_READER_EVENT_DOCUMENT_TYPE: s = tb_xml_reader_doctype(reader); break;
            case TB_XML_READER_EVENT_ELEMENT_EMPTY:
            case TB_XML_READER_EVENT_ELEMENT_BEG:
            {
                s = tb_xml_reader_element(reader);
                tb_xml_node_ref_t attr = tb_xml_reader_attributes(reader);
                for (; attr; attr = attr->next) sink += tb_string_size(&attr->name) + tb_string_size(&attr->data);
                break;
            }
            case TB_XML_READER_EVENT_ELEMENT_END:   s = tb_xml_reader_element(reader); break;
            case TB_XML_READER_EVENT_TEXT:          s = tb_xml_reader_text(reader); break;
            case TB_XML_READER_EVENT_CDATA:         s = tb_xml_reader_cdata(reader); break;
            case TB_XML_READER_EVENT_COMMENT:       s = tb_xml_reader_comment(reader); break;
            default: break;
            }
            if (s) sink += tb_strlen(s);
            sink += tb_xml_reader_level(reader);
        }
        (void)sink;
    }
    else if (stream) tb_stream_exit(stream);
    tb_xml_reader_exit(reader);
}

int LLVMFuzzerTestOneInput(uint8_t const* data, size_t size)
{
    tb_xml_reader_ref_t reader = tb_xml_reader_init();
    if (!reader) return 0;
    tb_stream_ref_t stream = tb_stream_init_from_data((tb_byte_t const*)data, (tb_size_t)size);
    if (stream && tb_xml_reader_open(reader, stream, tb_true))
    {
        tb_xml_node_ref_t root = tb_xml_reader_load(reader);
        if (root)
        {
            tb_buffer_t out;
            if (tb_buffer_init(&out))
            {
                tb_stream_ref_t ostream = tb_stream_init_from_buffer(&out);
                tb_xml_writer_ref_t writer = tb_xml_writer_init();
                if (ostream && writer && tb_xml_writer_open(writer, tb_true, ostream, tb_true))
                {
                    tb_xml_writer_save(writer, root);
                    ostream = tb_null;
                }
                if (writer) tb_xml_writer_exit(writer);
                if (ostream) tb_stream_exit(ostream);
                tb_buffer_exit(&out);
            }
            tb_xml_node_exit(root);
        }
    }
    else if (stream) tb_stream_exit(stream);
    tb_xml_reader_exit(reader);

    pull(data, size);
    return 0;
}
