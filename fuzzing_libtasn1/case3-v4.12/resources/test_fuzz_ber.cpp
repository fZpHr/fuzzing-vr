#include "ber.pb.h"
#include <libtasn1.h>
#include <string>
#include <cstdio>
#include "libprotobuf-mutator/src/libfuzzer/libfuzzer_macro.h"

static long long depth = 0;
static long long max_depth = 0;

static void serialize(const BerNode &node, std::string &out) {
    ++depth;

    if (depth > max_depth)
        max_depth = depth;

    if (node.has_constructed()) {
        out.push_back(static_cast<char>(0x24));
        out.push_back(static_cast<char>(0x80));

        for (const BerNode &child : node.constructed().children())
            serialize(child, out);

        out.push_back(static_cast<char>(0x00));
        out.push_back(static_cast<char>(0x00));
    } else {
        out.push_back(static_cast<char>(0x04));

        const std::string &v = node.leaf();
        size_t n = v.size();

        if (n <= 127) {
            out.push_back(static_cast<char>(n));
            out.append(v);
        } else {
            unsigned char tmp[sizeof(size_t)];
            int num = 0;

            while (n > 0) {
                tmp[num++] = static_cast<unsigned char>(n & 0xFF);
                n >>= 8;
            }

            out.push_back(static_cast<char>(0x80 | num));

            for (int i = num - 1; i >= 0; --i)
                out.push_back(static_cast<char>(tmp[i]));

            out.append(v);
        }
    }

    --depth;
}

DEFINE_PROTO_FUZZER(const BerNode &node) {
    depth = 0;
    max_depth = 0;

    std::string ber;
    serialize(node, ber);

    fprintf(stderr,
            "protobuf_depth=%lld ber_size=%zu\n",
            max_depth,
            ber.size());

    unsigned char *str = nullptr;
    unsigned int str_len = 0;

    int ret = asn1_decode_simple_ber(
        ASN1_ETYPE_OCTET_STRING,
        reinterpret_cast<const unsigned char *>(ber.data()),
        static_cast<unsigned int>(ber.size()),
        &str,
        &str_len,
        nullptr
    );

    fprintf(stderr,
            "decode_ret=%d str_len=%u\n",
            ret,
            str_len);

    if (!ret)
        free(str);
}

/*-
 * _asn1_decode_simple_ber:
 * @etype: The type of the string to be encoded (ASN1_ETYPE_)
 * @der: the encoded string
 * @_der_len: the bytes of the encoded string
 * @str: a pointer to the data
 * @str_len: the length of the data
 * @ber_len: the total length occupied by BER (may be %NULL)
 * @have_tag: whether a DER tag is included
 *
 * Decodes a BER encoded type. The output is an allocated value 
 * of the data. This decodes BER STRINGS only. Other types are
 * decoded as DER.
 *
 * Returns: %ASN1_SUCCESS if successful or an error value.
 -*/
