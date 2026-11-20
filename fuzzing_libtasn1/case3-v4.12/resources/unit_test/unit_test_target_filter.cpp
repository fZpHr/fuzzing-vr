#include "../ber.pb.h"
#include <libtasn1.h>
#include <string>
#include <cstdio>
#include <cstdlib>

static void serialize(const BerNode &node, std::string &out) {
    out.push_back((char)node.tag());
    if (node.has_constructed()) {
        out.push_back((char)0x80);
        for (const BerNode &child : node.constructed().children())
            serialize(child, out);
        out.push_back(0x00); out.push_back(0x00);
    } else {
        const std::string &v = node.leaf();
        size_t n = v.size();
        if (n <= 127) {
            out.push_back((char)n);
            out.append(v);
        }
        else {
            unsigned char tmp[sizeof(size_t)];
            int num = 0;
            while (n > 0) {
                tmp[num++] = (unsigned char)(n & 0xFF);
                n >>= 8;
            }
            out.push_back((char)(0x80 | num));
            for (int i = num - 1; i >= 0; i--)
                out.push_back((char)tmp[i]);
            out.append(v);
        }
    }
}

static void decode(const BerNode &node) {
    std::string out;
    serialize(node, out);
    for (unsigned char c : out) printf("%02X ", c);
    printf("\n");

    unsigned char *str = nullptr;
    unsigned int str_len = 0;
    int rc = asn1_decode_simple_ber(ASN1_ETYPE_OCTET_STRING,
            (const unsigned char *)out.data(), out.size(), &str, &str_len, nullptr);
    printf("rc = %d (%s)", rc, asn1_strerror(rc));
    if (rc == ASN1_SUCCESS) {
        printf(" -> %u bytes: ", str_len);
        for (unsigned i = 0; i < str_len; i++) printf("%c", str[i]);
        free(str);
    }
    printf("\n\n");
}

int main() {
    // feuille primitive 0x04
    BerNode leaf;
    leaf.set_tag(0x04);
    leaf.set_leaf("HELLO");
    decode(leaf);

    // construit 0x24 avec une feuille -> entre dans la recursion
    BerNode root;
    root.set_tag(0x24);
    BerNode *c = root.mutable_constructed()->add_children();
    c->set_tag(0x04);
    c->set_leaf("HELLO");
    decode(root);

    // imbrique 0x24 / 0x24 / 0x04
    BerNode nest;
    nest.set_tag(0x24);
    BerNode *mid = nest.mutable_constructed()->add_children();
    mid->set_tag(0x24);
    BerNode *in = mid->mutable_constructed()->add_children();
    in->set_tag(0x04);
    in->set_leaf("XY");
    decode(nest);

    // mauvais tag 0x30 -> rejete par le filtre (tag != 4)
    BerNode bad;
    bad.set_tag(0x30);
    bad.set_leaf("HELLO");
    decode(bad);
}
