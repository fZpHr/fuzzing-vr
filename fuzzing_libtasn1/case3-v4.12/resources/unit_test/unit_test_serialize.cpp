#include "../ber.pb.h"
#include <string>
#include <cstdio>

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

int main() {
    BerNode root;
    root.set_tag(0x24);

    BerNode *child = root.mutable_constructed()->add_children();
    child->set_tag(0x24);
    BerNode *childofchild = child->mutable_constructed()->add_children();
    childofchild->set_tag(0x04);
    childofchild->set_leaf("okokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokokok");
    std::string out;
    serialize(root, out);
    for (unsigned char c : out) printf("%02X ", c);
    printf("\n");
}