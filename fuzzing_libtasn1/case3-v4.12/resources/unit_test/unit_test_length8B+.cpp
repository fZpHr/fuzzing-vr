#include <string>
#include <cstdio>
#include <cstddef>


static void write_length(std::string &out, size_t n) {
    if (n <= 127) { 
        out.push_back((char)n);
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
    }
}

static void show(size_t n) {
    std::string out;
    write_length(out, n);
    printf("n=%-6ld -> ", n);
    for (unsigned char c : out) printf("%02X ", c);
    printf("\n");
}

int main() {
    show(3);
    show(127);
    show(128);
    show(200);
    show(300);
    show(65535);
}