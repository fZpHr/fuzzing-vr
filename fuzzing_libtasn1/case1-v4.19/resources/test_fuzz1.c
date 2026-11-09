#include <stdint.h>
#include <stddef.h>
#include <libtasn1.h>


int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 2147483647)
        return 0;
    int len;
    asn1_get_length_der(data, (int)size, &len);
    return 0;
}