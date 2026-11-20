#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <libtasn1.h>

size_t LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize);

size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size, size_t MaxSize, unsigned int Seed) {
    size_t new_size = LLVMFuzzerMutate(Data, Size, MaxSize);
    if (new_size < 4) 
        return 0;

    size_t i = 0;
    while (i + 4 <= new_size) {
        Data[i]     = 0x24;
        Data[i + 1] = 0x80;
        i += 2;
    }
    Data[i]     = 0x04;
    Data[i + 1] = 0x00;
    return i + 2;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4 || size > 2147483647)
        return 0;

    unsigned char *str = NULL;
    unsigned int str_len = 0;

    if (!asn1_decode_simple_ber(ASN1_ETYPE_OCTET_STRING, data, (unsigned int)size, &str, &str_len, NULL))
        free(str);

    return 0;
}
