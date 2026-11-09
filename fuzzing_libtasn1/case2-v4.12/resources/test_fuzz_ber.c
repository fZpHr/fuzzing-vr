#include <stdint.h>
#include <stddef.h>
#include <libtasn1.h>
#include <stdlib.h> 


int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > 2147483647)        
        return 0;
    unsigned char *str = NULL;
    unsigned int str_len = 0;
    if (!asn1_decode_simple_ber(ASN1_ETYPE_OCTET_STRING, data, (unsigned int)size, &str, &str_len, NULL))
        free(str);

    return 0;
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
