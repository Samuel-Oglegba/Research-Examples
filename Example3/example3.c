#include <stdint.h>
#include <string.h>

#include "snmp-oid.h"

static uint8_t test_oid1[] = {0x06,0x08,0x2B,0x06,0x01,0x02,0x01,0x01,0x02,0x00};
static uint8_t test_oid2[] = {0x06,0x27,0x2B,0x06,
                                        0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
                                        0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,
                                        /*Buffer capacity limit*/
                                        0x86,0xE3,0xB1,0xCA,0xC8,0x86,0xE3,0xB1,0xCA,0xC8,
                                        0x86,0xE3,0xB1,0xCA,0xC8,0x86,0xE3,0xB1,0xCA,0xC8, 0x00};

static uint32_t test_oid1_len = sizeof(test_oid1);
static uint32_t test_oid2_len = sizeof(test_oid2);

void print_hex(char *data, size_t data_len)
{
    while(data_len--)
    {
        printf("%02hhX", *data++);
    }
    printf("\r\n");
}

int main(int argc, const char* argv[])
{
    uint8_t *ret;
    uint32_t oid1_len = 0;
    uint32_t oid2_len = 0;
    uint32_t oid1[SNMP_MSG_OID_MAX_LEN];
    uint32_t oid2[SNMP_MSG_OID_MAX_LEN];
    char text[] = "This is a very important stack variable.";


    printf("VALID OID:\r\n");
    ret = snmp_oid_decode_oid(test_oid1, &test_oid1_len, oid1, &oid1_len);
    printf("returned ptr = %p\r\n", ret);
    printf("Decoded oid length: %d\r\n", oid1_len);
    print_hex(text, sizeof(text));

    printf("BAD OID:\r\n");
    ret = snmp_oid_decode_oid(test_oid2, &test_oid2_len, oid2, &oid2_len);
    printf("returned ptr = %p\r\n", ret);
    printf("Decoded oid length: %d\r\n", oid2_len);
    print_hex(text, sizeof(text));

    return 0;
}