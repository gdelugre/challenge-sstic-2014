#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "chacha.h"

static uint8_t memory_key[] = "\x0b\xad\xb1\x05\x0b\xad\xb1\x05\x0b\xad\xb1\x05\x0b\xad\xb1\x05";
static uint8_t memory_iv[] = "\x00\x00\x00\x00\x00\x00\x00\x00";

#define POLY_SHUFFLER ((1<<12)+(1<<10)+(1<<9)+1)

static inline unsigned long parity(unsigned long n)
{
    n ^= (n >> 32UL);
    n ^= (n >> 16UL);
    n ^= (n >> 8UL);
    n ^= (n >> 4UL);    
    return (0x6996 >> (n & 0xfUL)) & 1;
}

static inline unsigned long shuffle(unsigned long page)
{
    return (parity(page & POLY_SHUFFLER) << 12) ^ (page >> 1);
}

static void hexdump(const unsigned char *addr, size_t size)
{
    int i;
    for ( i = 0; i < size; i++ )
    {
        printf("%02x ", addr[i]); 
        if ( i % 16 == 15 )
            printf("\n");
    } 
    printf("\n");
}
int main(int argc, char *argv[])
{
    ECRYPT_ctx ctx;
    void *buffer, *shuffled;
    size_t buffer_size;
    FILE *fp;

    if ( argc < 2 )
        return 1;

    fp = fopen(argv[1], "r");
    if ( !fp )
        return 1;

    fseek(fp, 0, SEEK_END);
    buffer_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if ( buffer_size != 8192 * 64 )
    {
        printf("Bad file size.\n");
        return 1;
    }

    buffer = malloc(buffer_size);
    shuffled = malloc(buffer_size);

    if ( !buffer || !shuffled )
        return 1;

    fread(buffer, 1, buffer_size, fp);
    fclose(fp);

    ECRYPT_init();
    ECRYPT_keysetup(&ctx, memory_key, 128, 0);
    ECRYPT_ivsetup(&ctx, memory_iv);

    ECRYPT_encrypt_bytes(&ctx, buffer, buffer, buffer_size);

    int i;
    for ( i = 0; i < 8192; i += 1 )
        memcpy(shuffled + shuffle(i) * 64, buffer + i * 64, 64);

    fp = fopen(argv[1], "w");
    if ( !fp )
        return 1;

    fwrite(shuffled, 1, buffer_size, fp);
    fclose(fp);

    return 0;
}

