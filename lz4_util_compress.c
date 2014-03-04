#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "lz4/lz4.h"
#include "lz4/lz4hc.h"

int main(int argc, char *argv[])
{
    size_t input_size, output_size;
    void *input_buffer, *output_buffer;
    FILE *fpi, *fpo;

    if ( argc != 3 )
    {
        fprintf(stderr, "Usage: %s <input> <output>\n", argv[0]);
        return 1;
    }

    fpi = fopen(argv[1], "r");
    if ( !fpi )
    {
        fprintf(stderr, "fopen: %s\n", strerror(errno));
        return 1;
    }

    fseek(fpi, 0, SEEK_END); input_size = ftell(fpi); fseek(fpi, 0, SEEK_SET);

    input_buffer = malloc(input_size);
    output_buffer = malloc(input_size);
    if ( !input_size || !output_buffer )
    {
        fprintf(stderr, "malloc: %s\n", strerror(errno));
        return 1;
    }

    if ( fread(input_buffer, 1, input_size, fpi) != input_size )
    {
        fprintf(stderr, "fread: %s\n", strerror(errno));
        return 1;
    }
    fclose(fpi);

    if ( !strstr(argv[0], "lz4hc") )
        output_size = LZ4_compress(input_buffer, output_buffer, input_size);
    else
        output_size = LZ4_compressHC2(input_buffer, output_buffer, input_size, 16);

    if ( output_size == 0 )
    {
        fprintf(stderr, "LZ4_compress error\n");
        return 1;
    }    

    fpo = fopen(argv[2], "w");
    if ( !fpo )
    {
        fprintf(stderr, "fopen: %s\n", strerror(errno));
        return 1;
    }

    printf("File reduced to %d bytes (%d before).\n", output_size, input_size);
    if ( fwrite(output_buffer, 1, output_size, fpo) != output_size )
    {
        fprintf(stderr, "fwrite: %s\n", strerror(errno));
        return 1;
    }
    fclose(fpo);

    if ( 0 ) 
    {
        void *tmp_buffer = malloc(input_size);
        printf("Decompressed back to %d bytes\n", LZ4_decompress_safe(output_buffer, tmp_buffer, output_size, input_size));
        printf("memcmp = %d\n", memcmp(tmp_buffer, input_buffer, input_size));
    }

    return 0;
}
