#include <sys/mman.h>
#include "code_compressed.h"
#include "syscalls.h"
#include "string.h"

#include "lz4/lz4.h"
#include "lz4/lz4hc.h"

#ifndef SEGMENT_ADDR
#error "No base address specified."
#endif

#ifndef SEGMENT_SIZE
#error "No segment size specified."
#endif

#ifndef ENTRYPOINT
#error "No entry point specified."
#endif

typedef int (* entrypoint)(int, char**);

int main(int argc, char *argv[])
{
    entrypoint entry = (entrypoint) ENTRYPOINT;
    void *code_segment;
    size_t segment_size = ROUND_PAGE(SEGMENT_SIZE);

    code_segment = (void *) sys_mmap(
        (void *) SEGMENT_ADDR, 
        segment_size, 
        PROT_READ | PROT_WRITE, 
        MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);

    if ( code_segment != (void *) SEGMENT_ADDR )
        return 1;

    if ( !LZ4_decompress_safe((char *) code_compressed, code_segment, sizeof(code_compressed), segment_size) )
        return 1;

    if ( sys_mprotect(code_segment, segment_size, PROT_READ | PROT_EXEC) != 0 )
        return 1;

    return entry(argc, argv);
}

_Noreturn void _start(int argc, char *argv[])
{
    sys_exit(main(argc, argv));
}
