#include <sys/mman.h>
#include "elf_map.h"
#include "syscalls.h"
#include "string.h"

#include "lz4/lz4.h"
#include "lz4/lz4hc.h"

typedef int (* entrypoint)(int, char **);

static inline int map_segment(struct elf_segment *segm)
{
    void *segment_base;
    size_t segment_size = ROUND_PAGE(segm->size);

    segment_base = (void *) sys_mmap(
        (void *)(segm->address), 
        segment_size, 
        PROT_READ | PROT_WRITE, 
        MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);

    if ( segment_base != (void *)(segm->address) )
        return 1;

    if ( segm->compressed )
    {
        if ( !LZ4_decompress_safe((char *)(segm->data), segment_base, segm->data_size, segment_size) )
            return 1;
    }
    else
        _memcpy(segment_base, segm->data, segm->data_size);

    if ( sys_mprotect(segment_base, segment_size, segm->prot) != 0 )
        return 1;

    return 0;
}

static int exec_elf_program(int argc, char *argv[], struct elf_memory_map *map)
{
    int i;
    entrypoint entry = (entrypoint)(map->entry);

    for ( i = 0; i < map->nr_segments; i++ )
    {
        if ( map_segment(&map->entries[i]) )
            return 1;
    }

    return entry(argc, argv);
}

typedef int (* entrypoint)(int, char**);
int main(int argc, char *argv[])
{
    return exec_elf_program(argc, argv, &memory_map);
}

_Noreturn void _start(int argc, char *argv[])
{
    sys_exit(main(argc, argv));
}
