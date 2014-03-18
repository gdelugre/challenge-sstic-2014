#ifndef _H_STDLIB
#define _H_STDLIB

#include <sys/mman.h>
#include <stddef.h>
#include "syscalls.h"
#include "string.h"

extern char **environ;

static inline void *_malloc(size_t size)
{
    void *buffer;

    buffer = (void *) sys_mmap(NULL, ROUND_PAGE(size), PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
    if ( buffer == MAP_FAILED )
        return NULL;

    return buffer;
}

static inline void _free(void *ptr, size_t size)
{
    sys_munmap(ptr, size);
}

static inline char *_getenv(const char *name)
{
    int i; 
    size_t name_len = _strlen(name);

    if ( !environ )
        return NULL;

    for ( i = 0; environ[i] != NULL; i++ )
    {
        //vm_println(environ[i]);
        if ( !_strncmp(environ[i], name, name_len) && environ[i][name_len] == '=' )
            return &(environ[i][name_len+1]);
    }

    return NULL;
}

static inline char *_strstr(const char *haystack, const char *needle)
{
    size_t needle_len = _strlen(needle);
    size_t haystack_len = _strlen(haystack);
    char *result, *current = (char *) haystack;

    while ( haystack_len >= needle_len )
    {
        if ( !_strncmp(current, needle, needle_len) )
        {
            result = current;
            break;
        }

        current++;
        haystack_len--;
    }

    return result;
}

#endif

