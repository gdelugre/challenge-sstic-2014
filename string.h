#ifndef _H_STRING
#define _H_STRING

#include <stddef.h>

static inline void _memcpy(void *dst, const void *src, size_t len)
{
    int i;
    for ( i = 0; i < len; i++ )
        ((unsigned char *)dst)[i] = ((unsigned char *)src)[i];
}

static inline void _memset(void *dst, int c, size_t n)
{
    int i;
    for ( i = 0; i < n; i++ )
        ((unsigned char *)dst)[i] = c;
}

static inline size_t _strlen(const char *s)
{
    size_t length = 0;

    while ( s[length] )
        length++;

    return length;
}

static inline int _strcmp(const char *s1, const char *s2)
{
    int result = 0, i = 0; 

    while ( 1 )
    {
        if ( s1[i] == 0 && s2[i] == 0 )
            break;

        if ( s1[i] < s2[i] )
        {
            result = -1; break;
        }
        else if ( s1[i] > s2[i] )
        {
            result = 1; break;
        }

        i++;
    }

    return result;
}

static inline int _strncmp(const char *s1, const char *s2, size_t n)
{
    int result = 0, i = 0; 

    while ( i < n )
    {
        if ( s1[i] == 0 && s2[i] == 0 )
            break;

        if ( s1[i] < s2[i] )
        {
            result = -1; break;
        }
        else if ( s1[i] > s2[i] )
        {
            result = 1; break;
        }

        i++;
    }

    return result;
}

#endif
