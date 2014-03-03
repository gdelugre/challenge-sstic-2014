#ifndef _H_STRING
#define _H_STRING

static inline void _memcpy(void *dst, void *src, size_t len)
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

#endif
