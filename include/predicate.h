#ifndef __H_PREDICATE
#define __H_PREDICATE

register void *g_predicate asm ("x28");

#define PREDICATE_CHECK(vstate) \
    g_predicate = vstate

#endif
