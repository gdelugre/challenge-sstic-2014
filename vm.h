#ifndef __H_VM
#define __H_VM

#ifdef DEBUG
#include <stdio.h>
#endif

#include <stdint.h>
#include "chacha.h"
#include "syscalls.h"

static inline void _memcpy(void *dst, void *src, size_t len)
{
    int i;
    for ( i = 0; i < len; i++ )
        ((unsigned char *)dst)[i] = ((unsigned char *)src)[i];
}

static void _vm_print(char *msg, size_t size)
{
    sys_write(2, msg, size);
}

static void __attribute__((noinline)) vm_println (char *msg)
{
    size_t length = 0;
    while ( msg[length] != '\n' )
        length++;

    _vm_print(msg, length+1);
}

#ifdef DEBUG
#define vm_print(...) printf(__VA_ARGS__)
static void vm_hexdump(const void *addr, size_t size)
{
    int i;
    for ( i = 0; i < size; i++ )
    {
        printf("%02x ", ((unsigned char *)addr)[i]); 
        if ( i % 16 == 15 )
            printf("\n");
    } 
    printf("\n");
}

#define DBG_PRINT(msg) debug_write(msg "\n", sizeof(msg)+1)
#else
#define vm_print(...)
#define vm_hexdump(addr, size)
#endif

#define MIN(X,Y) ((X) < (Y) ? (X) : (Y))

#define PAGE_SHIFT 12UL
#define PAGE_SIZE (1UL << PAGE_SHIFT)
#define REQUIRED_PAGES(nr_bytes) ((nr_bytes + PAGE_SIZE - 1) >> PAGE_SHIFT)
#define ROUND_PAGE(nr_bytes) (REQUIRED_PAGES(nr_bytes) << PAGE_SHIFT)

typedef unsigned long vm_addr_t;
typedef unsigned long vm_page_t;
typedef unsigned long vm_off_t;
typedef unsigned long vm_time_t;
typedef uint64_t vm_reg_t;
typedef uint64_t vm_word_t;

#define VM_INVALID_ADDR ((vm_addr_t) -1)

#define VM_PAGE_SHIFT 6UL
#define VM_OFFSET_MASK ((1UL << VM_PAGE_SHIFT) - 1)
#define VM_PAGE_MASK ((1UL << 13UL) - 1)
#define VM_PAGE_SIZE (1UL << VM_PAGE_SHIFT)
#define VM_PAGE_ALIGN(addr) (addr & ~VM_OFFSET_MASK)
#define VM_PAGE(addr) ((vm_page_t) (addr >> VM_PAGE_SHIFT))
#define VM_PAGE_OFFSET(addr) ((vm_off_t) (addr & VM_OFFSET_MASK))

#define VM_MIN_ADDR ((vm_addr_t) 0UL)
#define VM_MAX_ADDR ((vm_addr_t) ((1UL << 13UL) << VM_PAGE_SHIFT) - 1)


#define POLY_SHUFFLER ((1<<12)+(1<<10)+(1<<9)+1)

static inline unsigned long parity(unsigned long n)
{
    n ^= (n >> 32UL);
    n ^= (n >> 16UL);
    n ^= (n >> 8UL);
    n ^= (n >> 4UL);    
    return (0x6996 >> (n & 0xfUL)) & 1;
}

static inline  unsigned long shuffle(vm_page_t vpage)
{
    return (parity(vpage & POLY_SHUFFLER) << 12) ^ (vpage >> 1);
}

#define VM_CACHE_SIZE 32
#define VM_CACHE_ENTRY(state, data) state->cache_entries[(((void *)data) - state->cache) >> VM_PAGE_SHIFT]

typedef struct {
    vm_time_t last_access;
    vm_page_t page;
    struct { 
        unsigned dirty:1;
        unsigned free:1;
    } flags;
} vm_cache_entry;

#define VM_NR_REGISTERS 8
#define VM_IP_REGISTER 7

typedef struct {
    struct {
        vm_reg_t r0;
        vm_reg_t r1;
        vm_reg_t r2;
        vm_reg_t r3;
        vm_reg_t r4;
        vm_reg_t r5;
        vm_reg_t r6;
        vm_addr_t ip;
    } ctx;
} vm_memory;

struct _vm_state;

/* 
 * VM instruction:
 *   [ opcode : 8 ], [ reg : 3 ], [ addr : 19 ], [ cond: 2]
 */
typedef struct __attribute__((packed)) {
    unsigned int opcode:8;
    unsigned int reg:3;
    unsigned int addr:19;
    unsigned int cond:2;
} vm_insn_t;

enum {
    VM_COND_ALWAYS,
    VM_COND_IS_EQUAL,
    VM_COND_IS_LOWER,
    VM_COND_IS_HIGHER
} VM_COND;

typedef void (*vm_opcode_handler)(struct _vm_state *, vm_insn_t);
enum {
    VM_OP_HALT,
    VM_OP_NONE,
    VM_OP_LDR, // Can be used for mov reg, reg
    VM_OP_STR, // Can be used for mov reg, reg
    VM_OP_MOV_IMM19,
    VM_OP_SHL,
    VM_OP_SHR,
    VM_OP_ADD,
    VM_OP_SUB,
    VM_OP_AND,
    VM_OP_OR,
    VM_OP_XOR,
    VM_OP_NOT,
    VM_OP_CMP,
    VM_OP_BR,
    VM_OP_PRINT,
    VM_OP_READLN,
    __NR_VM_OPCODES
} VM_OPCODE;

typedef struct _vm_state {
    struct {
        unsigned int running:1;
        unsigned int lower:1;
        unsigned int equal:1;
        unsigned int higher:1;
    } flags;

    int status;
    vm_time_t ticks;
    ECRYPT_ctx vmem_ctx;
    vm_memory *vmem;
    vm_cache_entry cache_entries[VM_CACHE_SIZE];
    void *cache;
    vm_opcode_handler handlers[__NR_VM_OPCODES];
} vm_state;

#define VM_INSTALL_HANDLER(vstate, opc, code) \
    vstate->handlers[opc] = ({ void op_handler(vm_state *state, vm_insn_t insn) { \
        code \
     }; &op_handler; })

enum {
    VM_STATUS_NO_ERROR = 0,
    VM_STATUS_BAD_IP,
    VM_STATUS_BAD_INSN,
    VM_STATUS_MEMORY_FAULT,
    VM_STATUS_INTERNAL_ERROR,
    VM_STATUS_INVALID_ARGUMENT,
} VM_STATUS;

int vm_initialize(vm_memory *, size_t, vm_state **);
int vm_start(vm_state *);

#endif
