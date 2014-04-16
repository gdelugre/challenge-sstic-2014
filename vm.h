#ifndef __H_VM
#define __H_VM

#ifdef DEBUG
#include <stdio.h>
#endif

#include <stdint.h>
#include "chacha.h"
#include "syscalls.h"
#include "string.h"

__attribute__((noinline)) 
static void _vm_print(char *msg, size_t size)
{
    sys_write(2, msg, size);
}

__attribute__((noinline)) 
static void vm_println (char *msg)
{
    size_t length = 0;
    while ( msg[length] != '\n' && msg[length] != '\0' )
        length++;

    _vm_print(msg, length);
    _vm_print("\n", 1);
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
#else
#define vm_print(...)
#define printf(...)
//#define vm_hexdump(addr, size)
__attribute__((noinline)) 
static void vm_hexdump(const void *addr, size_t size)
{
    static char digits[3];
    static const char table[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
    unsigned char c;
    int i;
    
    for ( i = 0; i < size; i++ )
    {
        c = ((unsigned char *)addr)[i];
        digits[0] = table[(c >> 4) & 0xf];
        digits[1] = table[c & 0xf];
        digits[2] = ' ';

        _vm_print(digits, sizeof(digits));
        if ( i % 16 == 15 )
        {
            digits[0] = '\n';
            _vm_print(&digits, 1);
        }
    }
    digits[0] = '\n';
    _vm_print(&digits, 1);
}
#endif

#define MIN(X,Y) ((X) < (Y) ? (X) : (Y))

typedef unsigned long vm_time_t;
typedef unsigned long vm_page_t;
typedef unsigned long vm_off_t;
typedef unsigned long vm_addr_t;

typedef uint32_t vm_word_t;
typedef int32_t vm_sword_t;
typedef vm_word_t vm_reg_t;

/* N = 13, TAPS = 13, 12, 10, 9 */
//#define POLY_SIZE 13UL
//#define POLY_SHUFFLER ((1<<12)+(1<<10)+(1<<9)+1)

/* N = 10, TAPS = 9, 7, 6 */
#define POLY_SIZE 10UL
#define POLY_SHUFFLER ((1<<9)+(1<<7)+(1<<6)+1)

#define VM_INVALID_ADDR ((vm_addr_t) -1)

#define VM_PAGE_SHIFT 6UL
#define VM_OFFSET_MASK ((1UL << VM_PAGE_SHIFT) - 1)
#define VM_PAGE_MASK ((1UL << POLY_SIZE) - 1)
#define VM_PAGE_SIZE (1UL << VM_PAGE_SHIFT)
#define VM_PAGE_ALIGN(addr) (addr & ~VM_OFFSET_MASK)
#define VM_PAGE(addr) ((vm_page_t) (addr >> VM_PAGE_SHIFT))
#define VM_PAGE_OFFSET(addr) ((vm_off_t) (addr & VM_OFFSET_MASK))

#define VM_MIN_ADDR ((vm_addr_t) 0UL)
#define VM_MAX_ADDR ((vm_addr_t) ((1UL << POLY_SIZE) << VM_PAGE_SHIFT) - 1)

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
    //return (parity(vpage & POLY_SHUFFLER) << (POLY_SIZE-1)) ^ (vpage >> 1);
    return vpage;
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

#define VM_NR_REGISTERS 16
#define VM_STACK_REGISTER 14
#define VM_LINK_REGISTER 15
#define VM_REGISTER_SIZE sizeof(vm_reg_t)

typedef struct {
    struct {
        vm_reg_t r1;
        vm_reg_t r2;
        vm_reg_t r3;
        vm_reg_t r4;
        vm_reg_t r5;
        vm_reg_t r6;
        vm_reg_t r7;
        vm_reg_t r8;
        vm_reg_t r9;
        vm_reg_t r10;
        vm_reg_t r11;
        vm_reg_t r12;
        vm_reg_t r13;
        vm_reg_t r14;
        vm_reg_t r15;
        vm_reg_t ip;
    } ctx;
} vm_memory;

struct _vm_state;
typedef unsigned char vm_opcode_t;

typedef struct __attribute__((packed)) {
    union {
        /* [mov, or] Rd, imm16 << shift */
        struct {
            unsigned opcode: 8;
            unsigned rd: 4;
            unsigned imm: 16;
            unsigned sbz: 4;
        } mov_or_imm16;

        /* ld, ldh, ldb, st, sth, stb Rd, [Rs,off] */
        struct {
            unsigned opcode: 8;
            unsigned rd: 4;
            unsigned rs: 4;
            unsigned off: 16;
        } mem;

        /* bcc Rc, dest */
        struct {
            unsigned opcode: 8;
            unsigned link: 1;
            unsigned rc: 4;
            unsigned cond: 3;
            unsigned dest: 16;
        } bcc;

        /* [not, inc, dec, push, pop] Rd */
        struct {
            unsigned opcode: 8;
            unsigned rd: 4;
            unsigned sbz: 4;
        } un;

        /* [xor, or, and, add, sub, mul, div, lsl, asr, lsr, rol, ror] Rd, Rs*/
        struct {
            unsigned opcode: 8;
            unsigned rd: 4;
            unsigned rs: 4;
        } bin;

        /* syscall, ret, nop, hlt */
        struct {
            unsigned opcode : 8;
            unsigned sbz: 8;
        } noarg;

        unsigned int i;
    };
} vm_insn_t;

enum {
    VM_COND_ALWAYS,
    VM_COND_NEVER,
    VM_COND_EQZ,
    VM_COND_NEQZ,
    VM_COND_LTZ,
    VM_COND_GTZ,
    VM_COND_LTEZ,
    VM_COND_GTEZ,
} VM_COND;

typedef void (*vm_opcode_handler)(struct _vm_state *, vm_insn_t);
enum {
    VM_OP_MOV_IMM16,
    VM_OP_OR_IMM16,
    VM_OP_LDR,
    VM_OP_LDRH,
    VM_OP_LDRB,
    VM_OP_STR,
    VM_OP_STRH,
    VM_OP_STRB,
    VM_OP_BCC,

    VM_OP_NOT,
    VM_OP_XOR,
    VM_OP_OR,
    VM_OP_AND,
    VM_OP_LSL,
    VM_OP_LSR,
    VM_OP_ASR,
    VM_OP_ROL,
    VM_OP_ROR,

    VM_OP_ADD,
    VM_OP_SUB,
    VM_OP_MUL,
    VM_OP_DIV,

    VM_OP_INC,
    VM_OP_DEC,
    VM_OP_PUSH,
    VM_OP_POP,

    VM_OP_RET,
    VM_OP_NOP,
    VM_OP_HLT,
    VM_OP_SYS,

    VM_OP_PAR,

    __NR_VM_OPCODES
} VM_OPCODE;

enum {
    VM_SYS_OPEN,
    VM_SYS_READ,
    VM_SYS_WRITE,
    VM_SYS_CLOSE,
} VM_SYSCALL;

typedef struct _vm_state {
    struct {
        unsigned int running:1;
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
    VM_STATUS_OUT_OF_MEMORY,
    VM_STATUS_DIV_BY_ZERO,
} VM_STATUS;

int vm_initialize(vm_memory *, size_t, vm_state **);
int vm_start(vm_state *);
void vm_stop(vm_state *, int);

vm_reg_t vm_get_register(vm_state *, int);
void vm_set_register(vm_state *, int, vm_reg_t);
vm_addr_t vm_current_instruction_pointer(vm_state *);
void vm_set_instruction_pointer(vm_state *, vm_reg_t);

int vm_read(vm_state *, vm_addr_t, void *, size_t);
int vm_write(vm_state *, vm_addr_t, void *, size_t);
int vm_read_string(vm_state *, vm_addr_t, char *, size_t);
int vm_read_word(vm_state *, vm_addr_t, vm_word_t *);
int vm_write_word(vm_state *, vm_addr_t, vm_word_t);

#endif
