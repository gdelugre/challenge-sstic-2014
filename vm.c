#include <stddef.h>
//#include <sys/mman.h>

#include "vm.h"
#include "stdlib.h"
#include "syscalls.h"
#include "chacha.h"

/*
 * Converts a VM address into a real address.
 * VM pages are 64-bytes long.
 */
static void *vm_address_translate(vm_state *state, vm_addr_t addr)
{
    vm_page_t vpage;
    vm_off_t voff;

    if ( addr > VM_MAX_ADDR )
        return NULL;

    vpage = VM_PAGE(addr);
    voff = VM_PAGE_OFFSET(addr);

    return (void *)(state->vmem) + (shuffle(vpage) << VM_PAGE_SHIFT) + voff;
}

static int vm_page_write(vm_state *state, vm_addr_t vaddr, void *buffer)
{
    void *data = vm_address_translate(state, VM_PAGE_ALIGN(vaddr));
    if ( !data )
        return 0;

    state->vmem_ctx.input[12] = VM_PAGE(vaddr);
    state->vmem_ctx.input[13] = (VM_PAGE(vaddr) >> 32UL);

    ECRYPT_encrypt_bytes(&state->vmem_ctx, buffer, data, VM_PAGE_SIZE);
    return VM_PAGE_SIZE;
}

static void *vm_cache_get_free_slot(vm_state *state, vm_page_t page)
{
    int i, lru = 0;
    vm_time_t oldest = -1;
    vm_cache_entry *lru_entry;

    /* Lookup for a free entry. */
    for ( i = 0; i < VM_CACHE_SIZE; i++ )
    {
        if ( state->cache_entries[i].flags.free )
        {
            state->cache_entries[i].flags.free = 0;
            state->cache_entries[i].flags.dirty = 0;
            state->cache_entries[i].page = page;
            state->cache_entries[i].last_access = state->ticks;
            
            return state->cache + VM_PAGE_SIZE * i;
        }

        /* Keep track of least recently used entry. */
        if ( state->cache_entries[i].last_access < oldest )
        {
            lru = i;
            oldest = state->cache_entries[i].last_access;
        }
    }

    /* No free entry available. Destroy the oldest entry. */
    lru_entry = &state->cache_entries[lru];

    /* Commit cache to memory if necessary. */
    if ( lru_entry->flags.dirty )
        vm_page_write(state, lru_entry->page << VM_PAGE_SHIFT, state->cache + lru * VM_PAGE_SIZE);

    lru_entry->flags.free = 0;
    lru_entry->flags.dirty = 0;
    lru_entry->page = page;
    lru_entry->last_access = state->ticks;

    return state->cache + lru * VM_PAGE_SIZE;
}

static void *vm_page_read(vm_state *state, vm_addr_t vaddr)
{
    void *data = vm_address_translate(state, VM_PAGE_ALIGN(vaddr));
    if ( !data )
        return 0;

    void *cache = vm_cache_get_free_slot(state, VM_PAGE(vaddr));

    //vm_print("memory: data:%p cache:%p\n", data, cache);
    state->vmem_ctx.input[12] = VM_PAGE(vaddr);
    state->vmem_ctx.input[13] = (VM_PAGE(vaddr) >> 32UL);

    //vm_hexdump(data, VM_PAGE_SIZE);
    ECRYPT_decrypt_bytes(&state->vmem_ctx, data, cache, VM_PAGE_SIZE);
    //vm_hexdump(cache, VM_PAGE_SIZE);

    return cache;
}

static void *vm_page_get_from_cache(vm_state *state, vm_page_t page)
{
    int i;

    for ( i = 0; i < VM_CACHE_SIZE; i++ )
    {
        if ( !state->cache_entries[i].flags.free && state->cache_entries[i].page == page )
        {
            state->cache_entries[i].last_access = state->ticks;
            return state->cache + i * VM_PAGE_SIZE;
        }
    }

    return NULL;
}

static void *vm_page_get(vm_state *state, vm_addr_t vaddr)
{
    void *cache = vm_page_get_from_cache(state, VM_PAGE(vaddr));

    if ( !cache )
    {
        //vm_print("memory: Cache miss for address %lx\n", vaddr);
        return vm_page_read(state, vaddr);
    }

    return cache;
}

static void vm_page_put(vm_state *state, void *page)
{
    VM_CACHE_ENTRY(state, page).flags.dirty = 1;
}

static int vm_read(vm_state *state, vm_addr_t vaddr, void *buffer, size_t size)
{
    void *page;
    long rem = size;
    size_t nr_read = 0, block_size;
    vm_off_t page_off;

    //vm_print("memory: Reading %ld bytes at address %lx\n", size, vaddr);
    while ( rem ) 
    {
        page = vm_page_get(state, vaddr);
        if ( page == NULL)
            break;

        block_size = MIN(rem, VM_PAGE_SIZE - VM_PAGE_OFFSET(vaddr));
        page_off = VM_PAGE_OFFSET(vaddr);

        _memcpy(buffer, page + page_off, block_size);
        nr_read += block_size;
        rem -= block_size; 

        buffer += block_size;
        vaddr += block_size;
    }

    return nr_read;
}

static int vm_write(vm_state *state, vm_addr_t vaddr, void *buffer, size_t size)
{
    void *page;
    long rem = size;
    size_t nr_written = 0, block_size;
    vm_off_t page_off;
    
    while ( rem )
    {
        page = vm_page_get(state, vaddr);
        if ( page == NULL )
            break;

        block_size = MIN(rem, VM_PAGE_SIZE - VM_PAGE_OFFSET(vaddr));
        page_off = VM_PAGE_OFFSET(vaddr);

        _memcpy(page + page_off, buffer, block_size);
        vm_page_put(state, page);

        nr_written += block_size;
        rem -= block_size;
        buffer += block_size;
        vaddr += block_size;
    }

    return nr_written;
}

void vm_stop(vm_state *state, int status)
{
    state->flags.running = 0;
    state->status = status;
}

static int vm_read_string(vm_state *state, vm_addr_t addr, char *buffer, size_t buffer_size)
{
    char *page;
    size_t rem_size, nr_read = 0;
    int eos = 0;
    char c;

    while ( nr_read < buffer_size && !eos )
    {
        page = (char *) vm_page_get(state, addr);
        if ( !page )
            return nr_read;

        rem_size = VM_PAGE_SIZE - VM_PAGE_OFFSET(addr);
        while ( nr_read < buffer_size && rem_size )
        {
            c = page[ VM_PAGE_OFFSET(addr) ];
            if ( c == '\0' )
            {
                *buffer = '\0';
                eos = 1;
                break;
            }

            *buffer++ = c;
            nr_read++;
            addr++;
            rem_size--;
        }

        vm_page_put(state, page);
    }

    return nr_read;
}

static int vm_read_word(vm_state *state, vm_addr_t addr, vm_word_t *word)
{
    if ( vm_read(state, addr, word, sizeof(*word)) != sizeof(*word) )
        return -1;

    return 0;
}

static int vm_write_word(vm_state *state, vm_addr_t addr, vm_word_t word)
{
    if ( vm_write(state, addr, &word, sizeof(word)) != sizeof(word) )
       return -1; 

    return 0;
}

static vm_reg_t vm_get_register(vm_state *state, int n)
{
    vm_reg_t reg;

    /* Should never happen. */
    if ( n > VM_NR_REGISTERS )
    {
        vm_stop(state, VM_STATUS_INTERNAL_ERROR);
        return -1;
    }

    if ( n == 0 )
        return 0;

    if ( vm_read_word(state, (n - 1) * sizeof(vm_reg_t), &reg) < 0 )
    {
        vm_stop(state, VM_STATUS_INTERNAL_ERROR);
        return -1;
    }

    return reg;
} 

static void vm_set_register(vm_state * state, int n, vm_reg_t value)
{
    /* Should never happen. */
    if ( n > VM_NR_REGISTERS )
    {
        vm_stop(state, VM_STATUS_INTERNAL_ERROR);
        return;
    }

    if ( n == 0 )
        return;

    if ( vm_write_word(state, (n - 1) * sizeof(vm_reg_t), value) < 0 )
    {
        vm_stop(state, VM_STATUS_INTERNAL_ERROR);
        return;
    }
}

static vm_addr_t vm_current_instruction_pointer(vm_state *state)
{
    vm_reg_t ip;

    if ( vm_read(state, offsetof(vm_memory, ctx.ip), &ip, sizeof(ip)) != sizeof(ip) )
        return VM_INVALID_ADDR;
    
    return (vm_addr_t) ip; 
}

static void vm_set_instruction_pointer(vm_state *state, vm_reg_t ip)
{
    if ( ip > VM_MAX_ADDR )
    {
        vm_stop(state, VM_STATUS_BAD_IP);
        return;
    }

    vm_write(state, offsetof(vm_memory, ctx.ip), &ip, sizeof(ip));
}

static size_t vm_insn_get_size(vm_opcode_t opcode)
{
    if ( opcode > __NR_VM_OPCODES )
        return 0;

    switch ( opcode )
    {
        case VM_OP_MOV_IMM16:
        case VM_OP_OR_IMM16:
        case VM_OP_LDR:
        case VM_OP_LDRH:
        case VM_OP_LDRB:
        case VM_OP_STR:
        case VM_OP_STRH:
        case VM_OP_STRB:
        case VM_OP_BCC:
            return 4;
        default:
            return 2;
    }
}

int vm_execute(vm_state *state)
{
    vm_addr_t ip;
    vm_insn_t insn;
    vm_opcode_t opcode;
    size_t insn_size;

    while ( state->flags.running )
    {
        ip = vm_current_instruction_pointer(state);
        if ( ip == VM_INVALID_ADDR )
        {
            vm_stop(state, VM_STATUS_BAD_IP);
            break;
        } 

        if ( vm_read(state, ip, &opcode, sizeof(opcode)) != sizeof(opcode) )
        {
            vm_stop(state, VM_STATUS_BAD_IP);
            break;
        }

        insn_size = vm_insn_get_size(opcode);
        if ( insn_size == 0 )
        {
            vm_stop(state, VM_STATUS_BAD_INSN);
            break;
        }

        insn.i = 0;
        if ( vm_read(state, ip, &insn, insn_size) != insn_size )
        {
            vm_stop(state, VM_STATUS_BAD_IP);
            break;
        }

        ip += insn_size;
        //vm_println("set ip");
        vm_set_instruction_pointer(state, ip);

        //vm_println("execute handler");
        //printf("opcode = %d\n", opcode);
        /* Execute the opcode handler. */
        state->handlers[opcode](state, insn);
    }

    return state->status;
}

static void vm_crash_report(vm_state *state)
{
    static char *status_msg[] =
    {
        [VM_STATUS_NO_ERROR] = "No error.\n",
        [VM_STATUS_BAD_IP] = "Bad instruction pointer.\n",
        [VM_STATUS_BAD_INSN] = "Invalid instruction.\n",
        [VM_STATUS_MEMORY_FAULT] = "Memory fault.\n",
        [VM_STATUS_INTERNAL_ERROR] = "Internal error.\n",
        [VM_STATUS_INVALID_ARGUMENT] = "Invalid argument.\n",
        [VM_STATUS_OUT_OF_MEMORY] = "Out of memory.\n",
    };

    vm_println(status_msg[state->status]);
}

/* Starts VM execution. */
int vm_start(vm_state *state)
{
    int status;

    state->flags.running = 1;
    status = vm_execute(state);

    if ( status != VM_STATUS_NO_ERROR )
        vm_crash_report(state);

    return status;
}

static int vm_initialize_cache(vm_state *vstate)
{
    int i;

    /* Initialize cache entries. */
    for ( i = 0; i < VM_CACHE_SIZE; i++ )
    {
        vstate->cache_entries[i].flags.free = 1;
        vstate->cache_entries[i].flags.dirty = 0;
        vstate->cache_entries[i].last_access = 0;
        vstate->cache_entries[i].page = (vm_page_t) 0;
    }

    /* Allocate VM memory cache. */
    vstate->cache = _malloc(VM_PAGE_SIZE * VM_CACHE_SIZE);
    if ( !vstate->cache )
        return -1;

    return 0;
}

static void vm_do_sys_open(vm_state *state)
{
    char filename[256];
    int flags, mode, fd;

    if ( !vm_read_string(state, vm_get_register(state, 2), filename, sizeof(filename)))
    {
        vm_stop(state, VM_STATUS_MEMORY_FAULT);
        return;
    }
    
    flags = vm_get_register(state, 3);
    mode = vm_get_register(state, 4);
    fd = sys_open(filename, flags, mode);
    //printf("fd = %x\n", fd);
    vm_set_register(state, 1, fd);
}

// R1 syscall_no, R2 fd, R3 buffer, R4 len, R1 result
static void vm_do_sys_read(vm_state *state)
{
    int fd, result;
    void *buffer;
    size_t buffer_size;
    vm_addr_t vaddr;

    fd = vm_get_register(state, 2);
    buffer_size = vm_get_register(state, 4);
    if ( !buffer_size )
    {
        vm_stop(state, VM_STATUS_INVALID_ARGUMENT);
        return;
    }

    buffer = _malloc(buffer_size);
    if ( !buffer )
    {
        vm_stop(state, VM_STATUS_OUT_OF_MEMORY);
        return;
    }

    result = sys_read(fd, buffer, buffer_size);
    vm_set_register(state, 1, result);

    vaddr = vm_get_register(state, 3);
    if ( vm_write(state, vaddr, buffer, buffer_size) != buffer_size )
    {
         vm_stop(state, VM_STATUS_MEMORY_FAULT);
         _free(buffer, buffer_size);
         sys_close(fd);
         return;
    }
    _free(buffer, buffer_size);
}

static void vm_do_sys_write(vm_state *state)
{
    int fd, result;
    void *buffer;
    size_t buffer_size;
    vm_addr_t vaddr;

    fd = vm_get_register(state, 2);
    //printf("sys_write to %x\n", fd);
    buffer_size = vm_get_register(state, 4); 
    if ( !buffer_size )
    {
        vm_stop(state, VM_STATUS_INVALID_ARGUMENT);
        return;
    }

    buffer = _malloc(buffer_size);
    if ( !buffer )
    {
        vm_stop(state, VM_STATUS_OUT_OF_MEMORY);
        return;
    }

    vaddr = vm_get_register(state, 3);
    if ( vm_read(state, vaddr, buffer, buffer_size) != buffer_size )
    {
        vm_stop(state, VM_STATUS_MEMORY_FAULT);
        _free(buffer, buffer_size);
        sys_close(fd);
    }

    result = sys_write(fd, buffer, buffer_size);
    vm_set_register(state, 1, result);
    _free(buffer, buffer_size);
}

static void vm_do_sys_close(vm_state *state)
{
    int result;

    result = sys_close(vm_get_register(state, 2));
    vm_set_register(state, 1, result);
}

static int vm_check_condition(unsigned int cond, vm_sword_t value)
{
    if ( cond == VM_COND_ALWAYS )
        return 1;

    if ( cond == VM_COND_NEVER )
        return 0;

    if ( cond == VM_COND_EQZ && value == 0 )
        return 1;

    if ( cond == VM_COND_NEQZ && value != 0 )
        return 1;

    if ( cond == VM_COND_LTZ && value < 0 )
        return 1;

    if ( cond == VM_COND_GTZ && value > 0 )
        return 1;

    if ( cond == VM_COND_LTEZ && value <= 0 )
        return 1;

    if ( cond == VM_COND_GTEZ && value >= 0 )
        return 1;

    return 0;
}

static void vm_initialize_handlers(vm_state *vstate)
{
    int i = 0;
    vm_opcode_handler default_handler = 
        ({ 
            void unknown_op_handler(vm_state *state, vm_insn_t insn) {
                vm_stop(state, VM_STATUS_BAD_INSN); 
            } &unknown_op_handler;
        });

    for ( i = 0; i < __NR_VM_OPCODES; i++ )
        vstate->handlers[i] = default_handler;

    VM_INSTALL_HANDLER(vstate, VM_OP_HLT, {
        vm_stop(state, VM_STATUS_NO_ERROR);
    });

    VM_INSTALL_HANDLER(vstate, VM_OP_NOP, {
    });

    VM_INSTALL_HANDLER(vstate, VM_OP_OR_IMM16, {
       vm_reg_t value = insn.mov_or_imm16.imm;
       vm_reg_t reg = vm_get_register(state, insn.mov_or_imm16.rd);
       vm_set_register(state, insn.mov_or_imm16.rd, reg | value);
    });

    VM_INSTALL_HANDLER(vstate, VM_OP_MOV_IMM16, {
       vm_reg_t value = insn.mov_or_imm16.imm << 16;
       vm_set_register(state, insn.mov_or_imm16.rd, value);
    });

    VM_INSTALL_HANDLER(vstate, VM_OP_RET, {
        vm_set_instruction_pointer(state, vm_get_register(state, VM_LINK_REGISTER));
    });

    VM_INSTALL_HANDLER(vstate, VM_OP_NOT, {
        vm_reg_t rd = vm_get_register(state, insn.un.rd);
        vm_set_register(state, insn.un.rd, ~rd);
    });

    VM_INSTALL_HANDLER(vstate, VM_OP_INC, {
        vm_reg_t rd = vm_get_register(state, insn.un.rd);
        vm_set_register(state, insn.un.rd, rd+1);
    });

    VM_INSTALL_HANDLER(vstate, VM_OP_DEC, {
        vm_reg_t rd = vm_get_register(state, insn.un.rd);
        vm_set_register(state, insn.un.rd, rd-1);
    });

    VM_INSTALL_HANDLER(vstate, VM_OP_XOR, {
        vm_reg_t rd = vm_get_register(state, insn.bin.rd); 
        vm_reg_t rs = vm_get_register(state, insn.bin.rs);
        vm_set_register(state, insn.bin.rd, rd ^ rs);
    });

    VM_INSTALL_HANDLER(vstate, VM_OP_OR, {
        vm_reg_t rd = vm_get_register(state, insn.bin.rd); 
        vm_reg_t rs = vm_get_register(state, insn.bin.rs);
        vm_set_register(state, insn.bin.rd, rd | rs);
    });

    VM_INSTALL_HANDLER(vstate, VM_OP_AND, {
        vm_reg_t rd = vm_get_register(state, insn.bin.rd); 
        vm_reg_t rs = vm_get_register(state, insn.bin.rs);
        vm_set_register(state, insn.bin.rd, rd & rs);
    });

    VM_INSTALL_HANDLER(vstate, VM_OP_LSL, {
        vm_reg_t rd = vm_get_register(state, insn.bin.rd); 
        vm_reg_t rs = vm_get_register(state, insn.bin.rs);
        vm_set_register(state, insn.bin.rd, rd << rs);
    });

    VM_INSTALL_HANDLER(vstate, VM_OP_LSR, {
        vm_reg_t rd = vm_get_register(state, insn.bin.rd); 
        vm_reg_t rs = vm_get_register(state, insn.bin.rs);
        vm_set_register(state, insn.bin.rd, rd >> rs);
    });

    VM_INSTALL_HANDLER(vstate, VM_OP_ASR, {
        vm_reg_t rd = vm_get_register(state, insn.bin.rd); 
        vm_reg_t rs = vm_get_register(state, insn.bin.rs);
        vm_set_register(state, insn.bin.rd, ((int32_t) rd) >> rs);
    });

    VM_INSTALL_HANDLER(vstate, VM_OP_ROL, {
        vm_reg_t rd = vm_get_register(state, insn.bin.rd); 
        vm_reg_t rs = vm_get_register(state, insn.bin.rs);
        vm_set_register(state, insn.bin.rd, (rd << rs) | (rd >> (VM_REGISTER_SIZE - (rs % VM_REGISTER_SIZE))));
    });

    VM_INSTALL_HANDLER(vstate, VM_OP_ROR, {
        vm_reg_t rd = vm_get_register(state, insn.bin.rd); 
        vm_reg_t rs = vm_get_register(state, insn.bin.rs);
        vm_set_register(state, insn.bin.rd, (rd >> rs) | (rd << (VM_REGISTER_SIZE - (rs % VM_REGISTER_SIZE))));
    });

    VM_INSTALL_HANDLER(vstate, VM_OP_ADD, {
        vm_reg_t rd = vm_get_register(state, insn.bin.rd); 
        vm_reg_t rs = vm_get_register(state, insn.bin.rs);
        vm_set_register(state, insn.bin.rd, rd + rs);
    });

    VM_INSTALL_HANDLER(vstate, VM_OP_SUB, {
        vm_reg_t rd = vm_get_register(state, insn.bin.rd); 
        vm_reg_t rs = vm_get_register(state, insn.bin.rs);
        vm_set_register(state, insn.bin.rd, rd - rs);
    });

    VM_INSTALL_HANDLER(vstate, VM_OP_MUL, {
        vm_reg_t rd = vm_get_register(state, insn.bin.rd); 
        vm_reg_t rs = vm_get_register(state, insn.bin.rs);
        vm_set_register(state, insn.bin.rd, rd * rs);
    });

    VM_INSTALL_HANDLER(vstate, VM_OP_DIV, {
        vm_reg_t rd = vm_get_register(state, insn.bin.rd); 
        vm_reg_t rs = vm_get_register(state, insn.bin.rs);

        if ( rs == 0 )
        {
            vm_stop(state, VM_STATUS_DIV_BY_ZERO);
            return;
        }
        vm_set_register(state, insn.bin.rd, rd / rs);
    });

    VM_INSTALL_HANDLER(vstate, VM_OP_PAR, {
        vm_reg_t v = vm_get_register(state, insn.bin.rs);
        v ^= v >> 1;
        v ^= v >> 2;
        v = (v & 0x11111111U) * 0x11111111U;
        v = (v >> 28) & 1; 
        vm_set_register(state, insn.bin.rd, v);
    });

    VM_INSTALL_HANDLER(vstate, VM_OP_PUSH, {
        vm_reg_t sp = vm_get_register(state, VM_STACK_REGISTER);
        vm_word_t value = vm_get_register(state, insn.un.rd);

        if ( vm_write_word(state, sp, value) < 0 )
        {
            vm_stop(state, VM_STATUS_MEMORY_FAULT);
            return;
        }
        
        vm_set_register(state, VM_STACK_REGISTER, sp - sizeof(vm_word_t));
    });

    VM_INSTALL_HANDLER(vstate, VM_OP_POP, {
        vm_reg_t sp = vm_get_register(state, VM_STACK_REGISTER);
        vm_word_t value;

        if ( vm_read_word(state, sp, &value) < 0 )
        {
            vm_stop(state, VM_STATUS_MEMORY_FAULT);
            return;
        }
        
        vm_set_register(state, insn.un.rd, value);
        vm_set_register(state, VM_STACK_REGISTER, sp + sizeof(vm_word_t));
    });

    VM_INSTALL_HANDLER(vstate, VM_OP_LDRB, {
        vm_word_t tmp_word = 0; 
        vm_addr_t base = vm_get_register(state, insn.mem.rs);
        vm_off_t offset = insn.mem.off;

        if ( vm_read(state, base + offset, &tmp_word, 1) != 1 )
        {
            vm_stop(state, VM_STATUS_MEMORY_FAULT);
            return;
        }
        vm_set_register(state, insn.mem.rd, tmp_word);
    });

    VM_INSTALL_HANDLER(vstate, VM_OP_LDRH, {
        vm_word_t tmp_word = 0; 
        vm_addr_t base = vm_get_register(state, insn.mem.rs);
        vm_off_t offset = insn.mem.off;

        if ( vm_read(state, base + offset, &tmp_word, 2) != 2 )
        {
            vm_stop(state, VM_STATUS_MEMORY_FAULT);
            return;
        }
        vm_set_register(state, insn.mem.rd, tmp_word);
    });

    VM_INSTALL_HANDLER(vstate, VM_OP_LDR, {
        vm_word_t tmp_word = 0; 
        vm_addr_t base = vm_get_register(state, insn.mem.rs);
        vm_off_t offset = insn.mem.off;

        if ( vm_read(state, base + offset, &tmp_word, 4) != 4 )
        {
            vm_stop(state, VM_STATUS_MEMORY_FAULT);
            return;
        }
        vm_set_register(state, insn.mem.rd, tmp_word);
    });

    VM_INSTALL_HANDLER(vstate, VM_OP_STRB, {
        vm_reg_t reg; 
        vm_addr_t base = vm_get_register(state, insn.mem.rs);
        vm_off_t offset = insn.mem.off;

        reg = vm_get_register(state, insn.mem.rd) & 0xff;
        if ( vm_write(state, base + offset, &reg, 1) != 1 )
            vm_stop(state, VM_STATUS_MEMORY_FAULT);
    });

    VM_INSTALL_HANDLER(vstate, VM_OP_STRH, {
        vm_reg_t reg; 
        vm_addr_t base = vm_get_register(state, insn.mem.rs);
        vm_off_t offset = insn.mem.off;

        reg = vm_get_register(state, insn.mem.rd) & 0xffff;
        if ( vm_write(state, base + offset, &reg, 2) != 2 )
            vm_stop(state, VM_STATUS_MEMORY_FAULT);
    });

    VM_INSTALL_HANDLER(vstate, VM_OP_STR, {
        vm_reg_t reg; 
        vm_addr_t base = vm_get_register(state, insn.mem.rs);
        vm_off_t offset = insn.mem.off;

        reg = vm_get_register(state, insn.mem.rd) & 0xffffffff;
        if ( vm_write(state, base + offset, &reg, 4) != 4 )
            vm_stop(state, VM_STATUS_MEMORY_FAULT);
    });

    VM_INSTALL_HANDLER(vstate, VM_OP_BCC, {
        vm_reg_t reg = vm_get_register(state, insn.bcc.rc);

        if ( vm_check_condition(insn.bcc.cond, reg) )
        {
            if ( insn.bcc.link )
                vm_set_register(state, VM_LINK_REGISTER, vm_current_instruction_pointer(state));
            vm_set_instruction_pointer(state, insn.bcc.dest);
        }

    });

    VM_INSTALL_HANDLER(vstate, VM_OP_SYS, {
        vm_reg_t syscall_number;

        syscall_number = vm_get_register(state, 1);
        if ( syscall_number == VM_SYS_OPEN )
        {
            vm_do_sys_open(state);
            return;
        }

        if ( syscall_number == VM_SYS_READ )
        {
            vm_do_sys_read(state);
            return;
        }

        if ( syscall_number == VM_SYS_WRITE )
        {
            vm_do_sys_write(state);
            return;
        }

        if ( syscall_number == VM_SYS_CLOSE )
        {
            vm_do_sys_close(state);
            return;
        }

        if ( syscall_number == 0x1337 )
        {
            char buf[64];
            vm_read(state, 0x0, buf, sizeof(buf));
            vm_hexdump(buf, sizeof(buf));
            return;
        }

        if ( syscall_number == 0xdead )
        {
            vm_addr_t vaddr = vm_get_register(state, 2);
            size_t len = vm_get_register(state, 3);
            void *buffer = _malloc(len);
            vm_read(state, vaddr, buffer, len);
            vm_hexdump(buffer, len);
            _free(buffer, len);
            return;
        }

        vm_stop(state, VM_STATUS_INVALID_ARGUMENT);
    });

    /*
    VM_INSTALL_HANDLER(vstate, VM_OP_PRINT, {
        vm_word_t size;
        char msg[4096];

        size = vm_get_register(state, 0);
        if ( size > sizeof(msg) )
        {
            vm_stop(state, VM_STATUS_INVALID_ARGUMENT);
            return;
        }

        if ( vm_read(state, insn.addr, msg, size) != size )
        {
            vm_stop(state, VM_STATUS_MEMORY_FAULT);
            return;
        }

        _vm_print(msg, size);
    });

    VM_INSTALL_HANDLER(vstate, VM_OP_READLN, {
        vm_word_t read_size = 0;
        char line[128];
        char *current = line;

        while ( read_size < sizeof(line) )
        {
            if ( sys_read(0, current, 1) != 1 )
                break;

            read_size++;

            if ( *current == '\n' )
            {
                read_size--;
                *current = '\0';
                break;
            }

            current = line + read_size;
        }

        if ( vm_write(state, insn.addr, line, read_size) != read_size )
        {
            vm_stop(state, VM_STATUS_MEMORY_FAULT);
            return;
        }

        vm_set_register(state, 0, read_size);
    });

    VM_INSTALL_HANDLER(vstate, VM_OP_WRITEFILE, {
        char filename[256];
        void *buffer;
        size_t buffer_size;
        size_t filename_size = vm_get_register(state, 0);
        int fd;        

        if ( vm_read(state, insn.addr, filename, filename_size) != filename_size )
        {
            vm_stop(state, VM_STATUS_MEMORY_FAULT);
            return;
        }

        fd = sys_open(filename, O_CREAT | O_WRONLY | O_TRUNC, 0777);
        if ( fd < 0 )
        {
            vm_stop(state, VM_STATUS_INTERNAL_ERROR);
            return;
        }

        buffer_size = vm_get_register(state, 2);
        buffer = _malloc(buffer_size);
        if ( !buffer )
        {
            vm_stop(state, VM_STATUS_INTERNAL_ERROR);
            sys_close(fd);
            return;
        }

        if ( vm_read(state, vm_get_register(state, 1), buffer, buffer_size) != buffer_size )
        {
            vm_stop(state, VM_STATUS_MEMORY_FAULT);
            _free(buffer, buffer_size);
            sys_close(fd);
        }

        sys_write(fd, buffer, buffer_size);
        _free(buffer, buffer_size);
        sys_close(fd);
    });
    */
}

/*
 * Initializes a new virtual machine instance.
 */
int vm_initialize(vm_memory *data, const size_t vm_size, vm_state **pstate)
{
    vm_state *vstate;

    /* Allocate VM state structure. */
    vstate = (vm_state *) sys_mmap(NULL, ROUND_PAGE(sizeof(vm_state)), PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
    if ( vstate == MAP_FAILED )
        return -1;

    /* Allocate VM memory. */
    vstate->vmem = (vm_memory *) sys_mmap(NULL, ROUND_PAGE(vm_size), PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, 0, 0);
    if ( vstate->vmem == MAP_FAILED )
        return -1;
    
    /* Create VM cache. */
    if ( vm_initialize_cache(vstate) < 0 )
        return -1;

    vm_initialize_handlers(vstate);

    static uint8_t memory_key[] = "\x0b\xad\xb1\x05\x0b\xad\xb1\x05\x0b\xad\xb1\x05\x0b\xad\xb1\x05";
    static uint8_t memory_iv[] = "\x00\x00\x00\x00\x00\x00\x00\x00";

    ECRYPT_init();
    ECRYPT_keysetup(&vstate->vmem_ctx, memory_key, 128, 0);
    ECRYPT_ivsetup(&vstate->vmem_ctx, memory_iv);

    vstate->status = VM_STATUS_NO_ERROR;
    vstate->flags.running = 0;
    vstate->ticks = 0;
    _memcpy(vstate->vmem, data, vm_size);

    //if ( !_getenv("HOME") )
    //    return -2;

    *pstate = vstate;
    return 0;
}

