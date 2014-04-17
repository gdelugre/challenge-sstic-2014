#include <stddef.h>
//#include <sys/mman.h>

#include "vm.h"
#include "vm_handlers.h"
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
#ifdef _LP64
    state->vmem_ctx.input[13] = (VM_PAGE(vaddr) >> 32UL);
#else
    state->vmem_ctx.input[13] = 0;
#endif

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
#ifdef _LP64
    state->vmem_ctx.input[13] = (VM_PAGE(vaddr) >> 32UL);
#else
    state->vmem_ctx.input[13] = 0;
#endif

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

int vm_read(vm_state *state, vm_addr_t vaddr, void *buffer, size_t size)
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

int vm_write(vm_state *state, vm_addr_t vaddr, void *buffer, size_t size)
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

int vm_read_string(vm_state *state, vm_addr_t addr, char *buffer, size_t buffer_size)
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

int vm_read_word(vm_state *state, vm_addr_t addr, vm_word_t *word)
{
    if ( vm_read(state, addr, word, sizeof(*word)) != sizeof(*word) )
        return -1;

    return 0;
}

int vm_write_word(vm_state *state, vm_addr_t addr, vm_word_t word)
{
    if ( vm_write(state, addr, &word, sizeof(word)) != sizeof(word) )
       return -1; 

    return 0;
}

vm_reg_t vm_get_register(vm_state *state, int n)
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

void vm_set_register(vm_state * state, int n, vm_reg_t value)
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

vm_addr_t vm_current_instruction_pointer(vm_state *state)
{
    vm_reg_t ip;

    if ( vm_read(state, offsetof(vm_memory, ctx.ip), &ip, sizeof(ip)) != sizeof(ip) )
        return VM_INVALID_ADDR;
    
    return (vm_addr_t) ip; 
}

void vm_set_instruction_pointer(vm_state *state, vm_reg_t ip)
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

