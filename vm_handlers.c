#include "vm.h"
#include "vm_handlers.h"
#include "stdlib.h"

__attribute__((noinline))
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
__attribute__((noinline))
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

__attribute__((noinline))
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

__attribute__((noinline))
static void vm_do_sys_close(vm_state *state)
{
    int result;

    result = sys_close(vm_get_register(state, 2));
    vm_set_register(state, 1, result);
}

__attribute__((noinline))
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

void vm_initialize_handlers(vm_state *vstate)
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

        /*
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

        if ( syscall_number == 0x42 )
        {
            char x;
            sys_read(1, &x, 1);
            return;
        }
        */

        vm_stop(state, VM_STATUS_INVALID_ARGUMENT);
    });
}

