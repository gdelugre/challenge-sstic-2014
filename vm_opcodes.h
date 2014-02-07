#ifndef __H_VM_OPCODES
#define __H_VM_OPCODES

/* VM instruction:
 *   [ opcode : 8 ], [ reg : 3 ], [ addr : 19 ], [ cond: 2]
 */

typedef struct {
    unsigned opcode:8;
    unsigned reg:3;
    unsigned addr:19;
    unsigned cond:2;
} vm_insn_t;

enum {
    VM_OP_HALT,
    VM_OP_NONE,
    VM_OP_MOV,
    VM_OP_SYS,

} VM_OPCODE;

#endif
