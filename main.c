#include <stdio.h>

#include "vm.h"
#include "vm_bytecode.h"
#include "syscalls.h"

int main(int argc, char *argv[])
{
    vm_state *vstate;

    if ( vm_initialize((vm_memory *) vm_bytecode, sizeof(vm_bytecode), &vstate) < 0 )
        return -1;

    return vm_start(vstate);
}

_Noreturn void start(int argc, char *argv[])
{
    sys_exit(main(argc, argv));
}
