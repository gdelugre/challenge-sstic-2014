#ifndef __SYSCALLS_H
#define __SYSCALLS_H

#include <syscall.h>
#include <time.h>

#define SYSCALL_DECL(name) static inline long (sys_##name)

SYSCALL_DECL(syscall1)(int n, long arg1)
{
    long result;

    __asm__ __volatile__ (
        "mov x0, %[a1]\n\t"
        "mov x8, %[sys_id]\n\t"
        "svc #0\n\t"
        "mov %[res], x0\n\t"
        : [res] "=r" (result)
        : [sys_id] "i" (n), [a1] "r" (arg1)
        : "x0", "x8"
    );

    return result;
}

SYSCALL_DECL(syscall2)(int n, long arg1, long arg2)
{
    long result;

    __asm__ __volatile__ (
        "mov x1, %[a2]\n\t"
        "mov x0, %[a1]\n\t"
        "mov x8, %[sys_id]\n\t"
        "svc #0\n\t"
        "mov %[res], x0\n\t"
        : [res] "=r" (result)
        : [sys_id] "i" (n), [a1] "r" (arg1), [a2] "r" (arg2)
        : "x0", "x1", "x8"
    );

    return result;
}

SYSCALL_DECL(syscall3)(int n, long arg1, long arg2, long arg3)
{
    long result;

    __asm__ __volatile__ (
        "mov x2, %[a3]\n\t"
        "mov x1, %[a2]\n\t"
        "mov x0, %[a1]\n\t"
        "mov x8, %[sys_id]\n\t"
        "svc #0\n\t"
        "mov %[res], x0\n\t"
        : [res] "=r" (result)
        : [sys_id] "i" (n), [a1] "r" (arg1), [a2] "r" (arg2), [a3] "r" (arg3)
        : "x0", "x1", "x2", "x8"
    );

    return result;
}

SYSCALL_DECL(syscall4)(int n, long arg1, long arg2, long arg3, long arg4)
{
    long result;

    __asm__ __volatile__ (
        "mov x3, %[a4]\n\t"
        "mov x2, %[a3]\n\t"
        "mov x1, %[a2]\n\t"
        "mov x0, %[a1]\n\t"
        "mov x8, %[sys_id]\n\t"
        "svc #0\n\t"
        "mov %[res], x0\n\t"
        : [res] "=r" (result)
        : [sys_id] "i" (n), [a1] "r" (arg1), [a2] "r" (arg2), [a3] "r" (arg3), [a4] "r" (arg4)
        : "x0", "x1", "x2", "x3", "x8"
    );

    return result;
}

SYSCALL_DECL(syscall5)(int n, long arg1, long arg2, long arg3, long arg4, long arg5)
{
    long result;

    __asm__ __volatile__ (
        "mov x4, %[a5]\n\t"
        "mov x3, %[a4]\n\t"
        "mov x2, %[a3]\n\t"
        "mov x1, %[a2]\n\t"
        "mov x0, %[a1]\n\t"
        "mov x8, %[sys_id]\n\t"
        "svc #0\n\t"
        "mov %[res], x0\n\t"
        : [res] "=r" (result)
        : [sys_id] "i" (n), [a1] "r" (arg1), [a2] "r" (arg2), [a3] "r" (arg3), [a4] "r" (arg4), [a5] "r" (arg5)
        : "x0", "x1", "x2", "x3", "x4", "x8"
    );


    return result;
}

SYSCALL_DECL(syscall6)(int n, long arg1, long arg2, long arg3, long arg4, long arg5, long arg6)
{
    long result;

    __asm__ __volatile__ (
        "mov x5, %[a6]\n\t"
        "mov x4, %[a5]\n\t"
        "mov x3, %[a4]\n\t"
        "mov x2, %[a3]\n\t"
        "mov x1, %[a2]\n\t"
        "mov x0, %[a1]\n\t"
        "mov x8, %[sys_id]\n\t"
        "svc #0\n\t"
        "mov %[res], x0\n\t"
        : [res] "=r" (result)
        : [sys_id] "i" (n), [a1] "r" (arg1), [a2] "r" (arg2), [a3] "r" (arg3), [a4] "r" (arg4), [a5] "r" (arg5), [a6] "r" (arg6)
        : "x0", "x1", "x2", "x3", "x4", "x5", "x8"
    );

    return result;
}

_Noreturn SYSCALL_DECL(exit)(int status)
{
    sys_syscall1(__NR_exit_group, status);
    for (;;);
}

SYSCALL_DECL(mmap)(void *addr, size_t len, int prot, int flags, int filedes, off_t off)
{
    return sys_syscall6(__NR_mmap, (long)addr, len, prot, flags, filedes, off);
}

SYSCALL_DECL(munmap)(void *addr, size_t len)
{
    return sys_syscall2(__NR_munmap, (long)addr, len);
}

SYSCALL_DECL(mprotect)(void *addr, size_t len, int prot)
{
    return sys_syscall3(__NR_mprotect, (long)addr, len, prot);
}

SYSCALL_DECL(clock_gettime)(clockid_t clkid, struct timespec *tp)
{
    return sys_syscall2(__NR_clock_gettime, clkid, (long) tp);
}

SYSCALL_DECL(read)(int fd, void *buf, size_t count)
{
    return sys_syscall3(__NR_read, fd, (long) buf, count);
}

SYSCALL_DECL(write)(int fd, const void *buf, size_t count)
{
    return sys_syscall3(__NR_write, fd, (long) buf, count);
} 

#endif
