#ifndef __SYSCALLS_H
#define __SYSCALLS_H

#include <syscall.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define PAGE_SHIFT 12UL
#define PAGE_SIZE (1UL << PAGE_SHIFT)
#define REQUIRED_PAGES(nr_bytes) ((nr_bytes + PAGE_SIZE - 1) >> PAGE_SHIFT)
#define ROUND_PAGE(nr_bytes) (REQUIRED_PAGES(nr_bytes) << PAGE_SHIFT)

#define SYSCALL_DECL(name) static inline long (sys_##name)

SYSCALL_DECL(syscall1)(int n, long arg1)
{
    long result;

    __asm__ __volatile__ (
#if defined(__aarch64__)
        "mov x0, %[a1]\n\t"
        "mov x8, %[sys_id]\n\t"
        "svc #0\n\t"
        "mov %[res], x0\n\t"
        : [res] "=r" (result)
        : [sys_id] "i" (n), [a1] "r" (arg1)
        : "x0", "x8"
#elif defined(__arm__)
        "mov r0, %[a1]\n\t"
        "ldr r7, %[sys_id]\n\t"
        "svc #0\n\t"
        "mov %[res], r0\n\t"
        : [res] "=r" (result)
        : [sys_id] "m" (n), [a1] "r" (arg1)
        : "r0", "r7"
#else
    #error "Architecture not supported."
#endif
    );

    return result;
}

SYSCALL_DECL(syscall2)(int n, long arg1, long arg2)
{
    long result;

    __asm__ __volatile__ (
#if defined(__aarch64__)
        "mov x1, %[a2]\n\t"
        "mov x0, %[a1]\n\t"
        "mov x8, %[sys_id]\n\t"
        "svc #0\n\t"
        "mov %[res], x0\n\t"
        : [res] "=r" (result)
        : [sys_id] "i" (n), [a1] "r" (arg1), [a2] "r" (arg2)
        : "x0", "x1", "x8"
#elif defined(__arm__)
        "mov r1, %[a2]\n\t"
        "mov r0, %[a1]\n\t"
        "ldr r7, %[sys_id]\n\t"
        "svc #0\n\t"
        "mov %[res], r0\n\t"
        : [res] "=r" (result)
        : [sys_id] "m" (n), [a1] "r" (arg1), [a2] "r" (arg2)
        : "r0", "r1", "r7"
#else
    #error "Architecture not supported."
#endif
    );

    return result;
}

SYSCALL_DECL(syscall3)(int n, long arg1, long arg2, long arg3)
{
    long result;

    __asm__ __volatile__ (
#if defined(__aarch64__)
        "mov x2, %[a3]\n\t"
        "mov x1, %[a2]\n\t"
        "mov x0, %[a1]\n\t"
        "mov x8, %[sys_id]\n\t"
        "svc #0\n\t"
        "mov %[res], x0\n\t"
        : [res] "=r" (result)
        : [sys_id] "i" (n), [a1] "r" (arg1), [a2] "r" (arg2), [a3] "r" (arg3)
        : "x0", "x1", "x2", "x8"
#elif defined(__arm__)
        "mov r2, %[a3]\n\t"
        "mov r1, %[a2]\n\t"
        "mov r0, %[a1]\n\t"
        "ldr r7, %[sys_id]\n\t"
        "svc #0\n\t"
        "mov %[res], r0\n\t"
        : [res] "=r" (result)
        : [sys_id] "m" (n), [a1] "r" (arg1), [a2] "r" (arg2), [a3] "r" (arg3)
        : "r0", "r1", "r2", "r7"
#else
    #error "Architecture not supported."
#endif
    );

    return result;
}

SYSCALL_DECL(syscall4)(int n, long arg1, long arg2, long arg3, long arg4)
{
    long result;

    __asm__ __volatile__ (
#if defined(__aarch64__)
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
#elif defined(__arm__)
        "mov r3, %[a4]\n\t"
        "mov r2, %[a3]\n\t"
        "mov r1, %[a2]\n\t"
        "mov r0, %[a1]\n\t"
        "ldr r7, %[sys_id]\n\t"
        "svc #0\n\t"
        "mov %[res], r0\n\t"
        : [res] "=r" (result)
        : [sys_id] "m" (n), [a1] "r" (arg1), [a2] "r" (arg2), [a3] "r" (arg3), [a4] "r" (arg4)
        : "r0", "r1", "r2", "r3", "r7"
#else
    #error "Architecture not supported."
#endif
    );

    return result;
}

SYSCALL_DECL(syscall5)(int n, long arg1, long arg2, long arg3, long arg4, long arg5)
{
    long result;

    __asm__ __volatile__ (
#if defined(__aarch64__)
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
#elif defined(__arm__)
        "mov r4, %[a5]\n\t"
        "mov r3, %[a4]\n\t"
        "mov r2, %[a3]\n\t"
        "mov r1, %[a2]\n\t"
        "mov r0, %[a1]\n\t"
        "ldr r7, %[sys_id]\n\t"
        "svc #0\n\t"
        "mov %[res], r0\n\t"
        : [res] "=r" (result)
        : [sys_id] "m" (n), [a1] "r" (arg1), [a2] "r" (arg2), [a3] "r" (arg3), [a4] "r" (arg4), [a5] "r" (arg5)
        : "r0", "r1", "r2", "r3", "r4", "r7"
#else
    #error "Architecture not supported."
#endif
    );


    return result;
}

SYSCALL_DECL(syscall6)(int n, long arg1, long arg2, long arg3, long arg4, long arg5, long arg6)
{
    long result;

    __asm__ __volatile__ (
#if defined(__aarch64__)
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
#elif defined(__arm__)
        "ldr r5, %[a6]\n\t"
        "ldr r4, %[a5]\n\t"
        "ldr r3, %[a4]\n\t"
        "ldr r2, %[a3]\n\t"
        "ldr r1, %[a2]\n\t"
        "ldr r0, %[a1]\n\t"
        "ldr r7, %[sys_id]\n\t"
        "svc #0\n\t"
        "mov %[res], r0\n\t"
        : [res] "=r" (result)
        : [sys_id] "m" (n), [a1] "m" (arg1), [a2] "m" (arg2), [a3] "m" (arg3), [a4] "m" (arg4), [a5] "m" (arg5), [a6] "m" (arg6)
        : "r0", "r1", "r2", "r3", "r4", "r5", "r7"
#else
    #error "Architecture not supported."
#endif
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
#ifdef __arm__
    return sys_syscall6(__NR_mmap2, (long)addr, len, prot, flags, filedes, off);
#else
    return sys_syscall6(__NR_mmap, (long)addr, len, prot, flags, filedes, off);
#endif
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

SYSCALL_DECL(open)(const char *pathname, int flags, mode_t mode)
{
    return sys_syscall4(__NR_openat, AT_FDCWD, (long) pathname, flags, mode);
}

SYSCALL_DECL(read)(int fd, void *buf, size_t count)
{
    return sys_syscall3(__NR_read, fd, (long) buf, count);
}

SYSCALL_DECL(write)(int fd, const void *buf, size_t count)
{
    return sys_syscall3(__NR_write, fd, (long) buf, count);
} 

SYSCALL_DECL(close)(int fd)
{
    return sys_syscall1(__NR_close, fd);
}

#endif
