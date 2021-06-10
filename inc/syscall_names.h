/*
** EPITECH PROJECT, 2018
** PSU_strace_2018
** File description:
** syscall_names
*/

#ifndef SYSCALL_NAMES_H_
# define SYSCALL_NAMES_H_

# define TABSIZE(x) (sizeof(x) / sizeof(*x))

#include "strace.h"

typedef struct syscall_s
{
    int type;
    int types[6];
    char *name;
} syscall_t;

static syscall_t my_syscall[] = {
    [0] = {
        .name = "read",
        .types = {INTE, STR, INTE, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [1] = {
        .name = "write",
        .types = {INTE, STR, INTE, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [2] = {
        .name = "open",
        .types = {STR, INTE, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [3] = {
        .name = "close",
        .types = {INTE, NDEF, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [4] = {
        .name = "stat",
        .types = {STR, OTH, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [5] = {
        .name = "fstat",
        .types = {INTE, OTH, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [6] = {
        .name = "lstat",
        .types = {STR, OTH, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [7] = {
        .name = "poll",
        .types = {OTH, INTE, INTE, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [8] = {
        .name = "lseek",
        .types = {INTE, INTE, INTE, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [9] = {
        .name = "mmap",
        .types = {OTH, INTE, INTE, INTE, INTE, INTE},
        .type = OTH,
    },
    [10] = {
        .name = "mprotect",
        .types = {OTH, INTE, INTE, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [11] = {
        .name = "munmap",
        .types = {INTE, INTE, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [12] = {
        .name = "brk",
        .types = {OTH, NDEF, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [13] = {
        .name = "rt_sigaction",
        .types = {INTE, OTH, OTH, INTE, NDEF, NDEF},
        .type = INTE,
    },
    [14] = {
        .name = "rt_sigprocmask",
        .types = {INTE, OTH, OTH, INTE, NDEF, NDEF},
        .type = INTE,
    },
    [15] = {
        .name = "rt_sigreturn",
        .types = {OTH, OTH, OTH, OTH, OTH, OTH},
        .type = INTE,
    },
    [16] = {
        .name = "ioctl",
        .types = {INTE, INTE, INTE, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [17] = {
        .name = "pread64",
        .types = {INTE, STR, INTE, INTE, NDEF, NDEF},
        .type = INTE,
    },
    [18] = {
        .name = "pwrite64",
        .types = {INTE, STR, INTE, INTE, NDEF, NDEF},
        .type = INTE,
    },
    [19] = {
        .name = "readv",
        .types = {INTE, OTH, INTE, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [20] = {
        .name = "writev",
        .types = {INTE, OTH, INTE, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [21] = {
        .name = "access",
        .types = {STR, INTE, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [22] = {
        .name = "pipe",
        .types = {OTH, NDEF, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [23] = {
        .name = "select",
        .types = {INTE, OTH, OTH, OTH, OTH, NDEF},
        .type = INTE,
    },
    [24] = {
        .name = "sched_yield",
        .types = {NDEF, NDEF, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [25] = {
        .name = "mremap",
        .types = {INTE, INTE, INTE, INTE, INTE, NDEF},
        .type = INTE,
    },
    [26] = {
        .name = "msync",
        .types = {INTE, INTE, INTE, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [27] = {
        .name = "mincore",
        .types = {INTE, INTE, OTH, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [28] = {
        .name = "madvise",
        .types = {INTE, INTE, INTE, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [29] = {
        .name = "shmget",
        .types = {INTE, INTE, INTE, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [30] = {
        .name = "shmat",
        .types = {INTE, STR, INTE, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [31] = {
        .name = "shmctl",
        .types = {INTE, INTE, OTH, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [32] = {
        .name = "dup",
        .types = {INTE, NDEF, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [33] = {
        .name = "dup2",
        .types = {INTE, INTE, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [34] = {
        .name = "pause",
        .types = {NDEF, NDEF, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [35] = {
        .name = "nanosleep",
        .types = {OTH, OTH, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [36] = {
        .name = "getitimer",
        .types = {INTE, OTH, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [37] = {
        .name = "alarm",
        .types = {INTE, NDEF, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [38] = {
        .name = "setitimer",
        .types = {INTE, OTH, OTH, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [39] = {
        .name = "getpid",
        .types = {NDEF, NDEF, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [40] = {
        .name = "sendfile",
        .types = {INTE, INTE, OTH, INTE, NDEF, NDEF},
        .type = INTE,
    },
    [41] = {
        .name = "socket",
        .types = {INTE, INTE, INTE, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [42] = {
        .name = "connect",
        .types = {INTE, OTH, INTE, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [43] = {
        .name = "accept",
        .types = {INTE, OTH, OTH, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [44] = {
        .name = "sendto",
        .types = {INTE, OTH, INTE, INTE, OTH, INTE},
        .type = INTE,
    },
    [45] = {
        .name = "recvfrom",
        .types = {INTE, OTH, INTE, INTE, OTH, OTH},
        .type = INTE,
    },
    [46] = {
        .name = "sendmsg",
        .types = {INTE, OTH, INTE, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [47] = {
        .name = "recvmsg",
        .types = {INTE, OTH, INTE, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [48] = {
        .name = "shutdown",
        .types = {INTE, INTE, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [49] = {
        .name = "bind",
        .types = {INTE, OTH, INTE, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [50] = {
        .name = "listen",
        .types = {INTE, INTE, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [51] = {
        .name = "getsockname",
        .types = {INTE, OTH, OTH, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [52] = {
        .name = "getpeername",
        .types = {INTE, OTH, OTH, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [53] = {
        .name = "socketpair",
        .types = {INTE, INTE, INTE, OTH, NDEF, NDEF},
        .type = INTE,
    },
    [54] = {
        .name = "setsockopt",
        .types = {INTE, INTE, INTE, STR, INTE, NDEF},
        .type = INTE,
    },
    [55] = {
        .name = "getsockopt",
        .types = {INTE, INTE, INTE, STR, OTH, NDEF},
        .type = INTE,
    },
    [56] = {
        .name = "clone",
        .types = {INTE, INTE, OTH, OTH, INTE, NDEF},
        .type = INTE,
    },
    [57] = {
        .name = "fork",
        .types = {NDEF, NDEF, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [58] = {
        .name = "vfork",
        .types = {NDEF, NDEF, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [59] = {
        .name = "execve",
        .types = {STR, STR, OTH, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [60] = {
        .name = "exit",
        .types = {INTE, NDEF, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [61] = {
        .name = "wait4",
        .types = {INTE, OTH, INTE, OTH, NDEF, NDEF},
        .type = INTE,
    },
    [62] = {
        .name = "kill",
        .types = {INTE, INTE, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [63] = {
        .name = "uname",
        .types = {OTH, NDEF, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [64] = {
        .name = "semget",
        .types = {INTE, INTE, INTE, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [65] = {
        .name = "semop",
        .types = {INTE, OTH, INTE, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [66] = {
        .name = "semctl",
        .types = {INTE, INTE, INTE, INTE, NDEF, NDEF},
        .type = INTE,
    },
    [67] = {
        .name = "shmdt",
        .types = {STR, NDEF, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [68] = {
        .name = "msgget",
        .types = {INTE, INTE, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [69] = {
        .name = "msgsnd",
        .types = {INTE, OTH, INTE, INTE, NDEF, NDEF},
        .type = INTE,
    },
    [70] = {
        .name = "msgrcv",
        .types = {INTE, OTH, INTE, INTE, INTE, NDEF},
        .type = INTE,
    },
    [71] = {
        .name = "msgctl",
        .types = {INTE, INTE, OTH, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [72] = {
        .name = "fcntl",
        .types = {INTE, INTE, INTE, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [73] = {
        .name = "flock",
        .types = {INTE, INTE, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [74] = {
        .name = "fsync",
        .types = {INTE, NDEF, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [75] = {
        .name = "fdatasync",
        .types = {INTE, NDEF, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [76] = {
        .name = "truncate",
        .types = {STR, INTE, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [77] = {
        .name = "ftruncate",
        .types = {INTE, INTE, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [78] = {
        .name = "getdents",
        .types = {INTE, OTH, INTE, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [79] = {
        .name = "getcwd",
        .types = {STR, INTE, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [80] = {
        .name = "chdir",
        .types = {STR, NDEF, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [81] = {
        .name = "fchdir",
        .types = {INTE, NDEF, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [82] = {
        .name = "rename",
        .types = {STR, STR, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [83] = {
        .name = "mkdir",
        .types = {STR, INTE, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [84] = {
        .name = "rmdir",
        .types = {STR, NDEF, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [85] = {
        .name = "creat",
        .types = {STR, INTE, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [86] = {
        .name = "link",
        .types = {STR, STR, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [87] = {
        .name = "unlink",
        .types = {STR, NDEF, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [88] = {
        .name = "symlink",
        .types = {STR, STR, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [89] = {
        .name = "readlink",
        .types = {STR, STR, INTE, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [90] = {
        .name = "chmod",
        .types = {STR, INTE, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [91] = {
        .name = "fchmod",
        .types = {INTE, INTE, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [92] = {
        .name = "chown",
        .types = {STR, INTE, INTE, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [93] = {
        .name = "fchown",
        .types = {INTE, INTE, INTE, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [94] = {
        .name = "lchown",
        .types = {STR, INTE, INTE, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [95] = {
        .name = "umask",
        .types = {INTE, NDEF, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [96] = {
        .name = "gettimeofday",
        .types = {OTH, OTH, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [97] = {
        .name = "getrlimit",
        .types = {INTE, OTH, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [98] = {
        .name = "getrusage",
        .types = {INTE, OTH, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [99] = {
        .name = "sysinfo",
        .types = {OTH, NDEF, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [100] = {
        .name = "times",
        .types = {OTH, NDEF, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [101] = {
        .name = "ptrace",
        .types = {INTE, INTE, INTE, INTE, NDEF, NDEF},
        .type = INTE,
    },
    [102] = {
        .name = "getuid",
        .types = {NDEF, NDEF, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [103] = {
        .name = "syslog",
        .types = {INTE, STR, INTE, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [104] = {
        .name = "getgid",
        .types = {NDEF, NDEF, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [105] = {
        .name = "setuid",
        .types = {INTE, NDEF, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [106] = {
        .name = "setgid",
        .types = {INTE, NDEF, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [107] = {
        .name = "geteuid",
        .types = {NDEF, NDEF, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [108] = {
        .name = "getegid",
        .types = {NDEF, NDEF, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [109] = {
        .name = "setpgid",
        .types = {INTE, INTE, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [110] = {
        .name = "getppid",
        .types = {NDEF, NDEF, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [111] = {
        .name = "getpgrp",
        .types = {NDEF, NDEF, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [112] = {
        .name = "setsid",
        .types = {NDEF, NDEF, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [113] = {
        .name = "setreuid",
        .types = {INTE, INTE, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [114] = {
        .name = "setregid",
        .types = {INTE, INTE, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [115] = {
        .name = "getgroups",
        .types = {INTE, OTH, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [116] = {
        .name = "setgroups",
        .types = {INTE, OTH, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [117] = {
        .name = "setresuid",
        .types = {INTE, INTE, INTE, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [118] = {
        .name = "getresuid",
        .types = {OTH, OTH, OTH, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [119] = {
        .name = "setresgid",
        .types = {INTE, INTE, INTE, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [120] = {
        .name = "getresgid",
        .types = {OTH, OTH, OTH, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [121] = {
        .name = "getpgid",
        .types = {INTE, NDEF, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [122] = {
        .name = "setfsuid",
        .types = {INTE, NDEF, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [123] = {
        .name = "setfsgid",
        .types = {INTE, NDEF, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [124] = {
        .name = "getsid",
        .types = {INTE, NDEF, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [125] = {
        .name = "capget",
        .types = {INTE, INTE, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [126] = {
        .name = "capset",
        .types = {INTE, INTE, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [127] = {
        .name = "rt_sigpending",
        .types = {OTH, INTE, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [128] = {
        .name = "rt_sigtimedwait",
        .types = {OTH, OTH, OTH, INTE, NDEF, NDEF},
        .type = INTE,
    },
    [129] = {
        .name = "rt_sigqueueinfo",
        .types = {INTE, INTE, OTH, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [130] = {
        .name = "rt_sigsuspend",
        .types = {OTH, INTE, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [131] = {
        .name = "sigaltstack",
        .types = {OTH, OTH, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [132] = {
        .name = "utime",
        .types = {STR, OTH, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [133] = {
        .name = "mknod",
        .types = {STR, INTE, INTE, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [134] = {
        .name = "uselib",
        .types = {STR, NDEF, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [135] = {
        .name = "personality",
        .types = {INTE, NDEF, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [136] = {
        .name = "ustat",
        .types = {INTE, OTH, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [137] = {
        .name = "statfs",
        .types = {STR, OTH, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [138] = {
        .name = "fstatfs",
        .types = {INTE, OTH, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [139] = {
        .name = "sysfs",
        .types = {INTE, INTE, INTE, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [140] = {
        .name = "getpriority",
        .types = {INTE, INTE, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [141] = {
        .name = "setpriority",
        .types = {INTE, INTE, INTE, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [142] = {
        .name = "sched_setparam",
        .types = {INTE, OTH, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [143] = {
        .name = "sched_getparam",
        .types = {INTE, OTH, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [144] = {
        .name = "sched_setscheduler",
        .types = {INTE, INTE, OTH, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [145] = {
        .name = "sched_getscheduler",
        .types = {INTE, NDEF, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [146] = {
        .name = "sched_get_priority_max",
        .types = {INTE, NDEF, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [147] = {
        .name = "sched_get_priority_min",
        .types = {INTE, NDEF, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [148] = {
        .name = "sched_rr_get_INTEerval",
        .types = {INTE, OTH, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [149] = {
        .name = "mlock",
        .types = {INTE, INTE, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [150] = {
        .name = "munlock",
        .types = {INTE, INTE, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [151] = {
        .name = "mlockall",
        .types = {INTE, NDEF, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [152] = {
        .name = "munlockall",
        .types = {NDEF, NDEF, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [153] = {
        .name = "vhangup",
        .types = {NDEF, NDEF, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [154] = {
        .name = "modify_ldt",
        .types = {OTH, OTH, OTH, OTH, OTH, OTH},
        .type = INTE,
    },
    [155] = {
        .name = "pivot_root",
        .types = {STR, STR, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [156] = {
        .name = "_sysctl",
        .types = {OTH, OTH, OTH, OTH, OTH, OTH},
        .type = INTE,
    },
    [157] = {
        .name = "prctl",
        .types = {INTE, INTE, INTE, INTE, INTE, NDEF},
        .type = INTE,
    },
    [158] = {
        .name = "arch_prctl",
        .types = {INTE, OTH, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [159] = {
        .name = "adjtimex",
        .types = {OTH, NDEF, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [160] = {
        .name = "setrlimit",
        .types = {INTE, OTH, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [161] = {
        .name = "chroot",
        .types = {STR, NDEF, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [162] = {
        .name = "sync",
        .types = {NDEF, NDEF, NDEF, NDEF, NDEF, NDEF},
        .type = VOID,
    },
    [163] = {
        .name = "acct",
        .types = {STR, NDEF, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [164] = {
        .name = "settimeofday",
        .types = {OTH, OTH, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [165] = {
        .name = "mount",
        .types = {STR, STR, STR, INTE, OTH, NDEF},
        .type = INTE,
    },
    [166] = {
        .name = "umount2",
        .types = {OTH, OTH, OTH, OTH, OTH, OTH},
        .type = INTE,
    },
    [167] = {
        .name = "swapon",
        .types = {STR, INTE, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [168] = {
        .name = "swapoff",
        .types = {STR, NDEF, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [169] = {
        .name = "reboot",
        .types = {INTE, INTE, INTE, OTH, NDEF, NDEF},
        .type = INTE,
    },
    [170] = {
        .name = "sethostname",
        .types = {STR, INTE, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [171] = {
        .name = "setdomainname",
        .types = {STR, INTE, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [172] = {
        .name = "iopl",
        .types = {INTE, NDEF, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [173] = {
        .name = "ioperm",
        .types = {OTH, OTH, OTH, OTH, OTH, OTH},
        .type = INTE,
    },
    [174] = {
        .name = "create_module",
        .types = {OTH, OTH, OTH, OTH, OTH, OTH},
        .type = INTE,
    },
    [175] = {
        .name = "init_module",
        .types = {OTH, INTE, STR, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [176] = {
        .name = "delete_module",
        .types = {STR, INTE, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [177] = {
        .name = "get_kernel_syms",
        .types = {OTH, OTH, OTH, OTH, OTH, OTH},
        .type = INTE,
    },
    [178] = {
        .name = "query_module",
        .types = {OTH, OTH, OTH, OTH, OTH, OTH},
        .type = INTE,
    },
    [179] = {
        .name = "quotactl",
        .types = {INTE, STR, INTE, OTH, NDEF, NDEF},
        .type = INTE,
    },
    [180] = {
        .name = "nfsservctl",
        .types = {OTH, OTH, OTH, OTH, OTH, OTH},
        .type = INTE,
    },
    [181] = {
        .name = "getpmsg",
        .types = {OTH, OTH, OTH, OTH, OTH, OTH},
        .type = INTE,
    },
    [182] = {
        .name = "putpmsg",
        .types = {OTH, OTH, OTH, OTH, OTH, OTH},
        .type = INTE,
    },
    [183] = {
        .name = "afs_syscall",
        .types = {OTH, OTH, OTH, OTH, OTH, OTH},
        .type = INTE,
    },
    [184] = {
        .name = "tuxcall",
        .types = {OTH, OTH, OTH, OTH, OTH, OTH},
        .type = INTE,
    },
    [185] = {
        .name = "security",
        .types = {OTH, OTH, OTH, OTH, OTH, OTH},
        .type = INTE,
    },
    [186] = {
        .name = "gettid",
        .types = {NDEF, NDEF, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [187] = {
        .name = "readahead",
        .types = {INTE, INTE, INTE, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [188] = {
        .name = "setxattr",
        .types = {STR, STR, OTH, INTE, INTE, NDEF},
        .type = INTE,
    },
    [189] = {
        .name = "lsetxattr",
        .types = {STR, STR, OTH, INTE, INTE, NDEF},
        .type = INTE,
    },
    [190] = {
        .name = "fsetxattr",
        .types = {INTE, STR, OTH, INTE, INTE, NDEF},
        .type = INTE,
    },
    [191] = {
        .name = "getxattr",
        .types = {STR, STR, OTH, INTE, NDEF, NDEF},
        .type = INTE,
    },
    [192] = {
        .name = "lgetxattr",
        .types = {STR, STR, OTH, INTE, NDEF, NDEF},
        .type = INTE,
    },
    [193] = {
        .name = "fgetxattr",
        .types = {INTE, STR, OTH, INTE, NDEF, NDEF},
        .type = INTE,
    },
    [194] = {
        .name = "listxattr",
        .types = {STR, STR, INTE, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [195] = {
        .name = "llistxattr",
        .types = {STR, STR, INTE, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [196] = {
        .name = "flistxattr",
        .types = {INTE, STR, INTE, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [197] = {
        .name = "removexattr",
        .types = {STR, STR, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [198] = {
        .name = "lremovexattr",
        .types = {STR, STR, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [199] = {
        .name = "fremovexattr",
        .types = {INTE, STR, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [200] = {
        .name = "tkill",
        .types = {INTE, INTE, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [201] = {
        .name = "time",
        .types = {OTH, NDEF, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [202] = {
        .name = "futex",
        .types = {OTH, INTE, INTE, OTH, OTH, INTE},
        .type = INTE,
    },
    [203] = {
        .name = "sched_setaffinity",
        .types = {INTE, INTE, OTH, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [204] = {
        .name = "sched_getaffinity",
        .types = {INTE, INTE, OTH, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [205] = {
        .name = "set_thread_area",
        .types = {OTH, NDEF, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [206] = {
        .name = "io_setup",
        .types = {INTE, OTH, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [207] = {
        .name = "io_deSTRoy",
        .types = {INTE, NDEF, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [208] = {
        .name = "io_getevents",
        .types = {INTE, INTE, INTE, OTH, OTH, NDEF},
        .type = INTE,
    },
    [209] = {
        .name = "io_submit",
        .types = {INTE, INTE, OTH, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [210] = {
        .name = "io_cancel",
        .types = {INTE, OTH, OTH, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [211] = {
        .name = "get_thread_area",
        .types = {OTH, NDEF, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [212] = {
        .name = "lookup_dcookie",
        .types = {INTE, STR, INTE, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [213] = {
        .name = "epoll_create",
        .types = {INTE, NDEF, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [214] = {
        .name = "epoll_ctl_old",
        .types = {OTH, OTH, OTH, OTH, OTH, OTH},
        .type = INTE,
    },
    [215] = {
        .name = "epoll_wait_old",
        .types = {OTH, OTH, OTH, OTH, OTH, OTH},
        .type = INTE,
    },
    [216] = {
        .name = "remap_file_pages",
        .types = {INTE, INTE, INTE, INTE, INTE, NDEF},
        .type = INTE,
    },
    [217] = {
        .name = "getdents64",
        .types = {INTE, OTH, INTE, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [218] = {
        .name = "set_tid_address",
        .types = {OTH, NDEF, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [219] = {
        .name = "restart_syscall",
        .types = {NDEF, NDEF, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [220] = {
        .name = "semtimedop",
        .types = {INTE, OTH, INTE, OTH, NDEF, NDEF},
        .type = INTE,
    },
    [221] = {
        .name = "fadvise64",
        .types = {INTE, INTE, INTE, INTE, NDEF, NDEF},
        .type = INTE,
    },
    [222] = {
        .name = "timer_create",
        .types = {INTE, OTH, OTH, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [223] = {
        .name = "timer_settime",
        .types = {INTE, INTE, OTH, OTH, NDEF, NDEF},
        .type = INTE,
    },
    [224] = {
        .name = "timer_gettime",
        .types = {INTE, OTH, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [225] = {
        .name = "timer_getoverrun",
        .types = {INTE, NDEF, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [226] = {
        .name = "timer_delete",
        .types = {INTE, NDEF, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [227] = {
        .name = "clock_settime",
        .types = {INTE, OTH, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [228] = {
        .name = "clock_gettime",
        .types = {INTE, OTH, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [229] = {
        .name = "clock_getres",
        .types = {INTE, OTH, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [230] = {
        .name = "clock_nanosleep",
        .types = {INTE, INTE, OTH, OTH, NDEF, NDEF},
        .type = INTE,
    },
    [231] = {
        .name = "exit_group",
        .types = {INTE, NDEF, NDEF, NDEF, NDEF, NDEF},
        .type = VOID,
    },
    [232] = {
        .name = "epoll_wait",
        .types = {INTE, OTH, INTE, INTE, NDEF, NDEF},
        .type = INTE,
    },
    [233] = {
        .name = "epoll_ctl",
        .types = {INTE, INTE, INTE, OTH, NDEF, NDEF},
        .type = INTE,
    },
    [234] = {
        .name = "tgkill",
        .types = {INTE, INTE, INTE, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [235] = {
        .name = "utimes",
        .types = {STR, OTH, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [236] = {
        .name = "vserver",
        .types = {OTH, OTH, OTH, OTH, OTH, OTH},
        .type = INTE,
    },
    [237] = {
        .name = "mbind",
        .types = {INTE, INTE, INTE, OTH, INTE, INTE},
        .type = INTE,
    },
    [238] = {
        .name = "set_mempolicy",
        .types = {INTE, OTH, INTE, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [239] = {
        .name = "get_mempolicy",
        .types = {OTH, OTH, INTE, INTE, INTE, NDEF},
        .type = INTE,
    },
    [240] = {
        .name = "mq_open",
        .types = {STR, INTE, INTE, OTH, NDEF, NDEF},
        .type = INTE,
    },
    [241] = {
        .name = "mq_unlink",
        .types = {STR, NDEF, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [242] = {
        .name = "mq_timedsend",
        .types = {INTE, STR, INTE, INTE, OTH, NDEF},
        .type = INTE,
    },
    [243] = {
        .name = "mq_timedreceive",
        .types = {INTE, STR, INTE, OTH, OTH, NDEF},
        .type = INTE,
    },
    [244] = {
        .name = "mq_notify",
        .types = {INTE, OTH, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [245] = {
        .name = "mq_getsetattr",
        .types = {INTE, OTH, OTH, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [246] = {
        .name = "kexec_load",
        .types = {INTE, INTE, OTH, INTE, NDEF, NDEF},
        .type = INTE,
    },
    [247] = {
        .name = "waitid",
        .types = {INTE, INTE, OTH, INTE, OTH, NDEF},
        .type = INTE,
    },
    [248] = {
        .name = "add_key",
        .types = {STR, STR, OTH, INTE, INTE, NDEF},
        .type = INTE,
    },
    [249] = {
        .name = "request_key",
        .types = {STR, STR, STR, INTE, NDEF, NDEF},
        .type = INTE,
    },
    [250] = {
        .name = "keyctl",
        .types = {INTE, INTE, INTE, INTE, INTE, NDEF},
        .type = INTE,
    },
    [251] = {
        .name = "ioprio_set",
        .types = {OTH, OTH, OTH, OTH, OTH, OTH},
        .type = INTE,
    },
    [252] = {
        .name = "ioprio_get",
        .types = {OTH, OTH, OTH, OTH, OTH, OTH},
        .type = INTE,
    },
    [253] = {
        .name = "inotify_init",
        .types = {NDEF, NDEF, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [254] = {
        .name = "inotify_add_watch",
        .types = {INTE, STR, INTE, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [255] = {
        .name = "inotify_rm_watch",
        .types = {INTE, INTE, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [256] = {
        .name = "migrate_pages",
        .types = {INTE, INTE, OTH, OTH, NDEF, NDEF},
        .type = INTE,
    },
    [257] = {
        .name = "openat",
        .types = {INTE, STR, INTE, INTE, NDEF, NDEF},
        .type = INTE,
    },
    [258] = {
        .name = "mkdirat",
        .types = {INTE, STR, INTE, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [259] = {
        .name = "mknodat",
        .types = {INTE, STR, INTE, INTE, NDEF, NDEF},
        .type = INTE,
    },
    [260] = {
        .name = "fchownat",
        .types = {INTE, STR, INTE, INTE, INTE, NDEF},
        .type = INTE,
    },
    [261] = {
        .name = "futimesat",
        .types = {INTE, STR, OTH, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [262] = {
        .name = "newfstatat",
        .types = {INTE, STR, OTH, INTE, NDEF, NDEF},
        .type = INTE,
    },
    [263] = {
        .name = "unlinkat",
        .types = {INTE, STR, INTE, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [264] = {
        .name = "renameat",
        .types = {INTE, STR, INTE, STR, NDEF, NDEF},
        .type = INTE,
    },
    [265] = {
        .name = "linkat",
        .types = {INTE, STR, INTE, STR, INTE, NDEF},
        .type = INTE,
    },
    [266] = {
        .name = "symlinkat",
        .types = {STR, INTE, STR, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [267] = {
        .name = "readlinkat",
        .types = {INTE, STR, STR, INTE, NDEF, NDEF},
        .type = INTE,
    },
    [268] = {
        .name = "fchmodat",
        .types = {INTE, STR, INTE, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [269] = {
        .name = "faccessat",
        .types = {INTE, STR, INTE, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [270] = {
        .name = "pselect6",
        .types = {INTE, OTH, OTH, OTH, OTH, OTH},
        .type = INTE,
    },
    [271] = {
        .name = "ppoll",
        .types = {OTH, INTE, OTH, OTH, INTE, NDEF},
        .type = INTE,
    },
    [272] = {
        .name = "unshare",
        .types = {INTE, NDEF, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [273] = {
        .name = "set_robust_list",
        .types = {OTH, INTE, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [274] = {
        .name = "get_robust_list",
        .types = {INTE, OTH, OTH, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [275] = {
        .name = "splice",
        .types = {INTE, OTH, INTE, OTH, INTE, INTE},
        .type = INTE,
    },
    [276] = {
        .name = "tee",
        .types = {INTE, INTE, INTE, INTE, NDEF, NDEF},
        .type = INTE,
    },
    [277] = {
        .name = "sync_file_range",
        .types = {INTE, INTE, INTE, INTE, NDEF, NDEF},
        .type = INTE,
    },
    [278] = {
        .name = "vmsplice",
        .types = {INTE, OTH, INTE, INTE, NDEF, NDEF},
        .type = INTE,
    },
    [279] = {
        .name = "move_pages",
        .types = {INTE, INTE, OTH, OTH, OTH, INTE},
        .type = INTE,
    },
    [280] = {
        .name = "utimensat",
        .types = {INTE, STR, OTH, INTE, NDEF, NDEF},
        .type = INTE,
    },
    [281] = {
        .name = "epoll_pwait",
        .types = {INTE, OTH, INTE, INTE, OTH, INTE},
        .type = INTE,
    },
    [282] = {
        .name = "signalfd",
        .types = {INTE, OTH, INTE, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [283] = {
        .name = "timerfd_create",
        .types = {INTE, INTE, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [284] = {
        .name = "eventfd",
        .types = {INTE, NDEF, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [285] = {
        .name = "fallocate",
        .types = {INTE, INTE, INTE, INTE, NDEF, NDEF},
        .type = INTE,
    },
    [286] = {
        .name = "timerfd_settime",
        .types = {INTE, INTE, OTH, OTH, NDEF, NDEF},
        .type = INTE,
    },
    [287] = {
        .name = "timerfd_gettime",
        .types = {INTE, OTH, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [288] = {
        .name = "accept4",
        .types = {INTE, OTH, OTH, INTE, NDEF, NDEF},
        .type = INTE,
    },
    [289] = {
        .name = "signalfd4",
        .types = {INTE, OTH, INTE, INTE, NDEF, NDEF},
        .type = INTE,
    },
    [290] = {
        .name = "eventfd2",
        .types = {INTE, INTE, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [291] = {
        .name = "epoll_create1",
        .types = {INTE, NDEF, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [292] = {
        .name = "dup3",
        .types = {INTE, INTE, INTE, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [293] = {
        .name = "pipe2",
        .types = {OTH, INTE, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [294] = {
        .name = "inotify_init1",
        .types = {INTE, NDEF, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [295] = {
        .name = "preadv",
        .types = {INTE, OTH, INTE, INTE, INTE, NDEF},
        .type = INTE,
    },
    [296] = {
        .name = "pwritev",
        .types = {INTE, OTH, INTE, INTE, INTE, NDEF},
        .type = INTE,
    },
    [297] = {
        .name = "rt_tgsigqueueinfo",
        .types = {INTE, INTE, INTE, OTH, NDEF, NDEF},
        .type = INTE,
    },
    [298] = {
        .name = "perf_event_open",
        .types = {OTH, INTE, INTE, INTE, INTE, NDEF},
        .type = INTE,
    },
    [299] = {
        .name = "recvmmsg",
        .types = {INTE, OTH, INTE, INTE, OTH, NDEF},
        .type = INTE,
    },
    [300] = {
        .name = "fanotify_init",
        .types = {INTE, INTE, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [301] = {
        .name = "fanotify_mark",
        .types = {INTE, INTE, INTE, INTE, STR, NDEF},
        .type = INTE,
    },
    [302] = {
        .name = "prlimit64",
        .types = {INTE, INTE, OTH, OTH, NDEF, NDEF},
        .type = INTE,
    },
    [303] = {
        .name = "name_to_handle_at",
        .types = {INTE, STR, OTH, OTH, INTE, NDEF},
        .type = INTE,
    },
    [304] = {
        .name = "open_by_handle_at",
        .types = {INTE, OTH, INTE, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [305] = {
        .name = "clock_adjtime",
        .types = {INTE, OTH, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [306] = {
        .name = "syncfs",
        .types = {INTE, NDEF, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [307] = {
        .name = "sendmmsg",
        .types = {INTE, OTH, INTE, INTE, NDEF, NDEF},
        .type = INTE,
    },
    [308] = {
        .name = "setns",
        .types = {INTE, INTE, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [309] = {
        .name = "getcpu",
        .types = {OTH, OTH, OTH, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [310] = {
        .name = "process_vm_readv",
        .types = {INTE, OTH, INTE, OTH, INTE, INTE},
        .type = INTE,
    },
    [311] = {
        .name = "process_vm_writev",
        .types = {INTE, OTH, INTE, OTH, INTE, INTE},
        .type = INTE,
    },
    [312] = {
        .name = "kcmp",
        .types = {INTE, INTE, INTE, INTE, INTE, NDEF},
        .type = INTE,
    },
    [313] = {
        .name = "finit_module",
        .types = {INTE, STR, INTE, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [314] = {
        .name = "sched_setattr",
        .types = {INTE, OTH, INTE, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [315] = {
        .name = "sched_getattr",
        .types = {INTE, OTH, INTE, INTE, NDEF, NDEF},
        .type = INTE,
    },
    [316] = {
        .name = "renameat2",
        .types = {INTE, STR, INTE, STR, INTE, NDEF},
        .type = INTE,
    },
    [317] = {
        .name = "seccomp",
        .types = {INTE, INTE, STR, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [318] = {
        .name = "getrandom",
        .types = {OTH, OTH, OTH, OTH, OTH, OTH},
        .type = INTE,
    },
    [319] = {
        .name = "memfd_create",
        .types = {STR, INTE, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [320] = {
        .name = "kexec_file_load",
        .types = {INTE, INTE, INTE, STR, INTE, NDEF},
        .type = INTE,
    },
    [321] = {
        .name = "bpf",
        .types = {INTE, OTH, INTE, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [322] = {
        .name = "execveat",
        .types = {INTE, STR, OTH, OTH, INTE, NDEF},
        .type = INTE,
    },
    [323] = {
        .name = "userfaultfd",
        .types = {INTE, NDEF, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [324] = {
        .name = "membarrier",
        .types = {INTE, INTE, NDEF, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [325] = {
        .name = "mlock2",
        .types = {INTE, INTE, INTE, NDEF, NDEF, NDEF},
        .type = INTE,
    },
    [326] = {
        .name = "copy_file_range",
        .types = {INTE, OTH, INTE, OTH, INTE, INTE},
        .type = INTE,
    },
    [327] = {
        .name = "preadv2",
        .types = {INTE, OTH, INTE, INTE, INTE, INTE},
        .type = INTE,
    },
    [328] = {
        .name = "pwritev2",
        .types = {INTE, OTH, INTE, INTE, INTE, INTE},
        .type = INTE,
    }
};

#endif
