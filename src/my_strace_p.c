/*
** EPITECH PROJECT, 2018
** getenv
** File description:
** getenv
*/

#include "strace.h"

int my_print_strace_p(struct user_regs_struct u_in, pid_t child)
{
    int status;
    unsigned short peek;

    while (waitpid(child, &status, 0) && !WIFEXITED(status)) {
        ptrace(PTRACE_GETREGS, child, 0, &u_in);
        peek = ptrace(PTRACE_PEEKTEXT, child, u_in.rip, 0);
        ptrace(PTRACE_SINGLESTEP, child, 0, 0);
        if ((WSTOPSIG(status) == SIGTRAP
        || WSTOPSIG(status) == SIGSTOP)
        && WIFSTOPPED(status)) {
            (peek == 0x050F) ? print(u_in, child) : 1;
        }
    }
    return (status);
}

int my_strace_p(char **av)
{
    int status;
    int pid = get_pid(av[2]);
    struct user_regs_struct u_in;
    pid_t child = fork();

    if (child == -1)
        return (EXIT_FAILURE);
    if (child == 0) {
        if (ptrace(PTRACE_ATTACH, pid, 0, 0) == -1)
            return (84);
        kill(pid, SIGSTOP);
    } else {
        status = my_print_strace_p(u_in, child);
    }
    dprintf(2, "+++ exited with %d +++\n", WSTOPSIG(status));
    return (0);
}