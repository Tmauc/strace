/*
** EPITECH PROJECT, 2018
** my_strace.c
** File description:
** my_strace.c
*/

#include "strace.h"

int my_print_strace(struct user_regs_struct u_in, pid_t child)
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

int my_strace(char *cmd, char **env, char **av)
{
    int status;
    int ret;
    struct user_regs_struct u_in;
    pid_t child = fork();

    if (child == -1)
        return (EXIT_FAILURE);
    if (child == 0) {
        ret = check_command(cmd, env, av);
        if (ret == -1) {
            perror("execve");
            return (84);
        }
    } else {
        status = my_print_strace(u_in, child);
    }
    dprintf(2, "+++ exited with %d +++\n", WSTOPSIG(status));
    return (0);
}