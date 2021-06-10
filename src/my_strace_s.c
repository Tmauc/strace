/*
** EPITECH PROJECT, 2018
** my_strace.c
** File description:
** my_strace.c
*/

#include "strace.h"
#include "syscall_names.h"

void print_s_bis(struct user_regs_struct u_in, pid_t child)
{
    if (my_syscall[u_in.rax].type == '?')
        dprintf(2, ") = ?\n");
    else if (my_syscall[u_in.rax].type == 4) {
        ptrace(PTRACE_GETREGS, child, 0, &u_in);
        dprintf(2, ") = 0x%llx\n", u_in.rax);
    } else {
        ptrace(PTRACE_GETREGS, child, 0, &u_in);
        ((int)u_in.rax <= -2) ? dprintf(2, ") = -1\n") : 
        dprintf(2, ") = %lld\n", u_in.rax);
    }
}

void print_parenthesis(struct user_regs_struct u_in, pid_t child)
{
    int nb_args = get_nbargs(u_in);
    int i;

    for (i = 0; i <= nb_args; i++) {
        switch (my_syscall[u_in.rax].types[i]) {
            case (1):
                print_int(u_in, i);
                break;
            case (2):
                if (strcmp("execve", my_syscall[u_in.rax].name) != 0)
                    print_str(u_in, i, child);
                else
                    print_int(u_in, i);
                break;
            case (4):
                print_exa(u_in, i);
                break;
        }
        (i + 1 < nb_args) ? dprintf(1, ", ") : 1; 
    }
}

void print_s(struct user_regs_struct u_in, pid_t child)
{
    dprintf(2, "%s(", my_syscall[u_in.rax].name);
    print_parenthesis(u_in, child);
    print_s_bis(u_in, child);
    (void)child;
}

int my_print_strace_s(struct user_regs_struct u_in, pid_t child)
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
            (peek == 0x050F) ? print_s(u_in, child) : 1;
        }
    }
    return (status);
}

int my_strace_s(char *cmd, char **env, char **av)
{
    int status;
    int ret;
    struct user_regs_struct u_in;
    pid_t child = fork();

    if (child == -1)
        return (EXIT_FAILURE);
    if (child == 0) {
        ret = check_command(cmd, env, av + 1);
        if (ret == -1) {
            perror("execve: ");
        }
    } else
        status = my_print_strace_s(u_in, child);
    dprintf(2, "+++ exited with %d +++\n", WSTOPSIG(status));
    return (0);
}