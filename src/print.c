/*
** EPITECH PROJECT, 2018
** arg_tab
** File description:
** arg_tab
*/

#include "strace.h"
#include "syscall_names.h"

int get_nbargs(struct user_regs_struct u_in)
{
    int nb = 0;
    int i = 0;

    for (; i < 6; i++) {
        if (my_syscall[u_in.rax].types[i] != 0)
            nb++;
    }
    return (nb);
}

int print_help(void)
{
    printf("USAGE: ./strace [-s] [-p <pid>|<command>]\n");
    return (84);
}

void print_bis(struct user_regs_struct u_in, int nb_args, pid_t child)
{
    if (nb_args > 3) {
        dprintf(2, "0x%llx", u_in.r10);
        if (nb_args > 4)
            dprintf(2, ", ");
    } if (nb_args > 4) {
        dprintf(2, "0x%llx", u_in.r8);
        if (nb_args > 5)
            dprintf(2, ", ");
    } if (nb_args > 5) {
        dprintf(2, "0x%llx", u_in.r9);
        if (nb_args > 6)
            dprintf(2, ", ");
    }
    if (my_syscall[u_in.rax].type == '?')
        dprintf(2, ") = ?\n");
    else {
        ptrace(PTRACE_GETREGS, child, 0, &u_in);
        dprintf(2, ") = 0x%llx\n", u_in.rax);
    }
}

void print(struct user_regs_struct u_in, pid_t child)
{
    int nb_args = get_nbargs(u_in);

    dprintf(2, "%s(", my_syscall[u_in.rax].name);
    if (nb_args > 0) {
        dprintf(2, "0x%llx", u_in.rdi);
        if (nb_args > 1)
            dprintf(2, ", ");
    } if (nb_args > 1) {
        dprintf(2, "0x%llx", u_in.rsi);
        if (nb_args > 2)
            dprintf(2, ", ");
    } if (nb_args > 2) {
        dprintf(2, "0x%llx", u_in.rdx);
        if (nb_args > 3)
            dprintf(2, ", ");
    }
    print_bis(u_in, nb_args, child);
}