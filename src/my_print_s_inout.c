/*
** EPITECH PROJECT, 2018
** my_strace.c
** File description:
** my_strace.c
*/

#include "strace.h"

void print_exa(struct user_regs_struct u_in, int i)
{
    switch (i) {
        case (0):
                dprintf(2, "0x%llx", u_in.rdi);
                break;
        case (1):
                dprintf(2, "0x%llx", u_in.rsi);
                break;
        case (2):
                dprintf(2, "0x%llx", u_in.rdx);
                break;
        case (3):
                dprintf(2, "0x%llx", u_in.r10);
                break;
        case (4):
                dprintf(2, "0x%llx", u_in.r8);
                break;
        case (5):
                dprintf(2, "0x%llx", u_in.r9);
                break;
    }
}

void print_int(struct user_regs_struct u_in, int i)
{
    switch (i){
        case (0):
                dprintf(2, "%lld", u_in.rdi);
                break;
        case (1):
                dprintf(2, "%lld", u_in.rsi);
                break;
        case (2):
                dprintf(2, "%lld", u_in.rdx);
                break;
        case (3):
                dprintf(2, "%lld", u_in.r10);
                break;
        case (4):
                dprintf(2, "%lld", u_in.r8);
                break;
        case (5):
                dprintf(2, "%lld", u_in.r9);
                break;
    }
}

void my_print_str_lld(long long unsigned int nb, pid_t child)
{
    char tmp;
    int i = 0;

    dprintf(2, "\"");
    for (; i != 27; i++) {
        tmp = ptrace(PTRACE_PEEKTEXT, child, nb + i, 0);
        if (tmp == -1)
            break;
        if (isprint(tmp))
            (tmp == '\n') ? dprintf(2, "\\n") : dprintf(2, "%c", tmp);
    }
    if (i >= 27)
        dprintf(2, "...");
    dprintf(2, "\"");
    (void)i;
}

void print_str(struct user_regs_struct u_in, int i, pid_t child)
{
    switch (i){
        case (0):
                my_print_str_lld(u_in.rdi, child);
                break;
        case (1):
                my_print_str_lld(u_in.rsi, child);
                break;
        case (2):
                my_print_str_lld(u_in.rdx, child);
                break;
        case (3):
                my_print_str_lld(u_in.r10, child);
                break;
        case (4):
                my_print_str_lld(u_in.r8, child);
                break;
        case (5):
                my_print_str_lld(u_in.r9, child);
                break;
    }
}
