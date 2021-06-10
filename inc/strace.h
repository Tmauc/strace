/*
** EPITECH PROJECT, 2019
** PSU_strace_2018
** File description:
** strace
*/

#ifndef STRACE_H_
# define STRACE_H_
# include <stdlib.h>
# include <stdio.h>
# include <string.h>
# include <unistd.h>
# include <signal.h>
# include <syscall.h>
# include <errno.h>
# include <ctype.h>
# include <sys/ptrace.h>
# include <sys/types.h>
# include <sys/wait.h>
# include <sys/user.h>
# include <sys/stat.h>
# include <sys/reg.h>
# define true 0
# define false 1
# define VOID ('?')
# define NDEF (0)
# define INTE (1)
# define STR (2)
# define OTH (4)

pid_t pid;

typedef struct my_info
{
    long long unsigned int rax;
    char *command;
    char **arg;
} my_info;

char **arg_tab(char *s);
int get_nbargs(struct user_regs_struct u_in);
char *my_getenv(char **env, char *a);
int check_command(char *cmd, char **env, char **av);
char **my_strtok(char *str, char c, char **g);
int print_help(void);
void print(struct user_regs_struct u_in, pid_t child);
int get_pid(char *str);
int is_num(char c);
int my_strace(char *cmd, char **env, char **av);
int my_strace_s(char *cmd, char **env, char **av);
int my_strace_p(char **av);
void print_exa(struct user_regs_struct u_in, int i);
void print_int(struct user_regs_struct u_in, int i);
void my_print_str_lld(long long unsigned int nb, pid_t child);
void print_str(struct user_regs_struct u_in, int i, pid_t child);

#endif