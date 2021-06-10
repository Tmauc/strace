/*
** EPITECH PROJECT, 2018
** command.c
** File description:
** command.c
*/

#include "strace.h"

char *check_access(char **tmp)
{
    int i = 0;

    for (; access(tmp[i], 0) != 0 && tmp[i] != NULL; i++);
    if (tmp[i] == NULL) {
        printf("Command not found.\n");
        exit(84);
    }
    return (tmp[i]);
}

char *var_env(char **env, char **args)
{
    char *sep = "PATH=";
    char *str = my_getenv(env, sep);
    char **tmp;

    str[strlen(str) + 1] = '\0';
    tmp = my_strtok(str, ':', args);
    return (check_access(tmp));
}

char *get_command(char **av)
{
    int i = 1;
    int size = 0;
    char *command;

    for (; av[i] != NULL; i++) {
        size += strlen(av[i]) + 1;
    }
    command = calloc(sizeof(char *), size + 1);
    for (i = 1; av[i] != NULL; i++) {
        strcat(command, av[i]);
        if (av[i + 1] != NULL)
            strcat(command, " ");
    }
    return (command);
}

int exec_func(char *cmd, char **args, char **env)
{
    ptrace(PTRACE_TRACEME, 0, 0, 0);
    kill(getpid(), SIGSTOP);
    return (execve(cmd, args, env));
}

int check_command(char *cmd, char **env, char **av)
{
    char *command = get_command(av);
    char **args = arg_tab(command);

    if (access(cmd, 0) == 0) {
        return (exec_func(cmd, args, env));
    }
    if (!strncmp("./", cmd, 2)) {
        if (access(cmd, 0) != 0) {
            printf("Command not found.\n");
            return (-1);
        } else {
            return (exec_func(cmd, args, env));
        }
    }
    return (exec_func(var_env(env, args), args, env));
}