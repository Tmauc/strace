/*
** EPITECH PROJECT, 2019
** main.c
** File description:
** main.c
*/

#include "strace.h"

int main(int ac, char **av, char **env)
{
    int status = 0;

    if (ac > 3 || ac < 2 || !strcmp(av[1], "--help") || !strcmp(av[1], "-h"))
        return (print_help());
    if (ac == 2 && strcmp(av[1], "-p") != 0 && strcmp(av[1], "-s") != 0)
        status = my_strace(av[1], env, av);
    else
        status = 84;
    if (ac == 3) {
        if (strcmp(av[1], "-p") == 0)
            status = my_strace_p(av);
        if (strcmp(av[1], "-s") == 0)
            status = my_strace_s(av[2], env, av);
        else
            status = my_strace(av[1], env, av);
    }
    return (status);
}