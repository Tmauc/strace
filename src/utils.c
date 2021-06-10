/*
** EPITECH PROJECT, 2019
** utils.c
** File description:
** utils.c
*/

#include "strace.h"

int is_num(char c)
{
    if (c > 47 && c < 58) {
        return (true);
    } else {
        return (false);
    }
}

int get_pid(char *str)
{
    int i = 0;

    if (!str || !str[0]) {
        fprintf(stderr, "No string after -p !\n");
        exit (84);
    }
    for (; str[i] != '\0'; i++) {
        if (is_num(str[i]) == false) {
            fprintf(stderr, "String need be a unsigned number !\n");
            exit (84);
        }
    }
    return (atoi(str));
}