/*
** EPITECH PROJECT, 2018
** getenv
** File description:
** getenv
*/

#include "strace.h"

char *my_getenv(char **env, char *a)
{
    int i = 0;
    int j = 0;
    int size = strlen(a) - 1;

    for (; env[j] != NULL; j++, i = 0) {
        while (env[j][i] == a[i]) {
            if (i == size) {
                return (env[j] + i + 1);
            } else
                i++;
        }
    }
    return (NULL);
}
