/*
** EPITECH PROJECT, 2018
** my_strtok
** File description:
** my_strtok
*/

#include "strace.h"

char *my_strcat(char *dest, char *src)
{
    int i = 0;
    int j = 0;
    int size = strlen(src) + strlen(dest);
    char *str = malloc(sizeof(char) * (size + 2));

    for (; dest[j] != '\0'; i++, j++) {
        str[i] = dest[j];
    }
    str[i++] = '/';
    for (j = 0; src[j] != '\0'; i++, j++) {
        str[i] = src[j];
    }
    str[i] = '\0';
    return (str);
}

char *strcat_free(char *str, char **args)
{
    char *tmp = my_strcat(str, args[0]);

    free(str);
    return (tmp);
}

char **my_strtok(char *str, char c, char **args)
{
    int i = 0;
    int j = 0;
    int a = 0;
    char **tmp = NULL;

    tmp = malloc(sizeof(char *) * strlen(str));
    for (; str[i] != '\0'; i++, a = 0, j++) {
        tmp[j] = malloc(sizeof(char) * strlen(str));
        for (; str[i] != c && str[i] != '\0'; i++, a++) {
            tmp[j][a] = str[i];
        }
        tmp[j][a] = '\0';
        tmp[j] = strcat_free(tmp[j], args);
    }
    tmp[j] = NULL;
    return (tmp);
}
