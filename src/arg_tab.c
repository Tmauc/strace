/*
** EPITECH PROJECT, 2018
** arg_tab
** File description:
** arg_tab
*/

#include "strace.h"

int comptarg(char *s)
{
    int i = 0;

    while (s[i] != '\0')
        i++;
    return (i);
}

char *arg_space(char *s)
{
    int i = 0;
    int j = 0;
    int k = 0;
    char *str = malloc(sizeof(char) * (comptarg(s) + 4));

    for (; k < comptarg(s) + 4; str[k++] = '\0');
    for (; s[i] != '\0'; i++) {
        if ((s[i] == ' ' || s[i] == '\t') && (s[i + 1] == ' ' ||
        s[i + 1] == '\t'))
            continue;
        else if (s[i] == '\t') {
            str[j] = ' ';
            j++;
        } else {
            str[j] = s[i];
            j++;
        }
    }
    str[j] = '\0';
    return (str);
}

char **arg_char(char *str)
{
    int i = 0;
    int j = 0;
    int a = 0;
    char **tmp;

    tmp = malloc(sizeof(char *) * strlen(str) + 1);
    for (; str[i] != '\0'; i++, j++, a = 0) {
        tmp[j] = malloc(sizeof(char) * (strlen(str) + 1));
        for (; str[i] != ' ' && str[i] != '\0'; i++, a++)
            tmp[j][a] = str[i];
        tmp[j][a] = '\0';
    }
    tmp[j] = NULL;
    return (tmp);
}

char **arg_tab(char *s)
{
    char *str = arg_space(s);
    char **tab = arg_char(str);

    free(str);
    return (tab);
}
