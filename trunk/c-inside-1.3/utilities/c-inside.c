/*
 * C-Inside (libc-inside) - C language interpreter library
 * Copyright (C) 2008-2015  Jason Todd <jtodd1@earthlink.net>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/* c-inside.c - main wrapper utility for the libc-inside C interpreter */

#include <stdio.h>          /* fopen, fgets, fclose */
#include <stdlib.h>         /* malloc, free */
#include <unistd.h>         /* isatty */
#include <string.h>         /* strlen, strcpy, strcat, strcmp, memset,
                               memcpy */
#include <errno.h>          /* strerror */

#include "c-inside.h"
#include "config.h"

#define SCRIPT_LINE_CHUNK_SIZE  1000

static char *prog = NULL;
static uint32_t line_num = 0;

static int do_error(char *str);
static int do_output(char *str);
static char *read_script_line(FILE *f);
static int show_usage(char *argv0);
static int remove_arg(int *argc, char **argv, size_t num);

int main(int argc, char *argv[], char *envp[])
{
    cinside_info *info;
    int ret, ret2;
    FILE *f;
    char *cmd, *msg;
    cinside_variable arg_vars[4];
    int new_argc;
    char **new_argv;

    if ((new_argv = malloc((argc + 1) * sizeof(char *))) == NULL)
    {
        fprintf(stderr, "%s: insufficient memory\n", argv[0]);
        return CINSIDE_ERR_RESOURCES;
    }

    new_argc = argc;
    memcpy(new_argv, argv, argc * sizeof(char *));
    new_argv[argc] = NULL;

    memset(&arg_vars, 0, sizeof(arg_vars));
    arg_vars[0].name = "argc";
    arg_vars[0].addr = (uint32_t *)&new_argc;
    arg_vars[1].name = "argv";
    arg_vars[1].addr = (uint32_t *)new_argv;
    arg_vars[2].name = "envp";
    arg_vars[2].addr = (uint32_t *)envp;

    if ((argc == 1) && isatty(STDIN_FILENO))
    {
        printf("%s (%s %s)\n", PACKAGE_STRING, __DATE__, __TIME__);
        printf("Type \"$help\" or \"$license\" for more information.\n");
        ret = cinside_go(arg_vars, NULL, 0, 0);
        if (ret != CINSIDE_SUCCESS_EXIT)
            return ret;

        return 0;
    }

    if ((ret = cinside_init(&info, arg_vars, NULL, 0, 0)) != CINSIDE_SUCCESS)
    {
        if (cinside_get(info, CINSIDE_ID_ERROR,
                        (uint32_t *)&msg) == CINSIDE_SUCCESS)
        {
            fprintf(stderr, msg);
        }
        else
        {
            fprintf(stderr, "%s: initialization error %d\n", argv[0], ret);
        }

        return ret;
    }

    ret = cinside_set(info, CINSIDE_ID_ERROR_FUNC, (uint32_t)do_error);
    if (ret != CINSIDE_SUCCESS)
        return ret;

    ret = cinside_set(info, CINSIDE_ID_OUTPUT_FUNC, (uint32_t)do_output);
    if (ret != CINSIDE_SUCCESS)
        return ret;

    if (argc > 1)
    {
        if ((strcmp(argv[1], "-h") == 0) || (strcmp(argv[1], "--help") == 0))
            return show_usage(argv[0]);

        if (strcmp(argv[1], "--version") == 0)
        {
            printf("%s and lib%s Copyright (C) 2008-2015 Jason Todd\n",
                   PACKAGE_NAME, PACKAGE_NAME);

            printf("%s\n", PACKAGE_STRING);
            return cinside_eval(info, "$version", NULL);
        }

        if (strcmp(argv[1], "-c") == 0)
        {
            ret = cinside_eval(info, argv[2], NULL);
            if (CINSIDE_RET_ERROR(ret))
                return ret;

            ret2 = cinside_set(info, CINSIDE_ID_INPUT_DONE, 1);
            if (ret2 != CINSIDE_SUCCESS)
                return ret2;

            ret2 = cinside_eval(info, "", NULL);
            if (CINSIDE_RET_ERROR(ret2))
                return ret2;

            return ret;
        }

        if ((f = fopen(argv[1], "r")) == NULL)
        {
            if (argv[1][0] == '-')
            {
                fprintf(stderr, "%s: invalid option '%s'\n", argv[0], argv[1]);
                return CINSIDE_ERR_PARAMETER;
            }

            fprintf(stderr, "%s: %s: %s\n", argv[0], argv[1], strerror(errno));
            return CINSIDE_ERR_NOT_FOUND;
        }

        remove_arg(&new_argc, new_argv, 0);
        prog = new_argv[0];
    }
    else
    {
        f = stdin;
    }

    while (!feof(f))
    {
        if (((cmd = read_script_line(f)) == NULL) ||
            ((ret = cinside_eval(info, cmd, NULL)) == CINSIDE_SUCCESS_EXIT) ||
            (CINSIDE_RET_ERROR(ret)))
        {
            break;
        }
    }

    fclose(f);
    if (CINSIDE_RET_ERROR(ret))
        return ret;

    ret2 = cinside_set(info, CINSIDE_ID_INPUT_DONE, 1);
    if (ret2 != CINSIDE_SUCCESS)
        return ret2;

    ret2 = cinside_eval(info, "", NULL);
    if (CINSIDE_RET_ERROR(ret2))
        return ret2;

    return 0;
}

static int do_error(char *str)
{
    if (prog == NULL)
        fprintf(stderr, "c-inside: %s\n", str);
    else
        fprintf(stderr, "%s:%u: %s\n", prog, line_num, str);

    return CINSIDE_SUCCESS;
}

static int do_output(char *str)
{
    printf("%s", str);
    fflush(stdout);
    return CINSIDE_SUCCESS;
}

static char *read_script_line(FILE *f)
{
    char *chunk, *tmp, *ret;
    size_t len, total;

    ret = NULL;
    total = 0;

    do
    {
        if (((chunk = malloc(SCRIPT_LINE_CHUNK_SIZE)) == NULL) ||
            (fgets(chunk, SCRIPT_LINE_CHUNK_SIZE, f) == NULL))
        {
            return ret;
        }

        len = strlen(chunk);
        total += len;

        if (ret != NULL)
        {
            if ((tmp = malloc(total + 1)) == NULL)
            {
                free(ret);
                return NULL;
            }

            strcpy(tmp, ret);
            strcat(tmp, chunk);
            free(chunk);
            free(ret);
            ret = tmp;
        }
        else
        {
            ret = chunk;
        }

        if ((len < (SCRIPT_LINE_CHUNK_SIZE - 1)) || (chunk[len - 1] == '\n'))
        {
            if (chunk[len - 1] == '\n')
            {
                if ((len > 1) && (chunk[len - 1] == '\\'))
                    continue;

                chunk[len - 1] = '\0';
            }

            if ((line_num++ == 0) && (ret[0] == '#') && (ret[1] == '!'))
                ret[0] = '\0';

            break;
        }
    } while (1);

    return ret;
}

static int show_usage(char *argv0)
{
    printf("Usage: %s [-h | --help | --version | -c COMMAND | FILE]\n", argv0);
    printf(
        "    -h, --help     Display this information.\n"
        "    --version      Display version information, including libc-inside.\n"
        "    -c COMMAND     Execute the given command.\n"
        "    FILE           Execute the commands in the given file.\n");

    printf(
        "\n"
        "When run with no arguments, the application runs in interactive mode.\n");

    return CINSIDE_SUCCESS;
}

static int remove_arg(int *argc, char **argv, size_t num)
{
    size_t i;
    int tmp_argc;

    if ((argc == NULL) || (num >= *argc))
        return CINSIDE_ERR_PARAMETER;

    tmp_argc = *argc;
    for (i = num; i < (tmp_argc - 1); i++)
        argv[i] = argv[i + 1];

    argv[--tmp_argc] = NULL;
    *argc = tmp_argc;
    return CINSIDE_SUCCESS;
}
