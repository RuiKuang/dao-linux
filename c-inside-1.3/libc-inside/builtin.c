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

/* builtin.c - libc-inside built-in commands */

#include <stdio.h>          /* sprintf */
#include <stdlib.h>         /* malloc, free */
#include <string.h>         /* strchr, memset, strlen, memcpy, strncmp */
#include <ctype.h>          /* isprint */
#include <dlfcn.h>          /* dlopen */
#include <errno.h>          /* strerror */
#include <sys/time.h>       /* gettimeofday */
#include <time.h>           /* gettimeofday */

#include "language.h"

/* one-time include for _cinside_builtin_license() (do not modify license.h) */
#include "license.h"

#define CINSIDE_LICENSE_END_OF_TERMS    "END OF TERMS AND CONDITIONS\n"

static int _cinside_builtin_help(cinside_info *info, size_t num_params,
                                 uint32_t *params, uint32_t *result,
                                 size_t *num, uint32_t **lval_addr);
static int _cinside_builtin_exit(cinside_info *info, size_t num_params,
                                 uint32_t *params, uint32_t *result,
                                 size_t *num, uint32_t **lval_addr);
static int _cinside_builtin_errno(cinside_info *info, size_t num_params,
                                  uint32_t *params, uint32_t *result,
                                  size_t *num, uint32_t **lval_addr);
static int _cinside_builtin_show(cinside_info *info, size_t num_params,
                                 uint32_t *params, uint32_t *result,
                                 size_t *num, uint32_t **lval_addr);
static int _cinside_builtin_show_vars(cinside_info *info);
static int _cinside_builtin_show_functions(cinside_info *info);
static int _cinside_builtin_show_strings(cinside_info *info);
static int _cinside_builtin_unset(cinside_info *info, size_t num_params,
                                  uint32_t *params, uint32_t *result,
                                  size_t *num, uint32_t **lval_addr);
static int _cinside_builtin_clear(cinside_info *info, size_t num_params,
                                  uint32_t *params, uint32_t *result,
                                  size_t *num, uint32_t **lval_addr);
static int _cinside_builtin_load(cinside_info *info, size_t num_params,
                                 uint32_t *params, uint32_t *result,
                                 size_t *num, uint32_t **lval_addr);
static int _cinside_builtin_dump(cinside_info *info, size_t num_params,
                                 uint32_t *params, uint32_t *result,
                                 size_t *num, uint32_t **lval_addr);
static int _cinside_builtin_mod(cinside_info *info, size_t num_params,
                                uint32_t *params, uint32_t *result,
                                size_t *num, uint32_t **lval_addr);
static int _cinside_builtin_time(cinside_info *info, size_t num_params,
                                 uint32_t *params, uint32_t *result,
                                 size_t *num, uint32_t **lval_addr);
static int _cinside_builtin_list(cinside_info *info, size_t num_params,
                                 uint32_t *params, uint32_t *result,
                                 size_t *num, uint32_t **lval_addr);
static int _cinside_builtin_license(cinside_info *info, size_t num_params,
                                    uint32_t *params, uint32_t *result,
                                    size_t *num, uint32_t **lval_addr);
static int _cinside_license_show(cinside_info *info, int first_section,
                                 int last_section);
static int _cinside_license_find_next(cinside_info *info, char *cur,
                                      char **next, unsigned long *num);
static int _cinside_builtin_version(cinside_info *info, size_t num_params,
                                    uint32_t *params, uint32_t *result,
                                    size_t *num, uint32_t **lval_addr);
static int _cinside_builtin_get(cinside_info *info, size_t num_params,
                                uint32_t *params, uint32_t *result,
                                size_t *num, uint32_t **lval_addr);
static int _cinside_builtin_set(cinside_info *info, size_t num_params,
                                uint32_t *params, uint32_t *result,
                                size_t *num, uint32_t **lval_addr);
static int _cinside_builtin_files(cinside_info *info, size_t num_params,
                                  uint32_t *params, uint32_t *result,
                                  size_t *num, uint32_t **lval_addr);
static int _cinside_builtin_words(cinside_info *info, size_t num_params,
                                  uint32_t *params, uint32_t *result,
                                  size_t *num, uint32_t **lval_addr);
static int _cinside_builtin_count(cinside_info *info, size_t num_params,
                                  uint32_t *params, uint32_t *result,
                                  size_t *num, uint32_t **lval_addr);
static int _cinside_builtin_next(cinside_info *info, size_t num_params,
                                 uint32_t *params, uint32_t *result,
                                 size_t *num, uint32_t **lval_addr);
static int _cinside_builtin_last(cinside_info *info, size_t num_params,
                                 uint32_t *params, uint32_t *result,
                                 size_t *num, uint32_t **lval_addr);
static int _cinside_builtin_go(cinside_info *info, size_t num_params,
                               uint32_t *params, uint32_t *result,
                               size_t *num, uint32_t **lval_addr);
static int _cinside_builtin_bp(cinside_info *info, size_t num_params,
                               uint32_t *params, uint32_t *result,
                               size_t *num, uint32_t **lval_addr);
static int _cinside_builtin_disasm(cinside_info *info, size_t num_params,
                                   uint32_t *params, uint32_t *result,
                                   size_t *num, uint32_t **lval_addr);

static _cinside_builtin_def _cinside_builtins[] = CINSIDE_BUILTINS;

/* update to match CINSIDE_ID_* */
static const char *_cinside_set_ids[] =
{
    "version", "error", "output_func", "error_func", "input_done", "add_semi",
    "getdata_func", "putdata_func", "setbp_func", "disasm_func",
    "enable_ctrlr"
};

int _cinside_eval_builtin(cinside_info *info, size_t first_token,
                          size_t last_token, size_t *num, uint32_t **lval_addr)
{
    int ret;
    char *cmd;
    size_t i, num_params, num_tokens;
    uint32_t result;
    uint32_t *params;
    _cinside_builtin_def *builtin;

    CINSIDE_DEBUG("<EXPR ==> BUILTIN ...>\n");

    result = 0;             /* default for built-in commands with no result */
    num_tokens = ((last_token - first_token) + 2);

    cmd = (char *)(info->token[first_token + 1]);
    for (i = 0; i < CINSIDE_NUM_BUILTINS(_cinside_builtins); i++)
    {
        builtin = &_cinside_builtins[i];
        if ((strcmp(cmd, builtin->name) == 0) &&
            (!(builtin->controller_mode) ||
             (info->flags & CINSIDE_FLAG_EN_CTRLR)))
        {
            break;
        }
    }

    if (i == CINSIDE_NUM_BUILTINS(_cinside_builtins))
    {
        return _cinside_error(info, CINSIDE_ERR_NOT_FOUND,
                              "invalid built-in command '$%s'", cmd);
    }

    num_params = 0;
    params = NULL;
    if (builtin->param_type == CINSIDE_PARAMS_NONE)
    {
        if (num_tokens != 2)
        {
            return _cinside_error(info, CINSIDE_ERR_SYNTAX,
                                  "invalid use of $%s", cmd);
        }
    }
    else if (builtin->param_type == CINSIDE_PARAMS_KEYWORD)
    {
        if (((num_tokens == 2) && (builtin->min_params == 1)) ||
            (num_tokens > 4) ||
            ((num_tokens == 4) &&
             (info->token[first_token + 2] != CINSIDE_TOKEN_NAME)))
        {
            return _cinside_error(info, CINSIDE_ERR_SYNTAX,
                                  "invalid use of $%s", cmd);
        }

        /*
         * Special case: one argument was supplied and it was a name (i.e.,
         * looked like a variable), so treat it as a keyword instead.  The
         * builtin functions will know it is a keyword because num_params is
         * zero and params is not NULL.
         * NOTE: keywords must be specified as unquoted literal words, not as
         * string literals nor as variables containing strings.
         */

        if (num_tokens == 4)
        {
            params = (uint32_t *)(info->token[first_token + 3]);
            num_params = 1;
        }
    }
    else if (builtin->param_type == CINSIDE_PARAMS_LIST)
    {
        if (num_tokens > 2)
        {
            ret = _cinside_eval_vals(info, first_token + 2, last_token,
                                     &num_params, &params);

            if (CINSIDE_RET_ERROR(ret))
                return ret;
        }
    }
    else if (builtin->param_type == CINSIDE_PARAMS_RAW)
    {
        if (num_tokens > 2)
        {
            num_params = 1;     /* since no processing of params, treat as 1 */

            /* temporarily use list storage for first_token and last_token */
            ret = _cinside_list_reserve(info, info->lists, 2, &params);
            if (ret != CINSIDE_SUCCESS)
                return ret;

            ret = _cinside_list_push(info, info->lists, first_token + 2);
            if (ret != CINSIDE_SUCCESS)
                return ret;

            ret = _cinside_list_push(info, info->lists, last_token);
            if (ret != CINSIDE_SUCCESS)
                return ret;
        }
    }

    if ((num_params < builtin->min_params) ||
        ((num_params > builtin->max_params) &&
         (builtin->max_params >= builtin->min_params)))
    {
        return _cinside_error(info, CINSIDE_ERR_SYNTAX, "invalid use of $%s",
                              cmd);
    }

    ret = builtin->f(info, num_params, params, &result, num, lval_addr);

    info->token[first_token] = CINSIDE_TOKEN_DATA;
    info->token[first_token + 1] = result;
    if (num_tokens > 2)
    {
        info->token[first_token + 2] = CINSIDE_TOKEN_NONE;
        info->token[first_token + 3] = 0;
    }

    return ret;
}

_cinside_builtin_def *_cinside_get_builtin(size_t idx)
{
    if (idx >= CINSIDE_NUM_BUILTINS(_cinside_builtins))
        return NULL;

    return &(_cinside_builtins[idx]);
}

static int _cinside_builtin_help(cinside_info *info, size_t num_params,
                                 uint32_t *params, uint32_t *result,
                                 size_t *num, uint32_t **lval_addr)
{
    char header_line[82];
    size_t header_max, bytes;

    /* one-time preparation of header line for all headings */
    header_max = (sizeof(header_line) - 3);
    header_line[header_max] = '\n';
    header_line[header_max + 1] = '\0';

    /* per-heading preparation and display */
    memset(header_line, '_', header_max);
    bytes = snprintf(header_line, sizeof(header_line) - 1,
                     "___ Online help for lib%s", PACKAGE_STRING);

    header_line[bytes] = ' ';
    _cinside_output(info, "%s", header_line);
    _cinside_output(info, "\n");

    _cinside_output(info, "lib%s  Copyright (C) 2008-2015  Jason Todd <%s>\n",
                    PACKAGE_STRING, PACKAGE_BUGREPORT);

    _cinside_output(info,
                    "lib%s comes with ABSOLUTELY NO WARRANTY; for details type\n",
                    PACKAGE_NAME);

    _cinside_output(info,
        "`$license warranty'.  This is free software, and you are welcome to\n");

    _cinside_output(info,
        "redistribute it under certain conditions; type `$license copying' for details.\n");

    _cinside_output(info, "\n");
    _cinside_output(info, "Summary of built-in commands:\n");
    _cinside_output(info, "\n");

    if (info->flags & CINSIDE_FLAG_EN_CTRLR)
    {
        _cinside_output(info,
        "$bp                    List currently set breakpoints.\n"
        "$bp <addr>[, <expr>]   Set a breakpoint at <addr>, with conditional expression\n"
        "                       <expr> (default <expr> is 1, for unconditional break).\n");
    }

    _cinside_output(info,
        "$clear all             Remove all known variables and functions, and all\n"
        "                       entered strings and lists.\n"
        "$clear functions       Remove all known functions.\n"
        "$clear vars            Remove all known variables.\n");

    _cinside_output(info,
        "$count <iter>          Return the number of items in <iter> (see $files and\n"
        "                       $words for information on <iter>).\n");

    if (info->flags & CINSIDE_FLAG_EN_CTRLR)
    {
        _cinside_output(info,
        "$disasm [<addr>[, <lines>]]\n"
        "                       Disassemble <lines> instructions starting at <addr>\n"
        "                       (default <addr> is just past the previous $disasm, or 0\n"
        "                       if no previous; default <lines> is the same number as\n"
        "                       the previous $disasm, or 8 if no previous).\n");
    }

    _cinside_output(info,
        "$dump <addr>[, <count>[, <size>]]\n"
        "                       Hex-dump data starting at <addr>, <count> values of\n"
        "                       <size> bytes (<size> can be 1, 2, or 4; default <count>\n"
        "                       is 128 and default <size> is 1).\n");

    _cinside_output(info,
        "$errno [quiet]         Return the errno value from the last function call.  The\n"
        "                       corresponding message is also displayed, unless [quiet]\n"
        "                       is supplied.\n");

    _cinside_output(info,
        "$exit                  Exit from the C-Inside environment.\n");

    _cinside_output(info,
        "$files <spec>[, <spec> ...]\n"
        "                       Create and return an iterator containing all file names\n"
        "                       that match the given <spec>(s).  The return value can be\n"
        "                       treated as a string, initially containing the first\n"
        "                       match (or empty string if no matches).  See also $next\n"
        "                       and $last.\n");

    _cinside_output(info,
        "$get [<id>]            Return the value of the named configuration item <id>.\n"
        "                       If no name is given, all configuration items are\n"
        "                       displayed.  Valid names are: version, error,\n"
        "                       output_func, error_func, input_done, add_semi,\n"
        "                       getdata_func, putdata_func, setbp_func, disasm_func,\n"
        "                       and enable_ctrlr.\n");

    if (info->flags & CINSIDE_FLAG_EN_CTRLR)
    {
        _cinside_output(info,
        "$go                    Begin or resume execution of controlled code.\n");
    }

    _cinside_output(info,
        "$help                  Display this text.\n");

    _cinside_output(info,
        "$last <iter>           Returns non-zero (and frees the iterator) if the last\n"
        "                       item in <iter> has already been obtained via $next (or\n"
        "                       $count, if the iterator only had 0 or 1 items).\n");

    _cinside_output(info,
        "$license               Display entire license.\n"
        "$license copying       Display redistribution sections of the license.\n"
        "$license warranty      Display warranty sections of the license.\n");

    _cinside_output(info,
        "$list <count>[, <val>]\n"
        "                       Create a new list, <count> items with value <val>.\n");

    _cinside_output(info,
        "$load <module>         Load the external module <mod>.\n");

    _cinside_output(info,
        "$mod <addr>, <val>[, <size>]\n"
        "                       Modify data at <addr> to <val> of <size> bytes (<size>\n"
        "                       can be 1, 2, or 4).\n");

    _cinside_output(info,
        "$next <iter>           Advances <iter> to the next item (see $files and $words).\n");

    _cinside_output(info,
        "$set <id>, <val>       Set the named configuration item <id> to <val>.  Valid\n"
        "                       names are: output_func, error_func, input_done, and\n"
        "                       add_semi, getdata_func, putdata_func, setbp_func,\n"
        "                       disasm_func, and enable_ctrlr.\n");

    _cinside_output(info,
        "$show all              Display all known variables, functions, and strings.\n"
        "$show functions        Display all known functions.\n"
        "$show strings          Display all entered strings.\n"
        "$show vars             Display all known local and global variables.\n");

    _cinside_output(info,
        "$time <statement>      Display the execution time of each function in\n"
        "                       <statement>.\n");

    _cinside_output(info,
        "$unset <var>           Remove the known variable <var>.\n");

    _cinside_output(info,
        "$version               Display libc-inside version information.\n");

    _cinside_output(info,
        "$words <string>[, <ifs>]\n"
        "                       Create and return an iterator containing all words in\n"
        "                       <string>, using characters from the string <ifs> (if\n"
        "                       provided) as word separators.  The default separators are\n"
        "                       space, tab, and newline.  The return value can be treated\n"
        "                       as a string, initially containing the first word (or\n"
        "                       empty string if no words).  See also $next and $last.\n");

    _cinside_output(info,
        "\n"
        "Built-in commands can alternatively be prefixed with '/' instead of '$'.\n");

    return CINSIDE_NOP;
}

static int _cinside_builtin_exit(cinside_info *info, size_t num_params,
                                 uint32_t *params, uint32_t *result,
                                 size_t *num, uint32_t **lval_addr)
{
    return CINSIDE_SUCCESS_EXIT;
}

static int _cinside_builtin_errno(cinside_info *info, size_t num_params,
                                  uint32_t *params, uint32_t *result,
                                  size_t *num, uint32_t **lval_addr)
{
    char *msg;
    int quiet;

    quiet = 0;
    if (num_params == 1)
    {
        if (strcmp((char *)params, "quiet") == 0)
        {
            quiet = 1;
        }
        else
        {
            return _cinside_error(info, CINSIDE_ERR_SYNTAX,
                                  "invalid keyword '%s' for $errno",
                                  (char *)params);
        }
    }

    if (!quiet)
    {
        if (info->last_errno == 0)
            msg = "No error";
        else
            msg = strerror(info->last_errno);

        if (msg == NULL)
            msg = "Unknown error";

        _cinside_output(info, "%s (0x%X)\n", msg, info->last_errno);
    }

    *result = info->last_errno;

    CINSIDE_DEBUG("($errno = 0x%X)\n", info->last_errno);
    return CINSIDE_SUCCESS;
}

static int _cinside_builtin_show(cinside_info *info, size_t num_params,
                                 uint32_t *params, uint32_t *result,
                                 size_t *num, uint32_t **lval_addr)
{
    int ret;
    char *arg;

    arg = (char *)params;
    if (strcmp(arg, "vars") == 0)
    {
        return _cinside_builtin_show_vars(info);
    }
    else if (strcmp(arg, "functions") == 0)
    {
        return _cinside_builtin_show_functions(info);
    }
    else if (strcmp(arg, "strings") == 0)
    {
        return _cinside_builtin_show_strings(info);
    }
    else if (strcmp(arg, "all") == 0)
    {
        ret = _cinside_builtin_show_vars(info);
        if (ret == CINSIDE_NOP)
            ret = _cinside_builtin_show_functions(info);

        if (ret == CINSIDE_NOP)
            ret = _cinside_builtin_show_strings(info);

        return ret;
    }
    else
    {
        return _cinside_error(info, CINSIDE_ERR_SYNTAX,
                              "invalid keyword '%s' for $show", arg);
    }
}

static int _cinside_builtin_show_vars(cinside_info *info)
{
    int j;
    size_t i;
    cinside_variable *var;

    _cinside_output(info, "%u variable%s defined (maximum %u)\n",
                    info->num_vars, ((info->num_vars == 1) ? "" : "s"),
                    info->max_vars);

    for (i = 0; i < info->num_vars; i++)
    {
        var = &(info->vars[i]);
        _cinside_output(info, "    0x%08X: %16s =", (unsigned int)(var->addr),
                        var->name);

        if (var->addr == NULL)
        {
            _cinside_output(info, " %-22s", "(NULL)");
        }
        else if (var->list_items == 0)
        {
            _cinside_output(info, " 0x%08X/%-11d", *(var->addr),
                            *(var->addr));
        }
        else
        {
            _cinside_output(info, " {");
            for (j = 0; j < var->list_items; j++)
            {
                _cinside_output(info, "%s0x%08X", ((j == 0) ? "" : ", "),
                                var->addr[j]);
            }

            _cinside_output(info, "}");
        }

        if (var->list_items == 0)
        {
            if (var->addr == &(var->local_value))
            {
                _cinside_output(info, " (local)");
            }
            else
            {
                _cinside_output(info, " (global");
                _cinside_analyze_global(info, var);
                _cinside_output(info, ")");
            }
        }

        _cinside_output(info, "\n");
    }

    return CINSIDE_NOP;
}

static int _cinside_builtin_show_functions(cinside_info *info)
{
    size_t i;

    _cinside_output(info, "%u function%s known (maximum %u)\n",
                    info->num_functions,
                    ((info->num_functions == 1) ? "" : "s"),
                    info->max_functions);

    for (i = 0; i < info->num_functions; i++)
    {
        _cinside_output(info, "    0x%08X: %s()\n",
                        (unsigned int)(info->functions[i].addr),
                        info->functions[i].name);
    }

    return CINSIDE_NOP;
}

static int _cinside_builtin_show_strings(cinside_info *info)
{
    int ret;
    unsigned int num_strings;
    _cinside_string_hdr *this_str;
    char *printable;
    size_t max_len;

    this_str = info->strings;
    num_strings = 0;
    max_len = 0;
    while (this_str != NULL)
    {
        num_strings++;
        if (this_str->len > max_len)
            max_len = this_str->len;

        this_str = this_str->next;
    }

    _cinside_output(info, "%u string literal%s\n", num_strings,
                    ((num_strings == 1) ? "" : "s"));

    /* worst case: every char is octal \NNN, + NUL */
    max_len = (max_len * 4) + 1;

    /* freed in _cinside_builtin_show_strings() */
    if ((printable = malloc(max_len)) == NULL)
        return _cinside_error(info, CINSIDE_ERR_RESOURCES, NULL);

    this_str = info->strings;
    while (this_str != NULL)
    {
        ret = _cinside_copy_printable(info, this_str, printable, max_len);
        if (ret != CINSIDE_SUCCESS)
        {
            free(printable);
            return ret;
        }

        _cinside_output(info, "    0x%X: '%s'\n", (unsigned int)this_str->str,
                        printable);

        this_str = this_str->next;
    }

    free(printable);
    return CINSIDE_NOP;
}

static int _cinside_builtin_unset(cinside_info *info, size_t num_params,
                                  uint32_t *params, uint32_t *result,
                                  size_t *num, uint32_t **lval_addr)
{
    size_t i;
    char *arg;
    cinside_variable *var;

    arg = (char *)params;
    for (i = 0; i < info->num_vars; i++)
    {
        var = &(info->vars[i]);
        if (strcmp(var->name, arg) == 0)
            break;
    }

    if (i == info->num_vars)
    {
        return _cinside_error(info, CINSIDE_ERR_NOT_FOUND, "'%s' not defined",
                              arg);
    }

    for (; i < info->num_vars; i++)
    {
        memcpy(&(info->vars[i]), &(info->vars[i + 1]),
               sizeof(cinside_variable));
    }

    info->num_vars--;
    return CINSIDE_NOP;
}

static int _cinside_builtin_clear(cinside_info *info, size_t num_params,
                                  uint32_t *params, uint32_t *result,
                                  size_t *num, uint32_t **lval_addr)
{
    int ret;
    void **this_buf, **next_buf;
    char *arg;

    arg = (char *)params;
    if (strcmp(arg, "vars") == 0)
    {
        info->num_vars = 0;
    }
    else if (strcmp(arg, "functions") == 0)
    {
        info->num_functions = 0;
    }
    else if (strcmp(arg, "all") == 0)
    {
        info->num_vars = 0;
        info->num_functions = 0;

        if ((ret = _cinside_list_reset(info, info->lists)) != CINSIDE_SUCCESS)
            return ret;

        ret = _cinside_list_reset(info, info->vals_stack);
        if (ret != CINSIDE_SUCCESS)
            return ret;

        this_buf = info->strings;
        while (this_buf != NULL)
        {
            next_buf = (void **)*this_buf;
            free(this_buf);
            this_buf = next_buf;
        }

        info->strings = NULL;
    }
    else
    {
        return _cinside_error(info, CINSIDE_ERR_SYNTAX,
                              "invalid keyword '%s' for $clear", arg);
    }

    return CINSIDE_NOP;
}

static int _cinside_builtin_load(cinside_info *info, size_t num_params,
                                 uint32_t *params, uint32_t *result,
                                 size_t *num, uint32_t **lval_addr)
{
    int ret;

    if ((ret = _cinside_lkup_load(info, (char *)params)) != CINSIDE_SUCCESS)
        return ret;

    return CINSIDE_NOP;
}

static int _cinside_builtin_dump(cinside_info *info, size_t num_params,
                                 uint32_t *params, uint32_t *result,
                                 size_t *num, uint32_t **lval_addr)
{
    uint32_t i, j, dump_len;
    uint8_t *bval, *bounce_buf, *updated_dump_addr;
    uint16_t *wval;
    uint32_t *dwval;
    unsigned char c, copy_data[17];

    if (num_params != 0)
    {
        if (num_params == 3)
        {
            if ((params[2] != 1) && (params[2] != 2) && (params[2] != 4))
            {
                return _cinside_error(info, CINSIDE_ERR_SYNTAX,
                                      "invalid size 0x%X for $dump",
                                      params[2]);
            }

            info->dump_size = params[2];
        }

        if (num_params >= 2)
            info->dump_len = params[1];

        info->dump_addr = (uint8_t *)(params[0]);
    }

    if (info->dump_size == 0)
        info->dump_size = 1;

    if (info->dump_len == 0)
    {
        info->dump_len = 128;
        if (info->dump_size == 2)
            info->dump_len /= 2;
        else if (info->dump_size == 4)
            info->dump_len /= 4;
    }

    dump_len = info->dump_len;
    if (info->dump_size == 2)
    {
        dump_len <<= 1;
        info->dump_addr = (uint8_t *)((uint32_t)(info->dump_addr) & ~1);
    }
    else if (info->dump_size == 4)
    {
        dump_len <<= 2;
        info->dump_addr = (uint8_t *)((uint32_t)(info->dump_addr) & ~3);
    }

    if ((bounce_buf = malloc(dump_len)) == NULL)
        return _cinside_error(info, CINSIDE_ERR_RESOURCES, NULL);

    if (info->get_data_function != NULL)
    {
        dump_len = info->get_data_function(bounce_buf,
                                           (uint32_t)(info->dump_addr),
                                           dump_len);

        bval = bounce_buf;
    }
    else
    {
        bval = info->dump_addr;
    }

    updated_dump_addr = info->dump_addr;
    memset(copy_data, 0, sizeof(copy_data));
    for (i = 0; i < dump_len; i++)
    {
        c = *(bval++);
        updated_dump_addr++;
        copy_data[i % 16] = c;

        if ((i % 16) == 15)
        {
            _cinside_output(info, "%08X:", info->dump_addr);

            wval = (uint16_t *)(copy_data);
            dwval = (uint32_t *)(copy_data);
            for (j = 0; j < 16; j++)
            {
                c = copy_data[j];
                if (info->dump_size == 1)
                    _cinside_output(info, " %02X", c);
                else if ((info->dump_size == 2) && ((j % 2) == 0))
                    _cinside_output(info, " %04X", *(wval++));
                else if ((info->dump_size == 4) && ((j % 4) == 0))
                    _cinside_output(info, " %08X", *(dwval++));

                if (!isprint(c))
                    copy_data[j] = '.';
            }

            _cinside_output(info, "  %s\n", copy_data);
            memset(copy_data, 0, sizeof(copy_data));
            info->dump_addr = updated_dump_addr;
        }
    }

    if ((i % 16) != 0)
    {
        _cinside_output(info, "%08X:", info->dump_addr);

        wval = (uint16_t *)(copy_data);
        dwval = (uint32_t *)(copy_data);
        for (j = 0; j < (i % 16); j++)
        {
            c = copy_data[j];
            if (info->dump_size == 1)
                _cinside_output(info, " %02X", c);
            else if ((info->dump_size == 2) && ((j % 2) == 0))
                _cinside_output(info, " %04X", *(wval++));
            else if ((info->dump_size == 4) && ((j % 4) == 0))
                _cinside_output(info, " %08X", *(dwval++));

            if (!isprint(c))
                copy_data[j] = '.';
        }

        copy_data[i % 16] = '\0';
        for (j = (i % 16); j < 16; j++)
        {
            if (info->dump_size == 1)
                _cinside_output(info, "   ");
            else if ((info->dump_size == 2) && ((j % 2) == 0))
                _cinside_output(info, "     ");
            else if ((info->dump_size == 4) && ((j % 4) == 0))
                _cinside_output(info, "         ");
        }

        _cinside_output(info, "  %s\n", copy_data);
        info->dump_addr = updated_dump_addr;
    }

    free(bounce_buf);
    return CINSIDE_NOP;
}

static int _cinside_builtin_mod(cinside_info *info, size_t num_params,
                                uint32_t *params, uint32_t *result,
                                size_t *num, uint32_t **lval_addr)
{
    uint32_t mod_val;
    uint8_t *mod_addr;
    uint16_t *wval;
    uint32_t *dwval;

    if (num_params == 3)
    {
        if ((params[2] != 1) && (params[2] != 2) && (params[2] != 4))
        {
            return _cinside_error(info, CINSIDE_ERR_SYNTAX,
                                  "invalid size 0x%X for $mod", params[2]);
        }

        info->mod_size = params[2];
    }

    mod_val = params[1];
    mod_addr = (uint8_t *)(params[0]);
    if (info->mod_size == 0)
        info->mod_size = 1;

    if ((info->put_data_function != NULL) && (info->get_data_function != NULL))
    {
        info->get_data_function((uint8_t *)result, (uint32_t)mod_addr,
                                info->mod_size);

        info->put_data_function((uint8_t *)&mod_val, (uint32_t)mod_addr,
                                info->mod_size);

    }
    else
    {
        wval = (uint16_t *)(mod_addr);
        dwval = (uint32_t *)(mod_addr);
        if (info->mod_size == 1)
        {
            if (mod_val > 0xFF)
            {
                return _cinside_error(info, CINSIDE_ERR_SYNTAX,
                                      "value 0x%X exceeds byte range",
                                      mod_val);
            }

            *result = *mod_addr;
            *mod_addr = mod_val;
        }
        else if (info->mod_size == 2)
        {
            if (mod_val > 0xFFFF)
            {
                return _cinside_error(info, CINSIDE_ERR_SYNTAX,
                                      "value 0x%X exceeds word range",
                                      mod_val);
            }

            *result = *wval;
            *wval = mod_val;
        }
        else if (info->mod_size == 4)
        {
            *result = *dwval;
            *dwval = mod_val;
        }
    }

    return CINSIDE_NOP;
}

static int _cinside_builtin_time(cinside_info *info, size_t num_params,
                                 uint32_t *params, uint32_t *result,
                                 size_t *num, uint32_t **lval_addr)
{
    int ret;
    struct timeval tv_before, tv_after;

    info->flags |= CINSIDE_FLAG_TIME;
    gettimeofday(&tv_before, NULL);

    ret = _cinside_eval_tokens(info, params[0], params[1], result);
    gettimeofday(&tv_after, NULL);
    _cinside_time_diff(&tv_before, &tv_after);
    _cinside_output(info, "total: %u.%06us\n", tv_after.tv_sec,
                    tv_after.tv_usec);

    info->flags &= ~(CINSIDE_FLAG_TIME);
    return ret;
}

static int _cinside_builtin_list(cinside_info *info, size_t num_params,
                                 uint32_t *params, uint32_t *result,
                                 size_t *num, uint32_t **lval_addr)
{
    int i, ret;
    uint32_t *list_addr;
    uint32_t count, init_val;

    count = params[0];
    init_val = ((num_params == 2) ? params[1]: 0);

    ret = _cinside_list_reserve(info, info->lists, count, &list_addr);
    if (ret != CINSIDE_SUCCESS)
        return ret;

    for (i = 0; i < count; i++)
    {
        ret = _cinside_list_push(info, info->lists, init_val);
        if (ret != CINSIDE_SUCCESS)
            return ret;
    }

    *result = (uint32_t)list_addr;

    if (lval_addr != NULL)
        *lval_addr = list_addr;

    if (num != NULL)
        *num = count;

    return CINSIDE_SUCCESS;
}

static int _cinside_builtin_license(cinside_info *info, size_t num_params,
                                    uint32_t *params, uint32_t *result,
                                    size_t *num, uint32_t **lval_addr)
{
    char *arg;

    /*
     * Ensure that the section numbers below are kept up to date with respect
     * to the COPYING file.  Providing -1 for the first section means start at
     * the beginning of the file, and -1 for the last section means go to the
     * end of the file.
     */
    arg = (char *)params;
    if (num_params == 0)
    {
        return _cinside_license_show(info, -1, -1);    /* -1, -1: whole file */
    }
    else if (strcmp(arg, "copying") == 0)
    {
        return _cinside_license_show(info, 0, 14);      /* keep up to date */
    }
    else if (strcmp(arg, "warranty") == 0)
    {
        return _cinside_license_show(info, 15, 17);     /* keep up to date */
    }
    else
    {
        return _cinside_error(info, CINSIDE_ERR_SYNTAX,
                              "invalid keyword '%s' for $license", arg);
    }
}

static int _cinside_license_show(cinside_info *info, int first_section,
                                 int last_section)
{
    int ret, first;
    unsigned int last;
    unsigned long cur_num, next_num;
    char *license_buf, *cur, *next;

    /* freed in _cinside_license_show() */
    if ((license_buf = malloc(_CINSIDE_LICENSE_LENGTH + 1)) == NULL)
        return _cinside_error(info, CINSIDE_ERR_RESOURCES, NULL);

    memcpy(license_buf, _cinside_license, _CINSIDE_LICENSE_LENGTH);
    license_buf[_CINSIDE_LICENSE_LENGTH] = '\0';

    cur = license_buf;
    if (_cinside_license_find_next(info, cur, &next,
                                   &next_num) != CINSIDE_SUCCESS)
    {
        free(license_buf);
        return _cinside_error(info, CINSIDE_ERR_GENERAL,
                              "invalid license text");
    }

    first = first_section;
    last = (unsigned int)last_section;  /* convert to unsigned, -1 ==> max */

    *next = '\0';
    if (first == -1)
        _cinside_output(info, "%s", cur);

    do
    {
        cur = next;
        cur_num = next_num;
        *cur = ' ';
        ret = _cinside_license_find_next(info, cur, &next, &next_num);
        if (ret == CINSIDE_SUCCESS)
            *next = '\0';

        if (((int)cur_num >= first) && (cur_num <= last))
            _cinside_output(info, "%s", cur);
    } while (ret == CINSIDE_SUCCESS);

    free(license_buf);
    return CINSIDE_NOP;
}

static int _cinside_license_find_next(cinside_info *info, char *cur,
                                      char **next, unsigned long *num)
{
    char *lf, *num_end, *end_of_terms;

    /*
     * Skip past the first character, in the event that it is at the beginning
     * of a section (so we will still find the "next" section).
     */
    cur++;

    end_of_terms = CINSIDE_LICENSE_END_OF_TERMS;
    while ((lf = strchr(cur, '\n')) != NULL)
    {
        *num = strtoul(lf + 4, &num_end, 10);
        if ((*(lf + 1) == '\n') && (*(lf + 2) == ' ') && (*(lf + 3) == ' ') &&
            (num_end != (lf + 4)) && (*num_end == '.') &&
            (*(num_end + 1) == ' '))
        {
            *next = (lf + 2);
            break;
        }

        if (*(lf + 1) == '\n')
        {
            cur = (lf + 2);
            while ((*cur == ' ') || (*cur == '\t'))
                cur++;

            if (strncmp(cur, end_of_terms, strlen(end_of_terms)) == 0)
            {
                *next = (lf + 2);
                *num = ~0;
                break;
            }
        }

        cur = ++lf;
    }

    if (lf == NULL)
        return CINSIDE_ERR_NOT_FOUND;

    return CINSIDE_SUCCESS;
}

static int _cinside_builtin_version(cinside_info *info, size_t num_params,
                                    uint32_t *params, uint32_t *result,
                                    size_t *num, uint32_t **lval_addr)
{
    _cinside_output(info, "lib%s\n", PACKAGE_STRING);
    return CINSIDE_NOP;
}

static int _cinside_builtin_get(cinside_info *info, size_t num_params,
                                uint32_t *params, uint32_t *result,
                                size_t *num, uint32_t **lval_addr)
{
    int ret;
    size_t i, len, max_len;
    uint32_t val;
    char *arg;

    arg = (char *)params;
    max_len = 0;
    for (i = 0; i <= CINSIDE_MAX_ID; i++)
    {
        if ((num_params == 1) && (strcmp(arg, _cinside_set_ids[i]) != 0))
            continue;

        if (num_params == 1)
        {
            if ((ret = cinside_get(info, i, result)) != CINSIDE_SUCCESS)
                return ret;

            return CINSIDE_SUCCESS;
        }
        else
        {
            len = strlen(_cinside_set_ids[i]);
            if (len > max_len)
                max_len = len;
        }
    }

    if (num_params == 0)
    {
        val = 0;
        for (i = 0; i <= CINSIDE_MAX_ID; i++)
        {
            if ((ret = cinside_get(info, i, &val)) != CINSIDE_SUCCESS)
                return ret;

            _cinside_output(info, "%-*s : 0x%08X/%d\n", max_len,
                            _cinside_set_ids[i], val, val);
        }

        return CINSIDE_NOP;
    }

    return _cinside_error(info, CINSIDE_ERR_NOT_FOUND,
                          "invalid configuration id '%s'", arg);
}

static int _cinside_builtin_set(cinside_info *info, size_t num_params,
                                uint32_t *params, uint32_t *result,
                                size_t *num, uint32_t **lval_addr)
{
    int ret;
    size_t i, num_tokens;
    char *arg;

    num_tokens = (params[1] - params[0]) + 2;
    if ((num_tokens < 6) || (info->token[params[0]] != CINSIDE_TOKEN_NAME) ||
        (info->token[params[0] + 2] != CINSIDE_TOKEN_COMMA))
    {
        return _cinside_error(info, CINSIDE_ERR_SYNTAX, "invalid use of $set");
    }

    arg = (char *)(info->token[params[0] + 1]);
    for (i = 0; i <= CINSIDE_MAX_ID; i++)
    {
        if (strcmp(arg, _cinside_set_ids[i]) == 0)
        {
            if ((ret = cinside_get(info, i, result)) != CINSIDE_SUCCESS)
                return ret;

            break;
        }
    }

    if (i > CINSIDE_MAX_ID)
    {
        return _cinside_error(info, CINSIDE_ERR_NOT_FOUND,
                              "invalid configuration id '%s'", arg);
    }

    ret = _cinside_eval_expr(info, params[0] + 4, params[1], NULL, NULL);
    if (CINSIDE_NO_RESULT(ret))
    {
        return _cinside_error(info, CINSIDE_ERR_SYNTAX,
                              "invalid expression for $set");
    }

    if (ret != CINSIDE_SUCCESS)
        return ret;

    return cinside_set(info, i, info->token[params[0] + 5]);
}

static int _cinside_builtin_files(cinside_info *info, size_t num_params,
                                  uint32_t *params, uint32_t *result,
                                  size_t *num, uint32_t **lval_addr)
{
    char *buf;

    if ((buf = _cinside_files((char **)params, num_params)) == NULL)
        return _cinside_error(info, CINSIDE_ERR_RESOURCES, NULL);

    *result = (uint32_t)buf;
    return CINSIDE_SUCCESS;
}

static int _cinside_builtin_words(cinside_info *info, size_t num_params,
                                  uint32_t *params, uint32_t *result,
                                  size_t *num, uint32_t **lval_addr)
{
    char *buf;

    buf = _cinside_words((char *)(params[0]),
                         ((num_params == 2) ? (char *)(params[1]) : NULL));

    if (buf == NULL)
        return _cinside_error(info, CINSIDE_ERR_RESOURCES, NULL);

    *result = (uint32_t)buf;
    return CINSIDE_SUCCESS;
}

static int _cinside_builtin_count(cinside_info *info, size_t num_params,
                                  uint32_t *params, uint32_t *result,
                                  size_t *num, uint32_t **lval_addr)
{
    *result = _cinside_count((char *)(params[0]));
    return CINSIDE_SUCCESS;
}

static int _cinside_builtin_next(cinside_info *info, size_t num_params,
                                 uint32_t *params, uint32_t *result,
                                 size_t *num, uint32_t **lval_addr)
{
    *result = (uint32_t)_cinside_next((char *)(params[0]));
    return CINSIDE_SUCCESS;
}

static int _cinside_builtin_last(cinside_info *info, size_t num_params,
                                 uint32_t *params, uint32_t *result,
                                 size_t *num, uint32_t **lval_addr)
{
    *result = _cinside_last((char *)(params[0]));
    return CINSIDE_SUCCESS;
}

static int _cinside_builtin_go(cinside_info *info, size_t num_params,
                               uint32_t *params, uint32_t *result,
                               size_t *num, uint32_t **lval_addr)
{
    return CINSIDE_SUCCESS_CONT;
}

static int _cinside_builtin_bp(cinside_info *info, size_t num_params,
                               uint32_t *params, uint32_t *result,
                               size_t *num, uint32_t **lval_addr)
{
    int ret;
    uint32_t addr;
    char *expr;

    if (info->set_bp_function == NULL)
    {
        return _cinside_error(info, CINSIDE_ERR_CANNOT,
                              "breakpoints are not supported");
    }

    if (num_params == 0)
    {
        info->set_bp_function(0xFFFFFFFF, NULL);
        return CINSIDE_NOP;
    }

    addr = params[0];
    expr = ((num_params == 2) ? (char *)(params[1]) : "1");

    ret = info->set_bp_function(addr, expr);
    if (ret != CINSIDE_SUCCESS)
        return _cinside_error(info, ret, NULL);

    return CINSIDE_NOP;
}

static int _cinside_builtin_disasm(cinside_info *info, size_t num_params,
                                   uint32_t *params, uint32_t *result,
                                   size_t *num, uint32_t **lval_addr)
{
    uint32_t i, j, dump_len;
    uint8_t *bval, *bounce_buf, *updated_dump_addr;
    uint16_t *wval;
    uint32_t *dwval;
    unsigned char c, copy_data[17];

    if (info->disasm_function == NULL)
    {
        return _cinside_error(info, CINSIDE_ERR_CANNOT,
                              "disassembly is not supported");
    }

    if (num_params != 0)
    {
        if (num_params == 2)
            info->disasm_lines = params[1];

        info->disasm_addr = (uint8_t *)(params[0]);
    }

    if (info->disasm_lines == 0)
        info->disasm_lines = 8;

    info->disasm_addr += info->disasm_function((uint32_t)info->disasm_addr,
                                               info->disasm_lines);

    return CINSIDE_NOP;
}
