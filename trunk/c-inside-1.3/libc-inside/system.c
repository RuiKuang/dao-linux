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

/* system.c - system-specific functions, including cinside_go() */

#include <stdio.h>          /* printf, fgets */
#include <stdlib.h>         /* malloc, free, getenv */
#include <string.h>         /* memcmp, strlen, strdup, strncmp, strcpy,
                                strcat */
#include <sys/time.h>       /* gettimeofday */
#include <time.h>           /* gettimeofday */
#include <errno.h>          /* errno */

#include "language.h"

#if HAVE_LIBDL              /* libdl has priority over direct linking */
#include <dlfcn.h>
#elif HAVE_LIBREADLINE
#include <readline/readline.h>
#include <readline/history.h>
#endif

int _cinside_caller_inner(uint32_t *args, uint32_t args_size,
                          struct timeval *tv_bp, struct timeval *tv_ap,
                          int *p_errno, int *p_last_errno,
                          uint32_t stack_align_offset, uint32_t gtod_fp);

#define CINSIDE_STACK_ALIGN 16          /* stack alignment required by ABI */
#define CINSIDE_INTERNAL_READLINE_CHUNK_SIZE    1000
#define CINSIDE_READLINE_ENV "READLINE_PATH"

#if HAVE_LIBDL
static char *_cinside_readline_paths[] =
{
    "libreadline", "libreadline.so", "libreadline.dylib",
    "/usr/local/lib/libreadline.so", "/usr/local/lib/libreadline.dylib", NULL
};
#endif

const unsigned char _cinside_syscall[] = {0x65, 0xff, 0x15, 0x10, 0, 0, 0};
const size_t _cinside_syscall_size = sizeof(_cinside_syscall);

static cinside_info *_cinside_completion_info;

static int _cinside_go_error(char *str);
static int _cinside_go_output(char *str);
static char **_cinside_completion(const char *text, int start, int end);
static char *_cinside_completion_generator(const char *text, int state);
static char *_cinside_internal_readline(const char *prompt);
static void _cinside_internal_add_history(const char *str);

typedef char *(*readline_fp)(char *);
typedef void (*add_history_fp)(char *);
typedef char *(*compentry_func_fp)(const char *, int);
typedef char **(*completion_matches_fp)(const char *, compentry_func_fp);

/* global pointers to readline global variables */
int *attempted_completion_over, *completion_append_character;

/* local pointers to readline functions */
completion_matches_fp completion_matches_f;

int cinside_go(cinside_variable *preload_vars,
               cinside_function *preload_functions, size_t max_vars,
               size_t max_functions)
{
    int ret;
    cinside_info *info;

    ret = cinside_init(&info, preload_vars, preload_functions, max_vars,
                       max_functions);

    if (ret != CINSIDE_SUCCESS)
        return ret;

    ret = cinside_set(info, CINSIDE_ID_ERROR_FUNC,
                      (uint32_t)_cinside_go_error);

    if (ret != CINSIDE_SUCCESS)
        return ret;

    ret = cinside_set(info, CINSIDE_ID_OUTPUT_FUNC,
                      (uint32_t)_cinside_go_output);

    if (ret != CINSIDE_SUCCESS)
        return ret;

    ret = cinside_set(info, CINSIDE_ID_ADD_SEMI, 1);
    if (ret != CINSIDE_SUCCESS)
        return ret;

    return cinside_loop(info, "; ");
}

void *dl_handle;

int cinside_loop(cinside_info *info, char *prompt)
{
    int i, ret, use_local;
    char *cmd, *input_buf, *readline_path, *cur_prompt;
    uint32_t result;

    /* local pointers to readline global variables */
    int *completion_query_items;
    const char **readline_name, **basic_word_break_characters;
    const char **special_prefixes;
    cinside_fp *attempted_completion_function;
    FILE **instream;

    /* local pointers to readline functions */
    readline_fp readline_f;
    add_history_fp add_history_f;

    /*
     * This, unfortunately, must be a global.  Thus, if multiple threads call
     * cinside_go() (integrity of which will depend on the readline library),
     * the most recent caller of cinside_go() will be the one whose known
     * variable and function names are searched.
     */
    _cinside_completion_info = info;

    attempted_completion_over = NULL;
    completion_append_character = NULL;
    completion_query_items = NULL;
    readline_name = NULL;
    basic_word_break_characters = NULL;
    special_prefixes = NULL;
    attempted_completion_function = NULL;
    instream = NULL;
    completion_matches_f = NULL;
    readline_f = NULL;
    add_history_f = NULL;
    use_local = 1;

    readline_path = getenv(CINSIDE_READLINE_ENV);
    i = 0;

#if HAVE_LIBDL

    if (dl_handle == NULL)
    {
        do
        {
            if (readline_path != NULL)
                dl_handle = dlopen(readline_path, RTLD_LAZY | RTLD_GLOBAL);

            if (dl_handle != NULL)
                break;

            readline_path = _cinside_readline_paths[i++];
        } while (readline_path != NULL);
    }

    if (dl_handle != NULL)
    {
        attempted_completion_over = dlsym(dl_handle,
                                          "rl_attempted_completion_over");

        completion_append_character = dlsym(dl_handle,
                                            "rl_completion_append_character");

        completion_query_items = dlsym(dl_handle, "rl_completion_query_items");
        readline_name = dlsym(dl_handle, "rl_readline_name");
        basic_word_break_characters = dlsym(dl_handle,
                                            "rl_basic_word_break_characters");

        special_prefixes = dlsym(dl_handle, "rl_special_prefixes");
        attempted_completion_function = dlsym(dl_handle,
                                           "rl_attempted_completion_function");

        instream = dlsym(dl_handle, "rl_instream");
        completion_matches_f = (completion_matches_fp)dlsym(dl_handle,
                                                      "rl_completion_matches");

        if (completion_matches_f == NULL)   /* libedit screwed the name up? */
        {
            completion_matches_f = (completion_matches_fp)dlsym(dl_handle,
                                                         "completion_matches");
        }

        readline_f = (readline_fp)dlsym(dl_handle, "readline");
        add_history_f = (add_history_fp)dlsym(dl_handle, "add_history");

        if ((attempted_completion_over != NULL) &&
            (completion_append_character != NULL) &&
            (completion_query_items != NULL) && (readline_name != NULL) &&
            (basic_word_break_characters != NULL) &&
            (special_prefixes != NULL) &&
            (attempted_completion_function != NULL) && (instream != NULL) &&
            (completion_matches_f != NULL) && (readline_f != NULL) &&
            (add_history_f != NULL))
        {
            use_local = 0;
        }
    }

#elif HAVE_LIBREADLINE

    attempted_completion_over = &rl_attempted_completion_over;
    completion_append_character = &rl_completion_append_character;
    completion_query_items = &rl_completion_query_items;
    readline_name = &rl_readline_name;
    basic_word_break_characters = &rl_basic_word_break_characters;
    special_prefixes = &rl_special_prefixes;
    attempted_completion_function = (cinside_fp *)&rl_attempted_completion_function;
    instream = &rl_instream;
#if HAVE_RL_COMPLETION_MATCHES
    completion_matches_f = rl_completion_matches;
#else                                       /* libedit screwed the name up? */
    completion_matches_f = completion_matches;
#endif
    readline_f = (readline_fp)readline;
    add_history_f = (add_history_fp)add_history;
    use_local = 0;

#endif

    if (use_local)
    {
        readline_f = (readline_fp)_cinside_internal_readline;
        add_history_f = (add_history_fp)_cinside_internal_add_history;
    }

    if (readline_name != NULL)
        *readline_name = "c-inside";

    if (attempted_completion_function != NULL)
        *attempted_completion_function = (cinside_fp)_cinside_completion;

    if (completion_query_items != NULL)
        *completion_query_items = -1;

    if (basic_word_break_characters != NULL)
        *basic_word_break_characters = CINSIDE_SEPARATORS;

    if (special_prefixes != NULL)
        *special_prefixes = "$/";

    if ((instream != NULL) && (*instream == NULL))
        *instream = stdin;                          /* BUG in readline */

    input_buf = NULL;
    cur_prompt = prompt;
    do
    {
        if (input_buf != NULL)
        {
            free(input_buf);
            input_buf = NULL;
        }

        if ((input_buf = readline_f(cur_prompt)) == NULL)
            break;

        if (*input_buf == '\0')
            continue;

        cur_prompt = prompt;
        add_history_f(input_buf);
        cmd = input_buf;
        if ((ret = cinside_eval(info, cmd, &result)) == CINSIDE_SUCCESS)
            _cinside_output(info, " = 0x%08X/%d\n", result, result);
        else if (ret == CINSIDE_PARTIAL)
            cur_prompt = "";
        else if ((ret == CINSIDE_SUCCESS_EXIT) || (ret == CINSIDE_SUCCESS_CONT))
            break;
    } while ((ret == CINSIDE_PARTIAL) ||
             !(info->flags & CINSIDE_FLAG_EN_CTRLR));

    if (ret == CINSIDE_SUCCESS_EXIT)
    {
        ret = cinside_set(info, CINSIDE_ID_INPUT_DONE, 1);
        if (ret != CINSIDE_SUCCESS)
            return ret;

        ret = cinside_eval(info, "", NULL);
        if (CINSIDE_RET_ERROR(ret))
            return ret;

#if HAVE_LIBDL
        if (dl_handle != NULL)
            dlclose(dl_handle);
#endif

        ret = CINSIDE_SUCCESS_EXIT;
    }

    return ret;
}

static int _cinside_go_error(char *str)
{
    printf("c-inside: %s\n", str);
    return CINSIDE_SUCCESS;
}

static int _cinside_go_output(char *str)
{
    printf("%s", str);
    return CINSIDE_SUCCESS;
}

int _cinside_analyze_global(cinside_info *info, cinside_variable *var)
{
    int ret;
    void *old_handlers, *fault_addr;
    volatile char sep;          /* may change between sigsetjmp/siglongjmp */
    int i;
    char *c;

    sep = ':';
    ret = _cinside_setup_signals(info, &old_handlers);
    if (ret != CINSIDE_SUCCESS)
        return ret;

    if (_cinside_invalid_access())
    {
        _cinside_restore_signals(info, old_handlers);
        _cinside_get_fault(info, &fault_addr, NULL);
        _cinside_output(info, "%c %sinaccessible", sep,
                        ((fault_addr == var->addr) ? "" : "almost "));

        return CINSIDE_SUCCESS;
    }

    if ((*(var->addr) & 0x00FFFFFF) == 0xE58955)
    {
        _cinside_output(info, "%c function?", sep);
        sep = ',';
    }

    c = (char *)(var->addr);
    for (i = 0; i < 64; i++)
    {
        if ((*c == 0x65) &&
            (memcmp(c, _cinside_syscall, _cinside_syscall_size) == 0))
        {
            _cinside_output(info, "%c syscall?", sep);
            sep = ',';
            break;
        }

        c++;
    }

    _cinside_restore_signals(info, old_handlers);
    return CINSIDE_SUCCESS;
}

int _cinside_caller(cinside_info *info, char *name, uint32_t argc,
                    uint32_t *argv, uint32_t *result)
{
    uint32_t tmp_val, stack_align_offset, gtod_fp;
    struct timeval tv_before, tv_after, *tv_bp, *tv_ap;
    int *errno_p;

    /*
     * This is to keep relocation entries out of the __text section, for
     * building on MacOS X 10.4 IA-32 (and I'm sure others...).  It's not a bad
     * idea to do this anyway, as long as function pointers are 32-bit.
     */
    gtod_fp = (uint32_t)gettimeofday;

    /*
     * Given a stack alignment requirement and argc, and assuming the stack
     * pointer is already properly aligned, this is:
     *      - IA32: how many bytes to subtract prior to pushing all argv[]
     *      - PPC32: how many bytes to use to pad the temporary stack frame
     *        (note, not implemented yet, will be in C-Inside 1.2 or later)
     * so the stack is properly aligned for the call.
     */
    if (argc > 1)
    {
        stack_align_offset = (CINSIDE_STACK_ALIGN -
                              (((argc - 1) * 4) & (CINSIDE_STACK_ALIGN - 1)));
    }
    else
    {
        stack_align_offset = 0;
    }

    argc = ((argc - 1) << 2);   /* modify argc = total size of all arguments */
    tv_bp = &tv_before;
    tv_ap = &tv_after;
    errno_p = &errno;

    tmp_val = _cinside_caller_inner(argv, argc, tv_bp, tv_ap, errno_p,
                                    &(info->last_errno), stack_align_offset,
                                    gtod_fp);

    if (result != NULL)
        *result = tmp_val;

    if (info->flags & CINSIDE_FLAG_TIME)
    {
        _cinside_time_diff(tv_bp, tv_ap);
        _cinside_output(info, "%s(): %u.%06us\n", name, tv_ap->tv_sec,
                        tv_ap->tv_usec);
    }

    return CINSIDE_SUCCESS;
}

void _cinside_time_diff(struct timeval *before, struct timeval *after)
{
    after->tv_sec -= before->tv_sec;
    if (after->tv_usec < before->tv_usec)
    {
        after->tv_usec += 1000000;
        after->tv_sec--;
    }

    after->tv_usec -= before->tv_usec;
}

static char **_cinside_completion(const char *text, int start, int end)
{
    *attempted_completion_over = 1;

    return completion_matches_f(text, _cinside_completion_generator);
}

static char *_cinside_completion_generator(const char *text, int state)
{
    static int len, tmp_len, function_idx, var_idx, builtin_idx, prev_idx;
    _cinside_builtin_def *builtin;
    cinside_info *info;
    char *name, *ret;

    info = _cinside_completion_info;
    if (state == 0)
    {
        len = strlen(text);
        function_idx = 0;
        var_idx = 0;
        builtin_idx = 0;
        prev_idx = SIZE_MAX;
    }

    for (; function_idx < info->num_functions; function_idx++)
    {
        name = info->functions[function_idx].name;
        if ((prev_idx != SIZE_MAX) &&
            (strcmp(name, info->functions[prev_idx].name) == 0))
        {
            continue;
        }

        if (strncmp(name, text, len) == 0)
        {
            prev_idx = function_idx;
            *completion_append_character = '(';

            /* freed by readline */
            return strdup(name);
        }
    }

    if (function_idx == info->num_functions)
    {
        prev_idx = SIZE_MAX;
        function_idx++;
    }

    for (; var_idx < info->num_vars; var_idx++)
    {
        name = info->vars[var_idx].name;
        if ((prev_idx != SIZE_MAX) &&
            (strcmp(name, info->vars[prev_idx].name) == 0))
        {
            continue;
        }

        if (strncmp(name, text, len) == 0)
        {
            prev_idx = var_idx;
            *completion_append_character = '\0';

            /* freed by readline */
            return strdup(name);
        }
    }

    if (var_idx == info->num_vars)
    {
        prev_idx = SIZE_MAX;
        var_idx++;
    }

    /* only show builtin commands if the user has started typing one */
    if ((text[0] == '$') || (text[0] == '/'))
    {
        for (; ; builtin_idx++)
        {
            if ((builtin = _cinside_get_builtin(builtin_idx)) == NULL)
                break;

            if ((prev_idx != SIZE_MAX) &&
                (strcmp(builtin->name,
                        _cinside_get_builtin(prev_idx)->name) == 0))
            {
                continue;
            }

            if ((strncmp(builtin->name, text + 1, len - 1) == 0) &&
                ((info->flags & CINSIDE_FLAG_EN_CTRLR) ||
                 !(builtin->controller_mode)))
            {
                prev_idx = builtin_idx;
                *completion_append_character = ' ';
                tmp_len = strlen(builtin->name);

                /* freed by readline */
                if ((ret = malloc(tmp_len + 2)) != NULL)
                {
                    ret[0] = text[0];
                    strcpy(ret + 1, builtin->name);
                }

                return ret;
            }
        }
    }

    return NULL;
}

static char *_cinside_internal_readline(const char *prompt)
{
    char *chunk, *tmp, *ret;
    size_t len, total;

    ret = NULL;
    total = 0;

    if (prompt != NULL)
    {
        printf("%s", prompt);
        fflush(stdout);
    }

    do
    {
        /* freed in _cinside_internal_readline() or _cinside_go() */
        if (((chunk = malloc(CINSIDE_INTERNAL_READLINE_CHUNK_SIZE)) == NULL) ||
            (fgets(chunk, CINSIDE_INTERNAL_READLINE_CHUNK_SIZE,
                   stdin) == NULL))
        {
            if (chunk != NULL)
                free(chunk);

            if ((ret != chunk) && (ret != NULL))
                free(ret);

            return NULL;
        }

        len = strlen(chunk);
        total += len;

        if (ret != NULL)
        {
            /* freed in _cinside_internal_readline() */
            if ((tmp = malloc(total + 1)) == NULL)
            {
                free(chunk);
                free(ret);
                return NULL;
            }

            strcpy(tmp, ret);
            strcat(tmp, chunk);
            free(chunk);
            chunk = NULL;
            free(ret);
            ret = tmp;
        }
        else
        {
            ret = chunk;
        }

        if ((len < (CINSIDE_INTERNAL_READLINE_CHUNK_SIZE - 1)) ||
            (chunk[len - 1] == '\n'))
        {
            if (chunk[len - 1] == '\n')
                chunk[len - 1] = '\0';

            break;
        }
    } while (1);

    return ret;
}

static void _cinside_internal_add_history(const char *str)
{
    /* the simple fgets() based readline substitution can't do history */
}
