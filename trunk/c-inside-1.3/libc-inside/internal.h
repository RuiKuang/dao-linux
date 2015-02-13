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

/* internal.h - declarations for internal use by libc-inside */

#ifndef __INTERNAL_H__
#define __INTERNAL_H__

#include "config.h"
#include <setjmp.h>         /* sigsetjmp, siglongjmp */
#include <sys/time.h>       /* struct timeval */
#include <time.h>           /* struct timeval */

#include "c-inside.h"

#if defined(CINSIDE_DBG) && (CINSIDE_DBG == 1)
#define CINSIDE_DEBUG(_a...) _cinside_output(info, ## _a)
#define IF_CINSIDE_DEBUG() if (1)
#else
#define CINSIDE_DEBUG(_a...)
#define IF_CINSIDE_DEBUG() if (0)
#endif

#define CINSIDE_PARAM_ERROR() \
    _cinside_error(info, CINSIDE_ERR_PARAMETER, "invalid parameter to %s()", \
                   __FUNCTION__)

/* internal return values */
#define CINSIDE_BREAK           200     /* break statement executed */
#define CINSIDE_CONTINUE        201     /* continue statement executed */

#define CINSIDE_FLAG_TIME       0x01    /* show timing information */
#define CINSIDE_FLAG_PARTIAL    0x02    /* last parse was partial */
#define CINSIDE_FLAG_COMMENT    0x04    /* partial slash-asterisk comment */
#define CINSIDE_FLAG_INPUT_DONE 0x08    /* end-of-input */
#define CINSIDE_FLAG_ADD_SEMI   0x10    /* automatically add ; to each line */
#define CINSIDE_FLAG_EN_CTRLR   0x20    /* enable controller mode ("go" cmd) */

/* c-inside.c */

/* initial sizes/counts (will be re-allocated to grow dynamically as needed) */
#define CINSIDE_DEFAULT_MSG_SIZE 80
#define CINSIDE_MAX_TOKENS      1024

/* handles buffers with escaped newline characters */
#define skip_wspace(_s) \
    while ((*_s == ' ') || (*_s == '\t') || (*_s == '\n') || (*_s == '\r') || \
           ((*_s == '\\') && ((*(_s + 1) == '\n') || (*(_s + 1) == '\0')))) \
    { \
        _s++; \
        if ((*(_s - 1) == '\\') && (*_s == '\n')) \
            _s++; \
    }

#define CINSIDE_STRING_LITERAL  1       /* string literal: may be modified */
#define CINSIDE_STRING_NOESC    2       /* ignore escape (\) char sequences */

typedef struct __cinside_string_hdr
{
    struct __cinside_string_hdr *next;
    unsigned int flags;
    size_t len;
    char *str;
} _cinside_string_hdr;

int _cinside_alloc_tokens(cinside_info *info, uint32_t **token,
                          size_t max_tokens);
int _cinside_get_variable(cinside_info *info, char *str, cinside_variable **v,
                          int create);
int _cinside_get_function(cinside_info *info, char *str, cinside_function **f);
int _cinside_unescape_char(cinside_info *info, char *seq, size_t len,
                           char *val);
int _cinside_string(cinside_info *info, char *str, size_t len,
                    unsigned int flags, _cinside_string_hdr **new_str);
int _cinside_copy_printable(cinside_info *info, _cinside_string_hdr *src,
                            char *dest, size_t max_len);
int _cinside_error(cinside_info *info, int ret, char *fmt, ...);
int _cinside_output(cinside_info *info, char *fmt, ...);


/* namespace.c */

int _cinside_lkup_init(cinside_info *info);
int _cinside_lkup_variable(cinside_info *info, char *name, uint32_t **addr);
int _cinside_lkup_function(cinside_info *info, char *name, cinside_fp *addr);
int _cinside_lkup_load(cinside_info *info, char *name);
int _cinside_lkup_destroy(cinside_info *info);


/* builtin.c */

typedef int (*builtin_fp)(cinside_info *info, size_t num_params,
                          uint32_t *params, uint32_t *result, size_t *num,
                          uint32_t **lval_addr);

#define CINSIDE_PARAMS_NONE     0       /* no parameters (min = 0, max = 0) */
#define CINSIDE_PARAMS_KEYWORD  1       /* single keyword expected */
#define CINSIDE_PARAMS_LIST     2       /* evaluate parameters into a list */
#define CINSIDE_PARAMS_RAW      3       /* do not evaluate parameters */

typedef struct __cinside_builtin_def
{
    char *name;
    builtin_fp f;
    size_t min_params;
    size_t max_params;
    int controller_mode;
    unsigned int param_type;            /* CINSIDE_PARAMS_* */
} _cinside_builtin_def;

#define CINSIDE_BUILTINS \
{ \
    {"bp",      _cinside_builtin_bp,      0, 2, 1, CINSIDE_PARAMS_LIST},    \
    {"clear",   _cinside_builtin_clear,   1, 1, 0, CINSIDE_PARAMS_KEYWORD}, \
    {"count",   _cinside_builtin_count,   1, 1, 0, CINSIDE_PARAMS_LIST},    \
    {"disasm",  _cinside_builtin_disasm,  0, 2, 1, CINSIDE_PARAMS_LIST},    \
    {"dump",    _cinside_builtin_dump,    0, 3, 0, CINSIDE_PARAMS_LIST},    \
    {"errno",   _cinside_builtin_errno,   0, 1, 0, CINSIDE_PARAMS_KEYWORD}, \
    {"exit",    _cinside_builtin_exit,    0, 0, 0, CINSIDE_PARAMS_NONE},    \
    {"files",   _cinside_builtin_files,   1, 0, 0, CINSIDE_PARAMS_LIST},    \
    {"get",     _cinside_builtin_get,     0, 1, 0, CINSIDE_PARAMS_KEYWORD}, \
    {"go",      _cinside_builtin_go,      0, 0, 1, CINSIDE_PARAMS_NONE},    \
    {"help",    _cinside_builtin_help,    0, 0, 0, CINSIDE_PARAMS_NONE},    \
    {"last",    _cinside_builtin_last,    1, 1, 0, CINSIDE_PARAMS_LIST},    \
    {"license", _cinside_builtin_license, 0, 1, 0, CINSIDE_PARAMS_KEYWORD}, \
    {"list",    _cinside_builtin_list,    1, 2, 0, CINSIDE_PARAMS_LIST},    \
    {"load",    _cinside_builtin_load,    1, 1, 0, CINSIDE_PARAMS_KEYWORD}, \
    {"mod",     _cinside_builtin_mod,     2, 3, 0, CINSIDE_PARAMS_LIST},    \
    {"next",    _cinside_builtin_next,    1, 1, 0, CINSIDE_PARAMS_LIST},    \
    {"set",     _cinside_builtin_set,     1, 1, 0, CINSIDE_PARAMS_RAW},     \
    {"show",    _cinside_builtin_show,    1, 1, 0, CINSIDE_PARAMS_KEYWORD}, \
    {"time",    _cinside_builtin_time,    1, 1, 0, CINSIDE_PARAMS_RAW},     \
    {"unset",   _cinside_builtin_unset,   1, 1, 0, CINSIDE_PARAMS_KEYWORD}, \
    {"version", _cinside_builtin_version, 0, 0, 0, CINSIDE_PARAMS_NONE},    \
    {"words",   _cinside_builtin_words,   1, 2, 0, CINSIDE_PARAMS_LIST} \
}

#define CINSIDE_NUM_BUILTINS(_a) \
    (sizeof(_a) / sizeof(_cinside_builtin_def))

int _cinside_eval_builtin(cinside_info *info, size_t first_token,
                          size_t last_token, size_t *num,
                          uint32_t **lval_addr);
_cinside_builtin_def *_cinside_get_builtin(size_t idx);


/* efault.c */

#define _CINSIDE_FAULT_UNKNOWN  0       /* unknown reason */
#define _CINSIDE_FAULT_VIRT     1       /* invalid virtual address */
#define _CINSIDE_FAULT_ACCESS   2       /* access permission denied */
#define _CINSIDE_FAULT_ALIGN    3       /* invalid address alignment */
#define _CINSIDE_FAULT_PHYS     4       /* invalid physical address */
#define _CINSIDE_FAULT_HW       5       /* hardware error */

#define _CINSIDE_FAULT_STRINGS \
{ \
    "address error at", "invalid virtual address", \
    "access permission denied at", "invalid address alignment at", \
    "invalid physical address", "hardware error at" \
}

extern sigjmp_buf _cinside_signal_jump;

#define _cinside_invalid_access() sigsetjmp(_cinside_signal_jump, 1)

int _cinside_setup_signals(cinside_info *info, void **old_handlers);
int _cinside_restore_signals(cinside_info *info, void *old_handlers);
int _cinside_get_fault(cinside_info *info, void **addr, int *reason);


/* expr.c */

typedef struct __cinside_expr_set
{
    uint32_t token;
    size_t expr1_first;                 /* expr1: before first/only operator */
    size_t expr1_last;
    size_t expr2_first;                 /* expr2: after first/only operator */
    size_t expr2_last;
    size_t expr3_first;                 /* expr3: after second operator */
    size_t expr3_last;
} _cinside_expr_set;

typedef int (_cinside_op_function)(cinside_info *info, _cinside_expr_set *e,
                                   size_t *num, uint32_t **lval_addr);

int _cinside_get_statement(cinside_info *info, size_t first_token,
                           size_t *eval_last, size_t *remove_last,
                           size_t *block);
int _cinside_eval_tokens(cinside_info *info, size_t first_token,
                         size_t last_token, uint32_t *result);
int _cinside_eval_expr(cinside_info *info, size_t first_token,
                       size_t last_token, size_t *num, uint32_t **lval_addr);
int _cinside_eval_vals(cinside_info *info, size_t first_token,
                       size_t last_token, size_t *num, uint32_t **lval_addr);


/* parse.c */

typedef struct _cinside_token_def
{
    char ch1, ch2, ch3;                 /* tokens up to 3 chars supported */
    uint32_t token;
    uint32_t flags;
    _cinside_op_function *eval;
} cinside_token_def;

#define CINSIDE_AFTER_VALUE     0x01    /* token must follow a value */
#define CINSIDE_ASSOC_LR        0x02    /* evaluate left-associative */
#define CINSIDE_ASSOC_RL        0x04    /* evaluate right-associative */
#define CINSIDE_COMBINED        0x08    /* a ternary operator */

int _cinside_tokenize(cinside_info *info, char *cmd);
int _cinside_dump_tokens(cinside_info *info, size_t first_token,
                         size_t last_token);
int _cinside_dump_token(cinside_info *info, uint32_t token, size_t idx);
int _cinside_get_token_def(cinside_info *info, uint32_t cur,
                           const cinside_token_def **sym);


/* operator.c */

int _cinside_eval_assign(cinside_info *info, _cinside_expr_set *e,
                         size_t *num, uint32_t **lval_addr);
int _cinside_eval_ternary(cinside_info *info, _cinside_expr_set *e,
                          size_t *num, uint32_t **lval_addr);
int _cinside_eval_logicor(cinside_info *info, _cinside_expr_set *e,
                          size_t *num, uint32_t **lval_addr);
int _cinside_eval_logicand(cinside_info *info, _cinside_expr_set *e,
                           size_t *num, uint32_t **lval_addr);
int _cinside_eval_binary(cinside_info *info, _cinside_expr_set *e,
                         size_t *num, uint32_t **lval_addr);
int _cinside_eval_unary(cinside_info *info, _cinside_expr_set *e,
                        size_t *num, uint32_t **lval_addr);


/* keyword.c */

int _cinside_get_keyword(cinside_info *info, size_t first_token,
                         size_t *body1_last, size_t *remove_last,
                         size_t *body2_last);
int _cinside_eval_keyword(cinside_info *info, size_t first_token,
                          size_t *body1_last, size_t *body2_last);


/* list.c */

int _cinside_list_init(cinside_info *info, cinside_list_segment **list);
int _cinside_list_reserve(cinside_info *info, cinside_list_segment *list,
                          size_t count, uint32_t **addr);
int _cinside_list_return(cinside_info *info, cinside_list_segment *list,
                         size_t count);
int _cinside_list_count(cinside_info *info, cinside_list_segment *list,
                        size_t *count);
int _cinside_list_push(cinside_info *info, cinside_list_segment *list,
                       uint32_t val);
int _cinside_list_pop(cinside_info *info, cinside_list_segment *list,
                      uint32_t *val);
int _cinside_list_destroy(cinside_info *info, cinside_list_segment *list);
int _cinside_list_reset(cinside_info *info, cinside_list_segment *list);


/* system.c */

int _cinside_analyze_global(cinside_info *info, cinside_variable *var);
int _cinside_caller(cinside_info *info, char *name, uint32_t argc,
                    uint32_t *argv, uint32_t *result);
void _cinside_time_diff(struct timeval *before, struct timeval *after);


/* iterators.c */

char *_cinside_files(char **path, size_t num_paths);
char *_cinside_words(char *str, char *ifs);
size_t _cinside_count(char *buf);
char *_cinside_next(char *buf);
int _cinside_last(char *buf);

#endif  /* __INTERNAL_H__ */
