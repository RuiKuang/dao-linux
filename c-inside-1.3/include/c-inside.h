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

/* c-inside.h - declarations for users of the libc-inside library */

#ifndef __C_INSIDE_H__
#define __C_INSIDE_H__

#include "c-inside-sys.h"       /* needed only for data types here */

#define CINSIDE_VERSION     0x00010003  /* hi = major, lo = minor (== v1.3) */

#define CINSIDE_MAX_VARS        1024    /* default maximum */
#define CINSIDE_MAX_FUNCTIONS   4096    /* default maximum */

/* non-error return values */
#define CINSIDE_SUCCESS         0       /* eval successful, has result */
#define CINSIDE_SUCCESS_EXIT    1       /* eval successful, want to exit */
#define CINSIDE_NOP             2       /* eval successful, has no result */
#define CINSIDE_PARTIAL         100     /* partial statement */
#define CINSIDE_SUCCESS_CONT    101     /* continue with main application */

/* error return values */
#define CINSIDE_ERR_PARAMETER   3       /* invalid parameter to cinside_... */
#define CINSIDE_ERR_GENERAL     4       /* unclassifiable (usually a bug) */
#define CINSIDE_ERR_SYNTAX      5       /* syntax error */
#define CINSIDE_ERR_RESOURCES   6       /* insufficient memory/etc. */
#define CINSIDE_ERR_NOT_FOUND   7       /* item not found */
#define CINSIDE_ERR_FULL        8       /* variable or list storage full */
#define CINSIDE_ERR_CANNOT      9       /* operation not permitted */

/* convenience macro to check for unsuccessful non-exit return values */
#define CINSIDE_RET_ERROR(_r) \
    ((_r != CINSIDE_SUCCESS) && (_r != CINSIDE_NOP) && \
     (_r != CINSIDE_PARTIAL) && (_r != CINSIDE_SUCCESS_CONT))

/* convenience macro to check for successful no-result return values */
#define CINSIDE_NO_RESULT(_r) \
    ((_r == CINSIDE_SUCCESS_EXIT) || (_r == CINSIDE_NOP) || \
     (_r == CINSIDE_BREAK) || (_r == CINSIDE_CONTINUE) || \
     (_r == CINSIDE_SUCCESS_CONT))

#define CINSIDE_ID_VERSION      0       /* libc-inside ver. (uint32_t, ro) */
#define CINSIDE_ID_ERROR        1       /* last error message (char *, ro) */
#define CINSIDE_ID_OUTPUT_FUNC  2       /* output function (func ptr, rw) */
#define CINSIDE_ID_ERROR_FUNC   3       /* error function (func ptr, rw) */
#define CINSIDE_ID_INPUT_DONE   4       /* end-of-input */
#define CINSIDE_ID_ADD_SEMI     5       /* automatically add ; in _eval() */
#define CINSIDE_ID_GETDATA_FUNC 6       /* get-data function (fptr, rw) */
#define CINSIDE_ID_PUTDATA_FUNC 7       /* put-data function (fptr, rw) */
#define CINSIDE_ID_SETBP_FUNC   8       /* set breakpoint (func ptr, rw) */
#define CINSIDE_ID_DISASM_FUNC  9       /* disassemble (func ptr, rw) */
#define CINSIDE_ID_ENABLE_CTRLR 10      /* enable controller mode ("go" cmd) */
#define CINSIDE_MAX_ID          10      /* maximum CINSIDE_ID_* value */

typedef uint32_t (*cinside_fp)(void);
typedef int (*cinside_output_function)(char *str);
typedef size_t (*cinside_xfer_function)(uint8_t *local_addr,
                                        uint32_t remote_addr, size_t n);
typedef int (*cinside_setbp_function)(uint32_t addr, char *expr);
typedef int (*cinside_disasm_function)(uint32_t addr, uint32_t lines);

typedef struct _cinside_variable
{
    char *name;
    uint32_t *addr;                     /* = &local_value if not a global */
    uint32_t local_value;               /* only applies if not a global */
    size_t list_items;                  /* nonzero if a list */
} cinside_variable;

typedef struct _cinside_function
{
    char *name;
    cinside_fp addr;
} cinside_function;

/*
 * This structure is followed immediately by up to (max_items) values.  If
 * _cinside_list_reserve() is called with a count larger than the number of
 * free items in the current segment, the current segment will be truncated
 * (max_items = num_items) and a new segment will be allocated to hold at least
 * (count) items.  The allocated area from malloc() will still have space for
 * max_items.
 */
typedef struct _cinside_list_segment
{
    struct _cinside_list_segment *next;
    struct _cinside_list_segment *prev;
    struct _cinside_list_segment *cur;  /* most recently added segment */
    size_t max_items;
    size_t num_items;                   /* values follow */
} cinside_list_segment;

typedef struct _cinside_info
{
    char *last_error;
    char *output_scratch;
    cinside_variable *vars;
    cinside_function *functions;
    uint32_t *token;
    cinside_list_segment *lists;
    cinside_list_segment *vals_stack;
    cinside_list_segment *sep_stack;    /* used in parenthesizing RL-assoc */
    cinside_list_segment *match_stack;  /* used in parsing, match (){}[]?: */
    void *strings;                      /* _cinside_string_hdr (internal.h) */
    void *lkup_handle;
    cinside_output_function error_function;
    cinside_output_function output_function;
    cinside_xfer_function get_data_function;
    cinside_xfer_function put_data_function;
    cinside_setbp_function set_bp_function;
    cinside_disasm_function disasm_function;
    uint8_t *dump_addr;
    uint8_t *disasm_addr;
    size_t last_error_size;
    size_t output_scratch_size;
    size_t max_vars;
    size_t num_vars;
    size_t max_functions;
    size_t num_functions;
    size_t max_tokens;
    size_t num_tokens;
    uint32_t dump_len;
    uint32_t dump_size;
    uint32_t mod_size;
    uint32_t disasm_lines;
    int last_errno;
    unsigned int flags;                 /* CINSIDE_FLAG_* */
} cinside_info;

int cinside_init(cinside_info **info, cinside_variable *preload_vars,
                 cinside_function *preload_functions, size_t max_vars,
                 size_t max_functions);
int cinside_destroy(cinside_info *info);
int cinside_eval(cinside_info *info, char *code_buf, uint32_t *result);
int cinside_get(cinside_info *info, size_t id, uint32_t *value);
int cinside_set(cinside_info *info, size_t id, uint32_t value);
int cinside_go(cinside_variable *preload_vars,
               cinside_function *preload_functions, size_t max_vars,
               size_t max_functions);
int cinside_loop(cinside_info *info, char *prompt);

#define cinside_simple() cinside_go(NULL, NULL, 0, 0)

#endif  /* __C_INSIDE_H__ */
