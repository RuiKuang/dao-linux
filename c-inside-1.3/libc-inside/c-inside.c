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

/* c-inside.c - first level of the libc-inside implementation */

#include <stdio.h>          /* snprintf, vsnprintf */
#include <stdlib.h>         /* malloc, free */
#include <string.h>         /* memset, memcpy, strcmp, strlen, strncmp,
                                strncpy, memcmp */
#include <stdarg.h>         /* va_start, va_end */
#include <ctype.h>          /* toupper, isprint */

#include "internal.h"

struct __cinside_escape_def
{
    char mnemonic;
    char val;
} _cinside_escape[] =
{
    {'n', '\n'}, {'"', '"'}, {'\\', '\\'}, {'\'', '\''}, {'t', '\t'},
    {'r', '\r'}, {'b', '\b'}, {'a', '\a'}, {'v', '\v'}, {'?', '\?'}
};

#define CINSIDE_NUM_ESCAPE \
    (sizeof(_cinside_escape) / sizeof(struct __cinside_escape_def))

static const char *_cinside_fault_str[] = _CINSIDE_FAULT_STRINGS;

static int _cinside_destroy(cinside_info *info, int ret);
static int _cinside_check(cinside_info *info);

/* helper macro for cinside_init(): store err msg, free stuff, return error */
#define _cinside_init_error(_i, _r, _s) \
    _cinside_destroy(_i, _cinside_error(_i, _r, _s))

int cinside_init(cinside_info **info_ptr, cinside_variable *preload_vars,
                 cinside_function *preload_functions, size_t max_vars,
                 size_t max_functions)
{
    int ret;
    cinside_info *info;

    info = NULL;

    /*
     * All we can really do here is return the value, but use the regular error
     * path in case we ever want to do anything via globals in the future.
     */
    if (info_ptr == NULL)
    {
        return _cinside_init_error(info, CINSIDE_ERR_GENERAL,
                                   "invalid parameter to cinside_init()");
    }

    if ((info = malloc(sizeof(*info))) == NULL)
        return _cinside_init_error(info, CINSIDE_ERR_RESOURCES, NULL);

    *info_ptr = info;

    /*
     * First initialize things for error output & regular output, so init
     * errors can be stored for CINSIDE_ID_ERROR (nothing will be displayed
     * yet, since CINSIDE_ID_ERROR_FUNC/CINSIDE_ID_OUTPUT_FUNC won't be set
     * until after initialization)
     */
    memset(info, 0, sizeof(*info));
    info->last_error_size = CINSIDE_DEFAULT_MSG_SIZE;

    /* freed in _cinside_error() or _cinside_destroy() */
    if ((info->last_error = malloc(info->last_error_size)) == NULL)
        return _cinside_init_error(info, CINSIDE_ERR_RESOURCES, NULL);

    memset(info->last_error, 0, info->last_error_size);
    info->output_scratch_size = CINSIDE_DEFAULT_MSG_SIZE;

    /* freed in _cinside_output() or _cinside_destroy() */
    if ((info->output_scratch = malloc(info->output_scratch_size)) == NULL)
        return _cinside_init_error(info, CINSIDE_ERR_RESOURCES, NULL);

    memset(info->output_scratch, 0, info->output_scratch_size);

    /*
     * On some systems, function pointers differ in size from other pointers.
     * Those systems are currently not supported, but may be in future
     * versions.
     */
    if (sizeof(cinside_fp) != sizeof(void *))
    {
        return _cinside_init_error(info, CINSIDE_ERR_CANNOT,
                                   "function pointer size mismatch");
    }

    /* currently, everything must be 32-bit (may change in future versions) */
    if (sizeof(void *) != sizeof(uint32_t))
    {
        return _cinside_init_error(info, CINSIDE_ERR_CANNOT,
                                   "pointers must be 32-bit");
    }

    if (max_vars == 0)
        max_vars = CINSIDE_MAX_VARS;

    info->max_vars = max_vars;

    /* freed in _cinside_destroy() */
    if ((info->vars = malloc(max_vars * sizeof(*(info->vars)))) == NULL)
        return _cinside_init_error(info, CINSIDE_ERR_RESOURCES, NULL);

    memset(info->vars, 0, max_vars * sizeof(*(info->vars)));
    if (preload_vars != NULL)
    {
        /* variables: NULL address ok, NULL name not ok (end of list) */
        while (preload_vars[info->num_vars].name != NULL)
        {
            if (info->num_vars == info->max_vars)
            {
                return _cinside_init_error(info, CINSIDE_ERR_FULL,
                                           "too many preload variables");
            }

            memcpy(&(info->vars[info->num_vars]),
                   &(preload_vars[info->num_vars]),
                   sizeof(cinside_variable));

            info->num_vars++;
        }
    }

    if (max_functions == 0)
        max_functions = CINSIDE_MAX_FUNCTIONS;

    info->max_functions = max_functions;

    /* freed in _cinside_destroy() */
    info->functions = malloc(max_functions * sizeof(*(info->functions)));
    if (info->functions == NULL)
        return _cinside_init_error(info, CINSIDE_ERR_RESOURCES, NULL);

    memset(info->functions, 0, max_functions * sizeof(*(info->functions)));
    if (preload_functions != NULL)
    {
        /* functions: NULL name or addr not ok (end of list if either) */
        while ((preload_functions[info->num_functions].name != NULL) &&
               (preload_functions[info->num_functions].addr != NULL))
        {
            if (info->num_functions == info->max_functions)
            {
                return _cinside_init_error(info, CINSIDE_ERR_FULL,
                                           "too many preload functions");
            }

            memcpy(&(info->functions[info->num_functions]),
                   &(preload_functions[info->num_functions]),
                   sizeof(cinside_function));

            info->num_functions++;
        }
    }

    ret = _cinside_alloc_tokens(info, &(info->token), CINSIDE_MAX_TOKENS);
    if (ret != CINSIDE_SUCCESS)
        return _cinside_destroy(info, ret); /* already called _cinside_error */

    info->max_tokens = CINSIDE_MAX_TOKENS;

    if ((ret = _cinside_list_init(info, &(info->lists))) != CINSIDE_SUCCESS)
        return _cinside_destroy(info, ret); /* already called _cinside_error */

    ret = _cinside_list_init(info, &(info->vals_stack));
    if (ret != CINSIDE_SUCCESS)
        return _cinside_destroy(info, ret); /* already called _cinside_error */

    ret = _cinside_list_init(info, &(info->sep_stack));
    if (ret != CINSIDE_SUCCESS)
        return _cinside_destroy(info, ret); /* already called _cinside_error */

    ret = _cinside_list_init(info, &(info->match_stack));
    if (ret != CINSIDE_SUCCESS)
        return _cinside_destroy(info, ret); /* already called _cinside_error */

    if ((ret = _cinside_lkup_init(info)) != CINSIDE_SUCCESS)
        return _cinside_destroy(info, ret); /* already called _cinside_error */

    return CINSIDE_SUCCESS;
}

int cinside_destroy(cinside_info *info)
{
    /*
     * This check can only be performed in the user-callable cinside_destroy()
     * (after initialization is complete).
     */
    if (!_cinside_check(info))
        return CINSIDE_PARAM_ERROR();

    /*
     * The internal _cinside_destroy() is needed, with no check, to handle
     * initialization errors.
     */
    return _cinside_destroy(info, CINSIDE_SUCCESS);
}

int cinside_eval(cinside_info *info, char *code_buf, uint32_t *result)
{
    int ret, fault_reason;
    void *old_handlers, *fault_addr;

    /* result is allowed to be NULL (caller may have no need for it) */
    if (!_cinside_check(info) || (code_buf == NULL))
        return CINSIDE_PARAM_ERROR();

    ret = _cinside_tokenize(info, code_buf);
    if (ret != CINSIDE_SUCCESS)     /* allow _NOP, _PARTIAL to be returned */
    {
        if (ret == CINSIDE_PARTIAL)
        {
            info->flags |= CINSIDE_FLAG_PARTIAL;
            if (info->flags & CINSIDE_FLAG_INPUT_DONE)
            {
                return _cinside_error(info, CINSIDE_ERR_SYNTAX,
                                      "incomplete comment");
            }
        }
        else
        {
            info->flags &= ~(CINSIDE_FLAG_PARTIAL | CINSIDE_FLAG_COMMENT);
        }

        return ret;
    }

    /* prepare to trap SIGSEGV and SIGBUS during entire evaluation */
    ret = _cinside_setup_signals(info, &old_handlers);
    if (ret != CINSIDE_SUCCESS)
        return ret;

    /* "placeholder" to jump back to if signal is encountered */
    if (_cinside_invalid_access())
    {
        _cinside_restore_signals(info, old_handlers);
        _cinside_get_fault(info, &fault_addr, &fault_reason);
        return _cinside_error(info, CINSIDE_ERR_CANNOT, "%s 0x%08X",
                              _cinside_fault_str[fault_reason], fault_addr);
    }

    ret = _cinside_eval_tokens(info, 0, info->num_tokens - 2, result);

    /* restore to original caller's behavior */
    _cinside_restore_signals(info, old_handlers);

    if (ret == CINSIDE_PARTIAL)
    {
        info->flags |= CINSIDE_FLAG_PARTIAL;
        if (info->flags & CINSIDE_FLAG_INPUT_DONE)
        {
            return _cinside_error(info, CINSIDE_ERR_SYNTAX,
                                  "incomplete statement");
        }
    }
    else
    {
        info->flags &= ~(CINSIDE_FLAG_PARTIAL | CINSIDE_FLAG_COMMENT);
        if (ret == CINSIDE_BREAK)
        {
            return _cinside_error(info, CINSIDE_ERR_SYNTAX,
                                  "unexpected \"break\"");
        }
        else if (ret == CINSIDE_CONTINUE)
        {
            return _cinside_error(info, CINSIDE_ERR_SYNTAX,
                                  "unexpected \"continue\"");
        }
    }

    return ret;
}

int cinside_get(cinside_info *info, size_t id, uint32_t *value)
{
    int bit;

    if (!_cinside_check(info) || (id > CINSIDE_MAX_ID) || (value == NULL))
        return CINSIDE_PARAM_ERROR();

    bit = 0;
    switch (id)
    {
        case CINSIDE_ID_VERSION:
            *value = CINSIDE_VERSION;
            break;
        case CINSIDE_ID_ERROR:
            *value = (uint32_t)(info->last_error);
            break;
        case CINSIDE_ID_OUTPUT_FUNC:
            *value = (uint32_t)(info->output_function);
            break;
        case CINSIDE_ID_ERROR_FUNC:
            *value = (uint32_t)(info->error_function);
            break;
        case CINSIDE_ID_INPUT_DONE:
            *value = info->flags & CINSIDE_FLAG_INPUT_DONE;
            bit = 1;
            break;
        case CINSIDE_ID_ADD_SEMI:
            *value = info->flags & CINSIDE_FLAG_ADD_SEMI;
            bit = 1;
            break;
        case CINSIDE_ID_GETDATA_FUNC:
            *value = (uint32_t)(info->get_data_function);
            break;
        case CINSIDE_ID_PUTDATA_FUNC:
            *value = (uint32_t)(info->put_data_function);
            break;
        case CINSIDE_ID_SETBP_FUNC:
            *value = (uint32_t)(info->set_bp_function);
            break;
        case CINSIDE_ID_DISASM_FUNC:
            *value = (uint32_t)(info->disasm_function);
            break;
        case CINSIDE_ID_ENABLE_CTRLR:
            *value = info->flags & CINSIDE_FLAG_EN_CTRLR;
    }

    if ((bit == 1) && (*value > 1))
    {
        while (*value > 1)
            *value >>= 1;
    }

    return CINSIDE_SUCCESS;
}

int cinside_set(cinside_info *info, size_t id, uint32_t value)
{
    if (!_cinside_check(info) || (id > CINSIDE_MAX_ID))
        return CINSIDE_PARAM_ERROR();

    switch (id)
    {
        case CINSIDE_ID_OUTPUT_FUNC:
            info->output_function = (cinside_output_function)value;
            break;
        case CINSIDE_ID_ERROR_FUNC:
            info->error_function = (cinside_output_function)value;
            break;
        case CINSIDE_ID_INPUT_DONE:
            if (info->flags & CINSIDE_FLAG_INPUT_DONE)
            {
                return _cinside_error(info, CINSIDE_ERR_CANNOT,
                                      "end-of-input already set");
            }

            if (value == 1)
            {
                info->flags |= CINSIDE_FLAG_INPUT_DONE;
            }
            else if (value != 0)
            {
                return _cinside_error(info, CINSIDE_ERR_PARAMETER,
                                      "invalid value %d for input_done",
                                      value);
            }

            break;
        case CINSIDE_ID_ADD_SEMI:
            if (value == 0)
            {
                info->flags &= ~CINSIDE_FLAG_ADD_SEMI;
            }
            else if (value == 1)
            {
                info->flags |= CINSIDE_FLAG_ADD_SEMI;
            }
            else
            {
                return _cinside_error(info, CINSIDE_ERR_PARAMETER,
                                      "invalid value %d for add_semi",
                                      value);
            }

            break;
        case CINSIDE_ID_GETDATA_FUNC:
            info->get_data_function = (cinside_xfer_function)value;
            break;
        case CINSIDE_ID_PUTDATA_FUNC:
            info->put_data_function = (cinside_xfer_function)value;
            break;
        case CINSIDE_ID_SETBP_FUNC:
            info->set_bp_function = (cinside_setbp_function)value;
            break;
        case CINSIDE_ID_DISASM_FUNC:
            info->disasm_function = (cinside_disasm_function)value;
            break;
        case CINSIDE_ID_ENABLE_CTRLR:
            if (value == 0)
            {
                info->flags &= ~CINSIDE_FLAG_EN_CTRLR;
            }
            else if (value == 1)
            {
                info->flags |= CINSIDE_FLAG_EN_CTRLR;
            }
            else
            {
                return _cinside_error(info, CINSIDE_ERR_PARAMETER,
                                      "invalid value %d for enable_ctrlr",
                                      value);
            }

            break;
        default:
            return _cinside_error(info, CINSIDE_ERR_CANNOT,
                                  "value with id %u is read-only", id);
    }

    return CINSIDE_SUCCESS;
}

int _cinside_alloc_tokens(cinside_info *info, uint32_t **token,
                          size_t max_tokens)
{
    uint32_t *buf;

    /*
     * Freed in _cinside_parenthesize(), _cinside_tokenize(), or
     * _cinside_destroy()
     */
    if ((buf = malloc(max_tokens * sizeof(uint32_t))) == NULL)
        return _cinside_error(info, CINSIDE_ERR_RESOURCES, NULL);

    memset(buf, 0, max_tokens * sizeof(uint32_t));
    *token = buf;
    return CINSIDE_SUCCESS;
}

static int _cinside_destroy(cinside_info *info, int ret)
{
    void **this_buf, **next_buf;

    if (info == NULL)
        return CINSIDE_ERR_GENERAL;

    if (info->lkup_handle != NULL)
        _cinside_lkup_destroy(info);

    this_buf = info->strings;
    while (this_buf != NULL)
    {
        next_buf = (void **)*this_buf;
        free(this_buf);
        this_buf = next_buf;
    }

    if (info->match_stack != NULL)
        _cinside_list_destroy(info, info->match_stack);

    if (info->sep_stack != NULL)
        _cinside_list_destroy(info, info->sep_stack);

    if (info->vals_stack != NULL)
        _cinside_list_destroy(info, info->vals_stack);

    if (info->lists != NULL)
        _cinside_list_destroy(info, info->lists);

    if (info->token != NULL)
        free(info->token);

    if (info->functions != NULL)
        free(info->functions);

    if (info->vars != NULL)
        free(info->vars);

    if (info->output_scratch != NULL)
        free(info->output_scratch);

    if (info->last_error != NULL)
        free(info->last_error);

    free(info);
    return ret;
}

/* NOTE: this function returns a "boolean" value */
static int _cinside_check(cinside_info *info)
{
    /* detailed sanity check to make sure caller passed a valid info struct */
    if ((info == NULL) || (info->vars == NULL) || (info->functions == NULL) ||
        (info->token == NULL) || (info->output_scratch == NULL) ||
        (info->last_error == NULL) || (info->lists == NULL) ||
        (info->vals_stack == NULL) || (info->sep_stack == NULL) ||
        (info->match_stack == NULL) || (info->last_error_size == 0) ||
        (info->output_scratch_size == 0) || (info->max_vars == 0) ||
        (info->max_functions == 0) || (info->max_tokens == 0) ||
        (info->num_vars > info->max_vars) ||
        (info->num_functions > info->max_functions) ||
        (info->num_tokens > info->max_tokens))
    {
        return 0;
    }

    return 1;
}

int _cinside_get_variable(cinside_info *info, char *str, cinside_variable **v,
                          int create)
{
    int ret;
    size_t i;
    cinside_variable *var;
    _cinside_string_hdr *name;

    /* first, check already known variables (locals and globals) */
    for (i = 0; i < info->num_vars; i++)
    {
        if (strcmp(str, info->vars[i].name) == 0)
        {
            if (v != NULL)              /* may only be checking if it exists */
                *v = &(info->vars[i]);

            return CINSIDE_SUCCESS;
        }
    }

    if (info->num_vars == info->max_vars)
    {
        return _cinside_error(info, CINSIDE_ERR_FULL,
                              "maximum number of variables reached");
    }

    var = &(info->vars[info->num_vars]);
    memset(var, 0, sizeof(*var));

    /* next, check globals via the namespace functionality */
    ret = _cinside_lkup_variable(info, str, &(var->addr));
    if ((ret != CINSIDE_SUCCESS) && !create)
    {
        /* give a hint to the user if the entire command was "help" */
        if ((strcmp(str, "help") == 0) && (info->num_tokens == 4))
            _cinside_error(info, ret, "'%s' not defined (try '$help')", str);
        else
            _cinside_error(info, ret, "'%s' not defined", str);

        return ret;
    }

    /*
     * Add a new variable.  If the caller wants to force creation of a new
     * variable, then it will be a local, regardless of the result of the
     * lookup (this allows for use of locals that override existing globals,
     * but only when they are evaluated directly by c-inside).  Otherwise, it
     * will be a global, "cached" so to speak (only its address, which can
     * never change anyway).
     */

    /* make and store its copy of the name */
    ret = _cinside_string(info, str, strlen(str), 0, &name);
    if (ret != CINSIDE_SUCCESS)
        return ret;

    var->name = name->str;
    *v = var;
    info->num_vars++;
    if (create)                     /* new variable is a local */
        var->addr = &(var->local_value);

    return CINSIDE_SUCCESS;
}

int _cinside_get_function(cinside_info *info, char *str, cinside_function **f)
{
    int i, ret;
    cinside_fp addr;
    cinside_function *function;
    _cinside_string_hdr *name;

    /* first, check already known functions */
    for (i = 0; i < info->num_functions; i++)
    {
        if (strcmp(str, info->functions[i].name) == 0)
        {
            if (f != NULL)
                *f = &(info->functions[i]);

            return CINSIDE_SUCCESS;
        }
    }

    if (info->num_functions == info->max_functions)
    {
        return _cinside_error(info, CINSIDE_ERR_FULL,
                              "maximum number of functions reached");
    }

    /* next, check via the namespace functionality */
    function = &(info->functions[info->num_functions]);
    if ((ret = _cinside_lkup_function(info, str, &addr)) != CINSIDE_SUCCESS)
        return ret;

    /* make and store its copy of the name */
    ret = _cinside_string(info, str, strlen(str), 0, &name);
    if (ret == CINSIDE_SUCCESS)
    {
        function->name = name->str;
        *f = function;
        info->num_functions++;
        function->addr = addr;  /* separate assignment to avoid gcc warning */
    }

    return ret;
}

int _cinside_unescape_char(cinside_info *info, char *seq, size_t len,
                           char *val)
{
    int invalid;
    char c, c2, c3, buf[4];
    size_t i;

    buf[0] = seq[1];
    buf[1] = seq[2];
    buf[2] = seq[3];
    buf[len - 1] = '\0';

    invalid = 0;
    c = seq[1];
    if ((len >= 2) && (len <= 4) && (c >= '0') && (c <= '7'))
    {
        c -= '0';
        c2 = seq[2] - '0';
        c3 = seq[3] - '0';
        if (len > 2)
            c = (c << 3) + c2;

        if (len == 4)
            c = (c << 3) + c3;

        if (((len > 2) && ((unsigned char)c2 > 7)) ||
            ((len == 4) && ((unsigned char)c3 > 7)))
        {
            invalid = 1;
        }
    }
    else if (((len == 3) || (len == 4)) && (c == 'x'))
    {
        if ((seq[2] >= '0') && (seq[2] <= '9'))
            c = seq[2] - '0';
        else
            c = toupper(seq[2]) - ('A' - 10);

        if ((seq[3] >= '0') && (seq[3] <= '9'))
            c2 = seq[3] - '0';
        else
            c2 = toupper(seq[3]) - ('A' - 10);

        if (((unsigned char)c > 0xF) ||
            ((len == 4) && ((unsigned char)c2 > 0xF)))
        {
            invalid = 1;
        }

        if (len == 4)
            c = (c << 4) + c2;
    }
    else if (len == 2)
    {
        /*
         * If \{char} is not found, it simply becomes {char}.  Add a warning
         * here, if/when warnings are implemented.
         */
        for (i = 0; i < CINSIDE_NUM_ESCAPE; i++)
        {
            if (c == _cinside_escape[i].mnemonic)
            {
                c = _cinside_escape[i].val;
                break;
            }
        }
    }
    else
    {
        invalid = 1;
    }

    if (invalid)
    {
        return _cinside_error(info, CINSIDE_ERR_SYNTAX,
                              "invalid escape character sequence '\\%s'", buf);
    }

    *val = c;
    return CINSIDE_SUCCESS;
}

int _cinside_string(cinside_info *info, char *str, size_t len,
                    unsigned int flags, _cinside_string_hdr **new_str)
{
    int ret;
    _cinside_string_hdr *this_hdr, *cur_hdr, *next_hdr;
    size_t i, bytes, seq_len;
    char c;

    bytes = ((sizeof(*this_hdr) + len + 1) + 3) & ~3;

    /* freed in _cinside_builtin_clear() or _cinside_destroy() */
    if ((this_hdr = malloc(bytes)) == NULL)
        return _cinside_error(info, CINSIDE_ERR_RESOURCES, NULL);

    memset(this_hdr, 0, bytes);
    this_hdr->flags = flags;
    this_hdr->str = (char *)(this_hdr + 1);
    for (i = 0; i < len; i++)
    {
        c = str[i];
        if ((c == '\\') && !(flags & CINSIDE_STRING_NOESC))
        {
            if (!(flags & CINSIDE_STRING_LITERAL))
            {
                free(this_hdr);
                return _cinside_error(info, CINSIDE_ERR_SYNTAX,
                                      "invalid backslash in '%s'", str);
            }

            if (i == (len - 1))
            {
                free(this_hdr);
                return _cinside_error(info, CINSIDE_ERR_SYNTAX,
                                      "trailing backslash in string");
            }

            seq_len = 2;
            if (str[i + 1] == 'x')
            {
                c = toupper(str[i + 2]);
                if (((c >= '0') && (c <= '9')) || ((c >= 'A') && (c <= 'F')))
                {
                    seq_len++;
                    c = toupper(str[i + 3]);
                    if (((c >= '0') && (c <= '9')) ||
                        ((c >= 'A') && (c <= 'F')))
                    {
                        seq_len++;
                    }
                }
            }
            else if ((str[i + 1] >= '0') && (str[i + 1] <= '9'))
            {
                c = str[i + 2];
                if ((c >= '0') && (c <= '9'))
                {
                    seq_len++;
                    c = str[i + 3];
                    if ((c >= '0') && (c <= '9'))
                        seq_len++;
                }
            }

            ret = _cinside_unescape_char(info, &(str[i]), seq_len, &c);
            if (ret != CINSIDE_SUCCESS)
                return ret;

            i += (seq_len - 1);
        }

        this_hdr->str[this_hdr->len++] = c;
    }

    this_hdr->str[this_hdr->len] = '\0';
    *new_str = this_hdr;

    next_hdr = info->strings;
    if (next_hdr == NULL)
    {
        info->strings = this_hdr;
        return CINSIDE_SUCCESS;
    }

    do
    {
        cur_hdr = next_hdr;
        next_hdr = cur_hdr->next;
        if ((cur_hdr->len == this_hdr->len) &&
            !(cur_hdr->flags & CINSIDE_STRING_LITERAL) &&
            !(this_hdr->flags & CINSIDE_STRING_LITERAL) &&
            (memcmp(cur_hdr->str, this_hdr->str, this_hdr->len) == 0))
        {
            free(this_hdr);
            *new_str = cur_hdr;
            return CINSIDE_SUCCESS;
        }
    } while (next_hdr != NULL);

    cur_hdr->next = this_hdr;
    return CINSIDE_SUCCESS;
}

int _cinside_copy_printable(cinside_info *info, _cinside_string_hdr *src,
                            char *dest, size_t max_len)
{
    size_t i, in_idx, out_idx;
    char c;

    out_idx = 0;
    for (in_idx = 0; in_idx < src->len; in_idx++)
    {
        c = src->str[in_idx];
        if ((out_idx + 4) == max_len)
        {
            return _cinside_error(info, CINSIDE_ERR_GENERAL,
                                  "printable string overflow\n");
        }

        if (isprint(c))
        {
            dest[out_idx++] = c;
            continue;
        }

        dest[out_idx++] = '\\';
        for (i = 0; i < CINSIDE_NUM_ESCAPE; i++)
        {
            if (c == _cinside_escape[i].val)
            {
                dest[out_idx++] = _cinside_escape[i].mnemonic;
                break;
            }
        }

        if (i < CINSIDE_NUM_ESCAPE)
            continue;

        snprintf(&(dest[out_idx]), 4, "%03o", c);
        out_idx += 3;
    }

    dest[out_idx] = '\0';
    return CINSIDE_SUCCESS;
}

int _cinside_error(cinside_info *info, int ret, char *fmt, ...)
{
    size_t bytes;
    va_list arg;
    char *final_str;

    /* we may still be initializing, make sure the essentials are present */
    if ((info == NULL) || (info->last_error == NULL) ||
        (info->last_error_size == 0))
    {
        return ret;
    }

    final_str = fmt;
    if (final_str == NULL)
    {
        /* NULL means select the default message for the error */
        if (ret == CINSIDE_ERR_PARAMETER)
            final_str = "invalid parameter(s)";
        else if (ret == CINSIDE_ERR_GENERAL)
            final_str = "low-level error";
        else if (ret == CINSIDE_ERR_SYNTAX)
            final_str = "syntax error";
        else if (ret == CINSIDE_ERR_RESOURCES)
            final_str = "insufficient memory";
        else if (ret == CINSIDE_ERR_NOT_FOUND)
            final_str = "not found";
        else if (ret == CINSIDE_ERR_FULL)
            final_str = "maximum count reached";
        else if (ret == CINSIDE_ERR_CANNOT)
            final_str = "operation not permitted";
        else
            final_str = "unknown error";

        snprintf(info->last_error, info->last_error_size, final_str);
    }
    else
    {
        va_start(arg, fmt);
        bytes = vsnprintf(info->last_error, info->last_error_size, fmt, arg);
        va_end(arg);
        if (bytes >= info->last_error_size)
        {
            free(info->last_error);

            /* freed in _cinside_error() or _cinside_destroy() */
            if ((info->last_error = malloc(bytes + 1)) == NULL)
                return ret;

            info->last_error_size = (bytes + 1);
            va_start(arg, fmt);
            vsnprintf(info->last_error, info->last_error_size, fmt, arg);
            va_end(arg);
        }
    }

    if (info->error_function != NULL)
        (info->error_function)(info->last_error);

    return ret;
}

int _cinside_output(cinside_info *info, char *fmt, ...)
{
    size_t bytes;
    va_list arg;

    va_start(arg, fmt);
    bytes = vsnprintf(info->output_scratch, info->output_scratch_size, fmt,
                      arg);

    va_end(arg);
    if (bytes >= info->output_scratch_size)
    {
        free(info->output_scratch);

        /* freed in _cinside_output() or _cinside_destroy() */
        if ((info->output_scratch = malloc(bytes + 1)) == NULL)
            return _cinside_error(info, CINSIDE_ERR_RESOURCES, NULL);

        info->output_scratch_size = (bytes + 1);
        va_start(arg, fmt);
        vsnprintf(info->output_scratch, info->output_scratch_size, fmt, arg);
        va_end(arg);
    }

    if (info->output_function != NULL)
        (info->output_function)(info->output_scratch);

    return CINSIDE_SUCCESS;
}
