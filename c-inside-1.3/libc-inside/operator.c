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

/* operator.c - evaluation of operator expressions */

#include "language.h"

int _cinside_eval_assign(cinside_info *info, _cinside_expr_set *e,
                         size_t *num, uint32_t **lval_addr)
{
    int ret;
    size_t tmp_num;
    uint32_t val, *addr;
    char *name;
    cinside_variable *var;

    IF_CINSIDE_DEBUG()
    {
        CINSIDE_DEBUG("<EXPR ==> EXPR");
        _cinside_dump_token(info, e->token, 0);
        CINSIDE_DEBUG(" EXPR>\n");
    }

    ret = _cinside_eval_expr(info, e->expr2_first, e->expr2_last, &tmp_num,
                             NULL);

    if (CINSIDE_NO_RESULT(ret))
    {
        return _cinside_error(info, CINSIDE_ERR_SYNTAX,
                              "invalid rval in assignment");
    }

    if (CINSIDE_RET_ERROR(ret))
        return ret;

    val = info->token[e->expr2_first + 1];
    var = NULL;
    if ((e->token == CINSIDE_TOKEN_EQUAL) &&
        (e->expr1_first == e->expr1_last) &&
        (info->token[e->expr1_first] == CINSIDE_TOKEN_NAME))
    {
        name = (char *)(info->token[e->expr1_first + 1]);
        ret = _cinside_get_variable(info, name, &var, 1);
        if (ret != CINSIDE_SUCCESS)
            return ret;

        addr = var->addr;
    }
    else
    {
        ret = _cinside_eval_expr(info, e->expr1_first, e->expr1_last, NULL,
                                 &addr);

        if (CINSIDE_RET_ERROR(ret))
            return ret;

        if (addr == NULL)
        {
            return _cinside_error(info, CINSIDE_ERR_SYNTAX,
                                  "invalid lval in assignment");
        }
    }

    if (e->token == CINSIDE_TOKEN_PLUSEQ)
        val = *addr + val;
    else if (e->token == CINSIDE_TOKEN_MINUSEQ)
        val = *addr - val;
    else if (e->token == CINSIDE_TOKEN_MULEQ)
        val = *addr * val;
    else if (e->token == CINSIDE_TOKEN_DIVEQ)
        val = *addr / val;
    else if (e->token == CINSIDE_TOKEN_MODEQ)
        val = *addr % val;
    else if (e->token == CINSIDE_TOKEN_ANDEQ)
        val = *addr & val;
    else if (e->token == CINSIDE_TOKEN_XOREQ)
        val = *addr ^ val;
    else if (e->token == CINSIDE_TOKEN_OREQ)
        val = *addr | val;
    else if (e->token == CINSIDE_TOKEN_SHLEQ)
        val = *addr << val;
    else if (e->token == CINSIDE_TOKEN_SHREQ)
        val = *addr >> val;
    else if (e->token != CINSIDE_TOKEN_EQUAL)
        return _cinside_error(info, CINSIDE_ERR_GENERAL, "unhandled operator");

    if ((var != NULL) && (tmp_num != 0))
    {
        var->list_items = tmp_num;
        var->addr = (uint32_t *)val;
    }
    else
    {
        *addr = val;
    }

    /* remove the operator */
    info->token[e->expr2_first - 2] = CINSIDE_TOKEN_NONE;
    info->token[e->expr2_first - 1] = 0;

    /* remove the second expression's result */
    info->token[e->expr2_first] = CINSIDE_TOKEN_NONE;
    info->token[e->expr2_first + 1] = 0;

    info->token[e->expr1_first] = CINSIDE_TOKEN_DATA;
    info->token[e->expr1_first + 1] = val;

    if (num != NULL)
        *num = tmp_num;

    CINSIDE_DEBUG("( = 0x%X)\n", val);
    return CINSIDE_SUCCESS;
}

int _cinside_eval_ternary(cinside_info *info, _cinside_expr_set *e,
                          size_t *num, uint32_t **lval_addr)
{
    int ret, val_first, val_last;
    uint32_t cond, val;
    size_t i, old_num_tokens;

    CINSIDE_DEBUG("<EXPR ==> EXPR ? EXPR : EXPR>\n");
    old_num_tokens = info->num_tokens;
    ret = _cinside_eval_expr(info, e->expr1_first, e->expr1_last, NULL, NULL);
    if (CINSIDE_NO_RESULT(ret))
    {
        return _cinside_error(info, CINSIDE_ERR_SYNTAX,
                              "invalid expression in ternary conditional");
    }

    if (CINSIDE_RET_ERROR(ret))
        return ret;

    e->expr2_first += (info->num_tokens - old_num_tokens);
    e->expr2_last += (info->num_tokens - old_num_tokens);
    e->expr3_first += (info->num_tokens - old_num_tokens);
    e->expr3_last += (info->num_tokens - old_num_tokens);
    cond = info->token[e->expr1_first + 1];
    if (cond != 0)
    {
        val_first = e->expr2_first;
        val_last = e->expr2_last;
    }
    else
    {
        val_first = e->expr3_first;
        val_last = e->expr3_last;
    }

    ret = _cinside_eval_expr(info, val_first, val_last, num, lval_addr);
    if (CINSIDE_NO_RESULT(ret))
    {
        return _cinside_error(info, CINSIDE_ERR_SYNTAX,
                              "invalid expression in ternary conditional");
    }

    if (CINSIDE_RET_ERROR(ret))
        return ret;

    val = info->token[val_first + 1];
    info->token[e->expr1_first] = CINSIDE_TOKEN_DATA;
    info->token[e->expr1_first + 1] = val;

    /* clean up tokens */
    for (i = e->expr1_first + 2; i <= e->expr3_last; i += 2)
    {
        info->token[i] = CINSIDE_TOKEN_NONE;
        info->token[i + 1] = 0;
    }

    CINSIDE_DEBUG("( = %s:0x%X)\n", (cond ? "true" : "false"),
                  info->token[val_first + 1]);

    return CINSIDE_SUCCESS;
}

int _cinside_eval_logicor(cinside_info *info, _cinside_expr_set *e,
                          size_t *num, uint32_t **lval_addr)
{
    int ret, second;
    uint32_t val;
    size_t old_num_tokens;

    CINSIDE_DEBUG("<EXPR ==> EXPR || EXPR>\n");
    old_num_tokens = info->num_tokens;
    ret = _cinside_eval_expr(info, e->expr1_first, e->expr1_last, num,
                             lval_addr);

    if (CINSIDE_NO_RESULT(ret))
    {
        return _cinside_error(info, CINSIDE_ERR_SYNTAX,
                              "invalid expression in ||");
    }

    if (CINSIDE_RET_ERROR(ret))
        return ret;

    e->expr2_first += (info->num_tokens - old_num_tokens);
    e->expr2_last += (info->num_tokens - old_num_tokens);
    second = 0;
    val = info->token[e->expr1_first + 1];
    if (val == 0)
    {
        second = 1;
        ret = _cinside_eval_expr(info, e->expr2_first, e->expr2_last, num,
                                 lval_addr);

        if (CINSIDE_NO_RESULT(ret))
        {
            return _cinside_error(info, CINSIDE_ERR_SYNTAX,
                                  "invalid expression in ||");
        }

        if (CINSIDE_RET_ERROR(ret))
            return ret;

        val = info->token[e->expr2_first + 1];
    }

    /* remove the operator */
    info->token[e->expr2_first - 2] = CINSIDE_TOKEN_NONE;
    info->token[e->expr2_first - 1] = 0;

    /* remove the second expression's result */
    info->token[e->expr2_first] = CINSIDE_TOKEN_NONE;
    info->token[e->expr2_first + 1] = 0;

    info->token[e->expr1_first] = CINSIDE_TOKEN_DATA;
    info->token[e->expr1_first + 1] = val;

    CINSIDE_DEBUG("( = %s:0x%X)\n", (second ? "second" : "first"), val);
    return CINSIDE_SUCCESS;
}

int _cinside_eval_logicand(cinside_info *info, _cinside_expr_set *e,
                           size_t *num, uint32_t **lval_addr)
{
    int ret, second;
    uint32_t val;
    size_t old_num_tokens;

    CINSIDE_DEBUG("<EXPR ==> EXPR && EXPR>\n");
    old_num_tokens = info->num_tokens;
    ret = _cinside_eval_expr(info, e->expr1_first, e->expr1_last, num,
                             lval_addr);

    if (CINSIDE_NO_RESULT(ret))
    {
        return _cinside_error(info, CINSIDE_ERR_SYNTAX,
                              "invalid expression in &&");
    }

    if (CINSIDE_RET_ERROR(ret))
        return ret;

    e->expr2_first += (info->num_tokens - old_num_tokens);
    e->expr2_last += (info->num_tokens - old_num_tokens);
    second = 0;
    val = info->token[e->expr1_first + 1];
    if (val != 0)
    {
        second = 1;
        ret = _cinside_eval_expr(info, e->expr2_first, e->expr2_last, num,
                                 lval_addr);

        if (CINSIDE_NO_RESULT(ret))
        {
            return _cinside_error(info, CINSIDE_ERR_SYNTAX,
                                  "invalid expression in &&");
        }

        if (CINSIDE_RET_ERROR(ret))
            return ret;

        val = info->token[e->expr2_first + 1];
    }

    /* remove the operator */
    info->token[e->expr2_first - 2] = CINSIDE_TOKEN_NONE;
    info->token[e->expr2_first - 1] = 0;

    /* remove the second expression's result */
    info->token[e->expr2_first] = CINSIDE_TOKEN_NONE;
    info->token[e->expr2_first + 1] = 0;

    info->token[e->expr1_first] = CINSIDE_TOKEN_DATA;
    info->token[e->expr1_first + 1] = val;

    CINSIDE_DEBUG("( = %s:0x%X)\n", (second ? "second" : "first"), val);
    return CINSIDE_SUCCESS;
}

int _cinside_eval_binary(cinside_info *info, _cinside_expr_set *e,
                         size_t *num, uint32_t **lval_addr)
{
    int ret;
    uint32_t a, b;
    size_t old_num_tokens;

    IF_CINSIDE_DEBUG()
    {
        CINSIDE_DEBUG("<EXPR ==> EXPR");
        _cinside_dump_token(info, e->token, 0);
        CINSIDE_DEBUG(" EXPR>\n");
    }

    old_num_tokens = info->num_tokens;
    ret = _cinside_eval_expr(info, e->expr1_first, e->expr1_last, num,
                             lval_addr);

    if (CINSIDE_NO_RESULT(ret))
    {
        return _cinside_error(info, CINSIDE_ERR_SYNTAX,
                              "invalid expression in binary operator");
    }

    if (CINSIDE_RET_ERROR(ret))
        return ret;

    e->expr2_first += (info->num_tokens - old_num_tokens);
    e->expr2_last += (info->num_tokens - old_num_tokens);
    ret = _cinside_eval_expr(info, e->expr2_first, e->expr2_last, num,
                             lval_addr);

    if (CINSIDE_NO_RESULT(ret))
    {
        return _cinside_error(info, CINSIDE_ERR_SYNTAX,
                              "invalid expression in binary operator");
    }

    if (CINSIDE_RET_ERROR(ret))
        return ret;

    a = info->token[e->expr1_first + 1];
    b = info->token[e->expr2_first + 1];

    /* remove the operator */
    info->token[e->expr2_first - 2] = CINSIDE_TOKEN_NONE;
    info->token[e->expr2_first - 1] = 0;

    /* remove the second expression's result */
    info->token[e->expr2_first] = CINSIDE_TOKEN_NONE;
    info->token[e->expr2_first + 1] = 0;

    if (e->token == CINSIDE_TOKEN_BITOR)
        a |= b;
    else if (e->token == CINSIDE_TOKEN_BITXOR)
        a ^= b;
    else if (e->token == CINSIDE_TOKEN_BITAND)
        a &= b;
    else if (e->token == CINSIDE_TOKEN_EQEQ)
        a = (a == b);
    else if (e->token == CINSIDE_TOKEN_NOTEQ)
        a = (a != b);
    else if (e->token == CINSIDE_TOKEN_LESS)
        a = (a < b);
    else if (e->token == CINSIDE_TOKEN_GREATER)
        a = (a > b);
    else if (e->token == CINSIDE_TOKEN_LESSEQ)
        a = (a <= b);
    else if (e->token == CINSIDE_TOKEN_GREATEREQ)
        a = (a >= b);
    else if (e->token == CINSIDE_TOKEN_SHL)
        a <<= b;
    else if (e->token == CINSIDE_TOKEN_SHR)
        a >>= b;
    else if (e->token == CINSIDE_TOKEN_ADD)
        a += b;
    else if (e->token == CINSIDE_TOKEN_SUB)
        a -= b;
    else if (e->token == CINSIDE_TOKEN_MUL)
        a *= b;
    else if (e->token == CINSIDE_TOKEN_DIV)
        a /= b;
    else if (e->token == CINSIDE_TOKEN_MOD)
        a %= b;
    else if (e->token == CINSIDE_TOKEN_COMMA)
        a = b;
    else
        return _cinside_error(info, CINSIDE_ERR_GENERAL, "unhandled operator");

    info->token[e->expr1_first] = CINSIDE_TOKEN_DATA;
    info->token[e->expr1_first + 1] = a;

    CINSIDE_DEBUG("( = 0x%X)\n", a);
    return CINSIDE_SUCCESS;
}

int _cinside_eval_unary(cinside_info *info, _cinside_expr_set *e, size_t *num,
                        uint32_t **lval_addr)
{
    int ret, val_first, val_last;
    uint32_t a;
    uint32_t *tmp_addr;

    IF_CINSIDE_DEBUG()
    {
        CINSIDE_DEBUG("<EXPR ==>");
        _cinside_dump_token(info, e->token, 0);
        CINSIDE_DEBUG(" EXPR>\n");
    }

    /* hacked comparison since size_t is unsigned */
    if ((e->expr1_first + 2) > (e->expr1_last + 2))
    {
        if (e->expr2_first > e->expr2_last)
        {
            return _cinside_error(info, CINSIDE_ERR_SYNTAX,
                                  "missing value for unary operator");
        }

        val_first = e->expr2_first;
        val_last = e->expr2_last;
    }
    else
    {
        val_first = e->expr1_first;
        val_last = e->expr1_last;
    }

    ret = _cinside_eval_expr(info, val_first, val_last, num, &tmp_addr);
    if (CINSIDE_NO_RESULT(ret))
    {
        return _cinside_error(info, CINSIDE_ERR_SYNTAX,
                              "invalid expression in unary operator");
    }

    if (CINSIDE_RET_ERROR(ret))
        return ret;

    a = info->token[val_first + 1];
    if (e->token == CINSIDE_TOKEN_PREINC)
    {
        if (tmp_addr == NULL)
        {
            return _cinside_error(info, CINSIDE_ERR_SYNTAX,
                                  "value cannot be pre-incremented");
        }

        *tmp_addr = ++a;
    }
    else if (e->token == CINSIDE_TOKEN_PREDEC)
    {
        if (tmp_addr == NULL)
        {
            return _cinside_error(info, CINSIDE_ERR_SYNTAX,
                                  "value cannot be pre-decremented");
        }

        *tmp_addr = --a;
    }
    else if (e->token == CINSIDE_TOKEN_NOT)
    {
        a = !a;
    }
    else if (e->token == CINSIDE_TOKEN_COMPL)
    {
        a = ~a;
    }
    else if (e->token == CINSIDE_TOKEN_POSITIVE)
    {
        a = +a;
    }
    else if (e->token == CINSIDE_TOKEN_NEGATIVE)
    {
        a = -a;
    }
    else if (e->token == CINSIDE_TOKEN_ADDRESS)
    {
        if (tmp_addr == NULL)
        {
            return _cinside_error(info, CINSIDE_ERR_SYNTAX,
                                  "value has no associated address");
        }

        a = (uint32_t)tmp_addr;
    }
    else if (e->token == CINSIDE_TOKEN_DEREF)
    {
        if (lval_addr != NULL)
            *lval_addr = (uint32_t *)a;

        a = *(uint32_t *)a;
    }
    else if ((e->token != CINSIDE_TOKEN_POSTINC) &&
             (e->token != CINSIDE_TOKEN_POSTDEC))
    {
        return _cinside_error(info, CINSIDE_ERR_GENERAL, "unhandled operator");
    }

    if (e->token == CINSIDE_TOKEN_POSTINC)
    {
        if (tmp_addr == NULL)
        {
            return _cinside_error(info, CINSIDE_ERR_SYNTAX,
                                  "value cannot be post-incremented");
        }

        *tmp_addr = a + 1;
    }
    else if (e->token == CINSIDE_TOKEN_POSTDEC)
    {
        if (tmp_addr == NULL)
        {
            return _cinside_error(info, CINSIDE_ERR_SYNTAX,
                                  "value cannot be post-decremented");
        }

        *tmp_addr = a - 1;
    }

    /* remove the operator */
    info->token[e->expr2_first - 2] = CINSIDE_TOKEN_NONE;
    info->token[e->expr2_first - 1] = 0;

    /* remove the second (or only) expression's result */
    info->token[e->expr2_first] = CINSIDE_TOKEN_NONE;
    info->token[e->expr2_first + 1] = 0;

    info->token[e->expr1_first] = CINSIDE_TOKEN_DATA;
    info->token[e->expr1_first + 1] = a;

    CINSIDE_DEBUG("( = 0x%X)\n", a);
    return CINSIDE_SUCCESS;
}
