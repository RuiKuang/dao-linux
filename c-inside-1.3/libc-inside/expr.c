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

/* expr.c - expression evaluation functions (see also operator.c) */

#include <stdlib.h>         /* malloc, free */
#include <string.h>         /* memset, memcpy, strcmp */

#include "language.h"

static int _cinside_eval_op_lr(cinside_info *info, size_t first_token,
                               size_t last_token, size_t *num,
                               uint32_t **lval_addr,
                               const cinside_token_def *sym);
static int _cinside_eval_op_rl(cinside_info *info, size_t first_token,
                               size_t last_token, size_t *num,
                               uint32_t **lval_addr,
                               const cinside_token_def *sym);
static int _cinside_parenthesize(cinside_info *info, size_t start,
                                 size_t stop);
static int _cinside_eval_base_expr(cinside_info *info, size_t first_token,
                                   size_t last_token, size_t *num,
                                   uint32_t **lval_addr);
static int _cinside_eval_int(cinside_info *info, size_t first_token,
                             size_t last_token, size_t *num,
                             uint32_t **lval_addr);
static int _cinside_eval_string(cinside_info *info, size_t first_token,
                                size_t last_token, size_t *num,
                                uint32_t **lval_addr);
static int _cinside_eval_name(cinside_info *info, size_t first_token,
                              size_t last_token, size_t *num,
                              uint32_t **lval_addr);
static int _cinside_eval_list(cinside_info *info, size_t first_token,
                              size_t last_token, size_t *num,
                              uint32_t **lval_addr);
static int _cinside_eval_paren(cinside_info *info, size_t first_token,
                               size_t last_token, size_t *num,
                               uint32_t **lval_addr);
static int _cinside_eval_call(cinside_info *info, size_t first_token,
                              size_t last_token, size_t *num,
                              uint32_t **lval_addr);
static int _cinside_eval_array(cinside_info *info, size_t first_token,
                               size_t last_token, size_t *num,
                               uint32_t **lval_addr);

int _cinside_eval_tokens(cinside_info *info, size_t first_token,
                         size_t last_token, uint32_t *result)
{
    int ret, had_expr;
    size_t i, eval_last, block, remove_last, old_num_tokens, body1_last;
    size_t body2_last;

    eval_last = 0;
    remove_last = 0;
    block = 0;
    had_expr = 0;
    while (first_token <= last_token)
    {
        if (info->num_tokens == 0)      /* end of loop can result in this */
            break;

        old_num_tokens = info->num_tokens;
        ret = _cinside_get_statement(info, first_token, &eval_last,
                                     &remove_last, &block);

        if (ret != CINSIDE_SUCCESS)                 /* _PARTIAL, _ERR_* */
            return ret;

        if (info->token[first_token] == CINSIDE_TOKEN_KEYWORD)
        {
            /*
             * Note, keywords must not return _NOP.  They can return _PARTIAL,
             * _SUCCESS, _SUCCESS_EXIT, _ERR_*, _BREAK, or _CONTINUE ("if" can
             * return break or continue).  Also, keywords have no overall
             * result, so leave had_expr = 0.  Finally, note that eval_last, in
             * the context of keywords, corresponds to the end of the "first
             * body" of the keyword (i.e. the "true" for "if", or whole body
             * for loops) and block corresponds to the "second body" if present
             * (the "false" for if).
             */
            body1_last = eval_last;
            body2_last = block;
            ret = _cinside_eval_keyword(info, first_token, &body1_last,
                                        &body2_last);

            if (ret != CINSIDE_SUCCESS)
                return ret;
        }
        else if (block)
        {
            /* statement blocks have no overall result, leave had_expr 0 */
            ret = _cinside_eval_tokens(info, first_token + 2,
                                       remove_last - 2, NULL);

            if (ret == CINSIDE_PARTIAL)
            {
                return _cinside_error(info, CINSIDE_ERR_SYNTAX,
                                      "incomplete statement in block");
            }

            if ((ret != CINSIDE_SUCCESS) && (ret != CINSIDE_NOP))
                return ret;
        }
        else
        {
            ret = _cinside_eval_expr(info, first_token, eval_last, NULL,
                                     NULL);

            if (CINSIDE_RET_ERROR(ret) || (ret == CINSIDE_SUCCESS_CONT))
                return ret;

            if (ret == CINSIDE_SUCCESS)
            {
                had_expr = 1;
                if (result != NULL)
                    *result = info->token[first_token + 1];
            }
        }

        /* account for inserted tokens (parenthesizations, etc.) */
        last_token += (info->num_tokens - old_num_tokens);

        /* skip past the last token in the statement, either } or ; */
        remove_last += 2;

        if ((first_token == 0) && (last_token == (info->num_tokens - 2)))
        {
            /* outermost invocation, called from cinside_eval() or a keyword */
            for (i = 0; (remove_last + i) < info->num_tokens; i++)
                info->token[first_token + i] = info->token[remove_last + i];

            info->num_tokens -= (remove_last);
            last_token -= (remove_last);
        }
        else
        {
            first_token = remove_last;      /* already skipped past } or ; */
        }
    }

    if (had_expr)
        return CINSIDE_SUCCESS;

    return CINSIDE_NOP;
}

int _cinside_get_statement(cinside_info *info, size_t first_token,
                           size_t *eval_last, size_t *remove_last,
                           size_t *block)
{
    int ret, is_list;
    size_t i, rbrace, rparen, num_inner_tokens, body1_last, body2_last;
    uint32_t token;

    if (block != NULL)
        *block = 0;

    if (info->token[first_token] == CINSIDE_TOKEN_KEYWORD)
    {
        ret = _cinside_get_keyword(info, first_token, &body1_last, remove_last,
                                   &body2_last);

        if (eval_last != NULL)
            *eval_last = body1_last;

        if (block != NULL)
            *block = body2_last;

        return ret;
    }
    else if (info->token[first_token] == CINSIDE_TOKEN_LBRACE)
    {
        rbrace = (info->token[first_token + 1] & 0x00FFFFFF) + first_token;
        is_list = 1;
        num_inner_tokens = 0;
        for (i = first_token + 2; i < rbrace; i += 2)
        {
            token = info->token[i];
            if ((token != CINSIDE_TOKEN_LBRACE) &&
                (token != CINSIDE_TOKEN_RBRACE))
            {
                num_inner_tokens++;
            }

            if (token == CINSIDE_TOKEN_SEMICOLON)
            {
                is_list = 0;
            }
            else if (token == CINSIDE_TOKEN_KEYWORD)
            {
                if (info->token[i - 2] == CINSIDE_TOKEN_LPAREN)
                {
                    rparen = (i - 2) + (info->token[i - 1] & 0x00FFFFFF);
                    for (i += 2; i < rparen; i += 2)
                    {
                        if (info->token[i] != CINSIDE_TOKEN_KEYWORD)
                        {
                            is_list = 0;
                            break;
                        }
                    }
                }
            }

            if (is_list == 0)
                break;
        }

        if ((is_list == 0) || (num_inner_tokens == 0))
        {
            if (block != NULL)
                *block = 1;

            if (eval_last != NULL)
                *eval_last = rbrace;

            *remove_last = rbrace;
            return CINSIDE_SUCCESS;
        }
    }

    for (i = first_token; i < info->num_tokens; i += 2)
    {
        token = info->token[i];
        if (token == CINSIDE_TOKEN_SEMICOLON)
        {
            if (eval_last != NULL)
                *eval_last = i - 2;

            *remove_last = i;
            return CINSIDE_SUCCESS;
        }
        else if ((token == CINSIDE_TOKEN_LBRACE) ||
                 (token == CINSIDE_TOKEN_LPAREN) ||
                 (token == CINSIDE_TOKEN_LBRACKET) ||
                 (token == CINSIDE_TOKEN_QUESTION))
        {
            i += (info->token[i + 1] & 0x00FFFFFF);
        }
    }

    return CINSIDE_PARTIAL;
}

int _cinside_eval_expr(cinside_info *info, size_t first_token,
                       size_t last_token, size_t *num, uint32_t **lval_addr)
{
    int ret;
    size_t i;
    uint32_t token, min_token;
    const cinside_token_def *sym;

    if (((last_token - first_token) + 2) == 0)      /* empty expression */
        return CINSIDE_NOP;

    CINSIDE_DEBUG("%u to %u: EXPR\n", first_token, last_token);
    if (lval_addr != NULL)
        *lval_addr = NULL;

    if (num != NULL)
        *num = 0;

    if (info->token[first_token] == CINSIDE_TOKEN_BUILTIN) /* EXPR ==> BUILTIN ... */
    {
        return _cinside_eval_builtin(info, first_token, last_token, num,
                                     lval_addr);
    }

    min_token = CINSIDE_MAX_OPERATOR;
    for (i = first_token; i <= last_token; i += 2)
    {
        token = info->token[i];
        if ((token == CINSIDE_TOKEN_LPAREN) ||
            (token == CINSIDE_TOKEN_LBRACE) ||
            (token == CINSIDE_TOKEN_LBRACKET) ||
            (token == CINSIDE_TOKEN_QUESTION))  /* NOTE: hard-coded ternary */
        {
            /* small hack: ternary operators can be lowest precedence */
            if ((token == CINSIDE_TOKEN_QUESTION) && (token < min_token))
                min_token = token;

            i += (info->token[i + 1] & 0x00FFFFFF);
            continue;
        }

        /*
         * Minimum operator found is the lowest precedence, and thus should be
         * the first one "pulled apart" so that its parts can be evaluated
         * before the operator itself is.
         */
        if ((token >= CINSIDE_MIN_OPERATOR) && (token < min_token))
            min_token = token;
    }

    if (min_token == CINSIDE_MAX_OPERATOR)
    {
        /* no valid operator found, so it must be a base expression */
        CINSIDE_DEBUG("<EXPR ==> BASE_EXPR>\n");
        return _cinside_eval_base_expr(info, first_token, last_token, num,
                                       lval_addr);
    }

    ret = _cinside_get_token_def(info, min_token, &sym);
    if (ret != CINSIDE_SUCCESS)                     /* returns silent errors */
    {
        return _cinside_error(info, CINSIDE_ERR_GENERAL,
                              "unknown token 0x%X", min_token);
    }

    if (sym->flags & CINSIDE_ASSOC_LR)
    {
        ret = _cinside_eval_op_lr(info, first_token, last_token, num,
                                  lval_addr, sym);
    }
    else if (sym->flags & CINSIDE_ASSOC_RL)
    {
        ret = _cinside_eval_op_rl(info, first_token, last_token, num,
                                  lval_addr, sym);
    }
    else
    {
        return _cinside_error(info, CINSIDE_ERR_GENERAL,
                              "undefined associativity for token 0x%X",
                              min_token);
    }

    return ret;
}

static int _cinside_eval_op_lr(cinside_info *info, size_t first_token,
                               size_t last_token, size_t *num,
                               uint32_t **lval_addr,
                               const cinside_token_def *sym)
{
    int ret;
    size_t i;
    uint32_t token, sep1, end, total_parens, j, group, check;
    _cinside_expr_set exprs;

    /* get the precedence grouping value */
    group = (sym->token & 0xFF00);
    IF_CINSIDE_DEBUG()
    {
        CINSIDE_DEBUG("%u to %u: operator(s)", first_token, last_token);
        check = (group + 1);
        while (_cinside_dump_token(info, check++, 0) == CINSIDE_SUCCESS);
        CINSIDE_DEBUG(" (left-associative)\n");
    }

    sep1 = 0;
    end = last_token;
    total_parens = 0;
    for (i = first_token; i <= end; i += 2)
    {
        token = info->token[i];
        if ((token == CINSIDE_TOKEN_LPAREN) ||
            (token == CINSIDE_TOKEN_LBRACE) ||
            (token == CINSIDE_TOKEN_LBRACKET))
        {
            i += (info->token[i + 1] & 0x00FFFFFF);
            continue;
        }

        /* check this token against all tokens in the specified group */
        check = (group + 1);
        do
        {
            ret = _cinside_get_token_def(info, check, NULL);
        } while ((ret == CINSIDE_SUCCESS) && (token != (check++)));

        if (ret != CINSIDE_SUCCESS)
            continue;               /* not interested in this token, skip */

        j = 0;
        if (sep1 != 0)
        {
            /*
             * We already have one occurrence of an "interesting" token, so
             * parenthesize from the beginning to here-1 (so the existing
             * occurrence and its operands are contained within the
             * parentheses).
             */
            ret = _cinside_parenthesize(info, first_token, i - 2);
            if (ret != CINSIDE_SUCCESS)
                return ret;

            /* we added two token "pairs" (4 tokens) before "here" */
            i += 4;
            end += 4;
        }

        /* save this occurrence of the interesting token */
        sep1 = i;
    }

    IF_CINSIDE_DEBUG()
    {
        CINSIDE_DEBUG("Parenthesized:");
        for (i = first_token; i <= end; i += 2)
            _cinside_dump_token(info, info->token[i], i);

        CINSIDE_DEBUG("\n");
    }

    exprs.token = info->token[sep1];
    exprs.expr1_first = first_token;
    exprs.expr1_last = (sep1 - 2);
    exprs.expr2_first = (sep1 + 2);
    exprs.expr2_last = end;

    return (sym->eval)(info, &exprs, num, lval_addr);
}

static int _cinside_eval_op_rl(cinside_info *info, size_t first_token,
                               size_t last_token, size_t *num,
                               uint32_t **lval_addr,
                               const cinside_token_def *sym)
{
    int ret;
    size_t i, count;
    uint32_t token, sep1, sep2, end, total_parens, j, group, check;
    _cinside_expr_set exprs;

    /* get the precedence grouping value */
    group = (sym->token & 0xFF00);
    IF_CINSIDE_DEBUG()
    {
        CINSIDE_DEBUG("%u to %u: operator(s)", first_token, last_token);
        check = (group + 1);
        while (_cinside_dump_token(info, check++, 0) == CINSIDE_SUCCESS);
        CINSIDE_DEBUG(" (left-associative)\n");
    }

    if ((ret = _cinside_list_reset(info, info->sep_stack)) != CINSIDE_SUCCESS)
        return ret;

    sep1 = 0;
    sep2 = 0;
    end = last_token;
    total_parens = 0;

    /* hacked loop conditional since size_t is unsigned */
    for (i = end; (i + 2) >= (first_token + 2); i -= 2)
    {
        token = info->token[i];
        if ((token == CINSIDE_TOKEN_RPAREN) ||
            (token == CINSIDE_TOKEN_RBRACE) ||
            (token == CINSIDE_TOKEN_RBRACKET))
        {
            i -= (info->token[i + 1] & 0x00FFFFFF);
            continue;
        }

        ret = _cinside_list_count(info, info->sep_stack, &count);
        if (ret != CINSIDE_SUCCESS)
            return ret;

        if ((sym->flags & CINSIDE_COMBINED) &&
            (token == (group + 2)))
        {
            if (sep1 != 0)
            {
                /*
                 * We already have an occurrence of the first part of this
                 * ternary operator, so check where to parenthesize.
                 */
                if (count != 0)
                {
                    /*
                     * We also have a prior unmatched occurrence of the second
                     * part of this ternary operator, so parenthesize from
                     * here+1 to just before that occurrence (so the current
                     * ternary operation is contained within the parentheses).
                     * The current operation then becomes the second operand
                     * (out of three) for the outer ternary operation.
                     */

                    /* temporarily grab the location of the prior occurrence */
                    ret = _cinside_list_pop(info, info->sep_stack, &j);
                    if (ret != CINSIDE_SUCCESS)
                        return ret;

                    ret = _cinside_parenthesize(info, i + 2,
                                                (j + total_parens) - 2);

                    if (ret != CINSIDE_SUCCESS)
                        return ret;

                    /* restore the location to the stack */
                    ret = _cinside_list_push(info, info->sep_stack, j);
                }
                else
                {
                    /*
                     * With no prior unmatched occurrence of the second part,
                     * parenthesize from here+1 to the end (so the current
                     * ternary operation is contained within the parentheses).
                     * The current operation then becomes the third operand
                     * (out of three) for the outer ternary operation.
                     */
                    ret = _cinside_parenthesize(info, i + 2, end);
                }

                if (ret != CINSIDE_SUCCESS)
                    return ret;

                /* we added two token "pairs" (4 tokens) */
                end += 4;
                total_parens += 4;
                sep1 = 0;
            }

            /* save this location so it can be matched with the first part */
            ret = _cinside_list_push(info, info->sep_stack, (uint32_t)i);
            if (ret != CINSIDE_SUCCESS)
                return ret;

            continue;
        }

        if (sym->flags & CINSIDE_COMBINED)
        {
            if (token != (group + 1))
                continue;       /* not interested in this token, skip */

            /* first part requires that a second part has already occurred */
            if (count == 0)
            {
                return _cinside_error(info, CINSIDE_ERR_SYNTAX,
                                      "unmatched ternary operator");
            }

            ret = _cinside_list_pop(info, info->sep_stack, &j);
            if (ret != CINSIDE_SUCCESS)
                return ret;

            if (sep1 != 0)
            {
                /*
                 * We already have an occurrence of the first part, so
                 * parenthesize from here+1 to our popped second part (so the
                 * current ternary operation is contained within the
                 * parentheses).  The current operation then becomes the second
                 * operand (out of three) for the outer ternary operation.
                 * Note, we may have already put some new parenthesis in the
                 * current operation, so account for those.
                 */
                j += total_parens;
                ret = _cinside_parenthesize(info, i + 2, j - 2);
                if (ret != CINSIDE_SUCCESS)
                    return ret;

                /* we added two token "pairs" (4 tokens) */
                end += 4;
                total_parens += 4;
                j += 4;
            }
        }
        else
        {
            /* check this token against all tokens in the specified group */
            check = (group + 1);
            do
            {
                ret = _cinside_get_token_def(info, check, NULL);
            } while ((ret == CINSIDE_SUCCESS) && (token != (check++)));

            if (ret != CINSIDE_SUCCESS)
                continue;           /* not interested in this token, skip */

            j = 0;
            if (sep1 != 0)
            {
                /*
                 * We already have an occurrence of an "interesting" token, so
                 * parenthesize from here+1 to the end (so the existing
                 * occurrence and its operands are contained within the
                 * parentheses).
                 */
                ret = _cinside_parenthesize(info, i + 2, end);
                if (ret != CINSIDE_SUCCESS)
                    return ret;

                /* we added two token "pairs" (4 tokens) */
                end += 4;
            }
        }

        /* save this occurrence of the interesting token(s) */
        sep1 = i;
        sep2 = j;
    }

    IF_CINSIDE_DEBUG()
    {
        CINSIDE_DEBUG("Parenthesized:");
        for (i = first_token; i <= end; i += 2)
            _cinside_dump_token(info, info->token[i], i);

        CINSIDE_DEBUG("\n");
    }

    if (sym->flags & CINSIDE_COMBINED)
    {
        ret = _cinside_list_count(info, info->sep_stack, &count);
        if (ret != CINSIDE_SUCCESS)
            return ret;

        if (count != 0)
        {
            return _cinside_error(info, CINSIDE_ERR_SYNTAX,
                                  "unmatched ternary operator");
        }
    }

    exprs.token = info->token[sep1];
    exprs.expr1_first = first_token;
    exprs.expr1_last = (sep1 - 2);
    exprs.expr2_first = (sep1 + 2);
    if (sym->flags & CINSIDE_COMBINED)
    {
        exprs.expr2_last = (sep2 - 2);
        exprs.expr3_first = (sep2 + 2);
        exprs.expr3_last = end;
    }
    else
    {
        exprs.expr2_last = end;
    }

    return (sym->eval)(info, &exprs, num, lval_addr);
}

/*
 * Adds parentheses at start and stop (in terms of existing indices).  In other
 * words, everything that was originally from start to stop, inclusive, will
 * now be inside the new parentheses.
 */
static int _cinside_parenthesize(cinside_info *info, size_t start, size_t stop)
{
    size_t i, new_max_tokens, level, match_offset;
    uint32_t *new_tokens;
    uint32_t val;

    /* will be adding 4 new tokens, make sure they will fit */
    if ((info->num_tokens + 4) >= info->max_tokens)
    {
        new_max_tokens = info->max_tokens << 1;

        /*
         * Freed in _cinside_parenthesize(), _cinside_tokenize(), or
         * _cinside_destroy()
         */
        new_tokens = malloc(new_max_tokens * sizeof(uint32_t));
        if (new_tokens == NULL)
            return _cinside_error(info, CINSIDE_ERR_RESOURCES, NULL);

        memset(new_tokens, 0, new_max_tokens * sizeof(uint32_t));
        memcpy(new_tokens, info->token,
               info->max_tokens * sizeof(uint32_t));

        free(info->token);
        info->token = new_tokens;
        info->max_tokens = new_max_tokens;
    }

    /* move everything that is after stop, 4 spots to the right */
    level = 0;
    for (i = (info->num_tokens - 1); i > (stop + 1); i--)
    {
        val = info->token[i];
        match_offset = val & 0x00FFFFFF;

        /*
         * If odd-numbered token index, and the previous one is )/}/]/:,
         * and its matching (/{/[/? is before start, then get that token's
         * level, and add 4 to its offset value.  Then update its paired
         * token's value.  The last value of level obtained here (if any...
         * zero otherwise) will be incremented and used as the level of the new
         * parentheses.
         */
        if (((i & 1) == 1) &&
            ((info->token[i - 1] == CINSIDE_TOKEN_RPAREN) ||
             (info->token[i - 1] == CINSIDE_TOKEN_RBRACE) ||
             (info->token[i - 1] == CINSIDE_TOKEN_RBRACKET) ||
             (info->token[i - 1] == CINSIDE_TOKEN_COLON)) &&
            ((i - match_offset) < start))
        {
            level = ((val & 0xFF000000) >> 24);
            val = (level << 24) | ((match_offset + 4) & 0x00FFFFFF);
            info->token[i - match_offset] = val;
        }

        info->token[i + 4] = val;
    }

    level++;

    /* add right parenthesis at the "new" value of stop */
    info->token[stop + 4] = CINSIDE_TOKEN_RPAREN;
    info->token[stop + 5] = (level << 24) | ((stop + 4) - start);

    /*
     * Move everything that is inside the new parentheses, 2 spots to the
     * right.  Hacked loop conditional is because size_t is unsigned.
     */
    for (i = (stop + 1); (i + 1) >= (start + 1); i--)
    {
        val = info->token[i];
        match_offset = val & 0x00FFFFFF;

        /*
         * If odd-numbered token index, and the previous one is )/}/]/:, then
         * increment that token's level.
         */
        if (((i & 1) == 1) &&
            ((info->token[i - 1] == CINSIDE_TOKEN_RPAREN) ||
             (info->token[i - 1] == CINSIDE_TOKEN_RBRACE) ||
             (info->token[i - 1] == CINSIDE_TOKEN_RBRACKET) ||
             (info->token[i - 1] == CINSIDE_TOKEN_COLON)))
        {
            val += 0x01000000;
            info->token[i - match_offset] = val;
        }

        info->token[i + 2] = val;
    }

    /* add left parenthesis at start (position didn't move any) */
    info->token[start] = CINSIDE_TOKEN_LPAREN;
    info->token[start + 1] = (level << 24) | ((stop + 4) - start);

    info->num_tokens += 4;
    return CINSIDE_SUCCESS;
}

static int _cinside_eval_base_expr(cinside_info *info, size_t first_token,
                                   size_t last_token, size_t *num,
                                   uint32_t **lval_addr)
{
    size_t num_tokens;
    uint32_t token, token2, last;

    CINSIDE_DEBUG("%u to %u: BASE_EXPR\n", first_token, last_token);
    num_tokens = ((last_token - first_token) + 2);

    /* check num/lval_addr != NULL everywhere they are used */

    /*
     * First check for built-in commands, since they can be any number of
     * tokens (2 or more):
     *      BUILTIN ...
     * Next, check for all other cases with exactly 2 tokens:
     *      INT             STRING          NAME
     * Finally, check for all cases with identifiable first and last tokens:
     *      { VALS }        ( EXPR )
     *      NAME ( VALS )   NAME [ EXPR ]
     */

    token = info->token[first_token];
    token2 = info->token[first_token + 2];
    last = info->token[last_token];

    if ((num_tokens == 2) &&
        (token == CINSIDE_TOKEN_INT))           /* BASE_EXPR ==> INT */
    {
        return _cinside_eval_int(info, first_token, last_token, num,
                                 lval_addr);
    }
    else if ((num_tokens == 2) &&
             (token == CINSIDE_TOKEN_STRING))   /* BASE_EXPR ==> STRING */
    {
        return _cinside_eval_string(info, first_token, last_token, num,
                                    lval_addr);
    }
    else if ((num_tokens == 2) &&
             (token == CINSIDE_TOKEN_NAME))     /* BASE_EXPR ==> NAME */
    {
        return _cinside_eval_name(info, first_token, last_token, num,
                                  lval_addr);
    }
    else if ((token == CINSIDE_TOKEN_LBRACE) &&
             (last == CINSIDE_TOKEN_RBRACE))    /* BASE_EXPR ==> { VALS } */
    {
        return _cinside_eval_list(info, first_token, last_token, num,
                                  lval_addr);
    }
    else if ((token == CINSIDE_TOKEN_LPAREN) &&
             (last == CINSIDE_TOKEN_RPAREN))    /* BASE_EXPR ==> ( EXPR ) */
    {
        return _cinside_eval_paren(info, first_token, last_token, num,
                                   lval_addr);
    }
    else if ((token == CINSIDE_TOKEN_NAME) &&
             (token2 == CINSIDE_TOKEN_LPAREN) &&
             (last == CINSIDE_TOKEN_RPAREN))  /* BASE_EXPR ==> NAME ( VALS ) */
    {
        return _cinside_eval_call(info, first_token, last_token, num,
                                  lval_addr);
    }
    else if ((token == CINSIDE_TOKEN_NAME) &&
             (token2 == CINSIDE_TOKEN_LBRACKET) &&
             (last == CINSIDE_TOKEN_RBRACKET)) /* BASE_EXPR ==> NAME [ EXPR ] */
    {
        return _cinside_eval_array(info, first_token, last_token, num,
                                   lval_addr);
    }

    return _cinside_error(info, CINSIDE_ERR_SYNTAX, "invalid base expression");
}

static int _cinside_eval_int(cinside_info *info, size_t first_token,
                             size_t last_token, size_t *num,
                             uint32_t **lval_addr)
{
    uint32_t val;

    CINSIDE_DEBUG("<BASE_EXPR ==> INT>\n");

    info->token[first_token] = CINSIDE_TOKEN_DATA;
    val = info->token[first_token + 1];

    CINSIDE_DEBUG("( = 0x%X/%d)\n", val, val);
    return CINSIDE_SUCCESS;
}

static int _cinside_eval_string(cinside_info *info, size_t first_token,
                                size_t last_token, size_t *num,
                                uint32_t **lval_addr)
{
    _cinside_string_hdr *hdr;
    uint32_t val;

    CINSIDE_DEBUG("<BASE_EXPR ==> STRING>\n");

    info->token[first_token] = CINSIDE_TOKEN_DATA;
    hdr = (_cinside_string_hdr *)(info->token[first_token + 1]);
    val = (uint32_t)(hdr->str);
    info->token[first_token + 1] = val;

    if (lval_addr != NULL)
        *lval_addr = (uint32_t *)val;

    CINSIDE_DEBUG("( = 0x%X/\"%s\")\n", val, (char *)val);
    return CINSIDE_SUCCESS;
}

static int _cinside_eval_name(cinside_info *info, size_t first_token,
                              size_t last_token, size_t *num,
                              uint32_t **lval_addr)
{
    int ret;
    uint32_t val;
    char *name;
    cinside_variable *var;

    CINSIDE_DEBUG("<BASE_EXPR ==> NAME>\n");

    info->token[first_token] = CINSIDE_TOKEN_DATA;
    val = info->token[first_token + 1];
    name = (char *)val;
    ret = _cinside_get_variable(info, name, &var, 0);
    if (ret != CINSIDE_SUCCESS)
        return ret;

    val = (uint32_t)(var->addr);

    /* only dereference non-list variables */
    if (var->list_items == 0)
        val = *((uint32_t *)val);

    info->token[first_token + 1] = val;
    if (lval_addr != NULL)
        *lval_addr = var->addr;

    CINSIDE_DEBUG("(%s = 0x%X/@0x%X)\n", name, val, var->addr);
    return CINSIDE_SUCCESS;
}

static int _cinside_eval_list(cinside_info *info, size_t first_token,
                              size_t last_token, size_t *num,
                              uint32_t **lval_addr)
{
    int i, ret;
    size_t tmp_num;
    uint32_t *next;
    uint32_t val;

    CINSIDE_DEBUG("<BASE_EXPR ==> { VALS }>\n");

    ret = _cinside_eval_vals(info, first_token + 2, last_token - 2, &tmp_num,
                             lval_addr);

    if (CINSIDE_RET_ERROR(ret))
        return ret;

    val = info->token[first_token + 3];
    info->token[first_token] = info->token[first_token + 2];
    info->token[first_token + 1] = val;
    info->token[first_token + 2] = CINSIDE_TOKEN_NONE;
    info->token[first_token + 3] = 0;
    info->token[last_token] = CINSIDE_TOKEN_NONE;
    info->token[last_token + 1] = 0;

    next = (uint32_t *)val;
    CINSIDE_DEBUG("( = 0x%X/{", val);
    for (i = 0; i < tmp_num; i++)
        CINSIDE_DEBUG("%s0x%X", ((i > 0) ? ", " : ""), *(next++));

    if (num != NULL)
        *num = tmp_num;

    CINSIDE_DEBUG("})\n");
    return CINSIDE_SUCCESS;
}

static int _cinside_eval_paren(cinside_info *info, size_t first_token,
                               size_t last_token, size_t *num,
                               uint32_t **lval_addr)
{
    int ret;

    CINSIDE_DEBUG("<BASE_EXPR ==> ( EXPR )>\n");
    ret = _cinside_eval_expr(info, first_token + 2, last_token - 2,
                             num, lval_addr);

    if (CINSIDE_RET_ERROR(ret))
        return ret;

    info->token[first_token] = info->token[first_token + 2];
    info->token[first_token + 1] = info->token[first_token + 3];
    info->token[first_token + 2] = CINSIDE_TOKEN_NONE;
    info->token[first_token + 3] = 0;
    info->token[last_token] = CINSIDE_TOKEN_NONE;
    info->token[last_token + 1] = 0;

    CINSIDE_DEBUG("( = 0x%X)\n", info->token[first_token + 1]);
    return ret;
}

static int _cinside_eval_call(cinside_info *info, size_t first_token,
                              size_t last_token, size_t *num,
                              uint32_t **lval_addr)
{
    int i, ret;
    size_t num_tokens, num_vals;
    uint32_t argc, val;
    uint32_t *argv, *tmp_addr, *next;
    char *name;
    cinside_function *function;

    CINSIDE_DEBUG("<BASE_EXPR ==> NAME ( VALS )>\n");
    num_tokens = ((last_token - first_token) + 2);
    num_vals = 0;
    next = NULL;
    if (num_tokens > 6)
    {
        ret = _cinside_eval_vals(info, first_token + 4, last_token - 2,
                                 &num_vals, &tmp_addr);

        if (CINSIDE_RET_ERROR(ret))
            return ret;

        next = (uint32_t *)(info->token[first_token + 5]);
    }

    num_vals++;
    name = (char *)(info->token[first_token + 1]);
    ret = _cinside_get_function(info, name, &function);
    if (ret != CINSIDE_SUCCESS)
        return ret;

    /* temporarily use some list storage for argv[] */
    ret = _cinside_list_reserve(info, info->lists, num_vals, &argv);
    if (ret != CINSIDE_SUCCESS)
        return ret;

    ret = _cinside_list_push(info, info->lists,
                             (uint32_t)(function->addr));

    if (ret != CINSIDE_SUCCESS)
        return ret;

    argc = num_vals;
    for (i = 1; i < num_vals; i++)
    {
        ret = _cinside_list_push(info, info->lists, *(next++));
        if (ret != CINSIDE_SUCCESS)
            return ret;
    }

    ret = _cinside_caller(info, name, argc, argv, &val);
    if (CINSIDE_RET_ERROR(ret))
        return ret;

    /* effectively remove the temporary argv[] from list storage */
    ret = _cinside_list_return(info, info->lists, argc);
    if (ret != CINSIDE_SUCCESS)
        return ret;

    /* remove the result of eval_vals() (don't bother upon errors above) */
    ret = _cinside_list_return(info, info->lists, num_vals - 1);
    if (ret != CINSIDE_SUCCESS)
        return ret;

    info->token[first_token] = CINSIDE_TOKEN_DATA;
    info->token[first_token + 1] = val;

    /* remove the parentheses and argument list pointer */
    info->token[first_token + 2] = CINSIDE_TOKEN_NONE;
    info->token[first_token + 3] = 0;
    info->token[first_token + 4] = CINSIDE_TOKEN_NONE;
    info->token[first_token + 5] = 0;
    info->token[last_token] = CINSIDE_TOKEN_NONE;
    info->token[last_token + 1] = 0;

    next = (argv + 1);
    CINSIDE_DEBUG("(%s(", name);
    for (i = 1; i < num_vals; i++)
        CINSIDE_DEBUG("%s0x%X", ((i > 1) ? ", " : ""), *(next++));

    CINSIDE_DEBUG(") = 0x%X)\n", info->token[first_token + 1]);
    return CINSIDE_SUCCESS;
}

static int _cinside_eval_array(cinside_info *info, size_t first_token,
                               size_t last_token, size_t *num,
                               uint32_t **lval_addr)
{
    int ret;
    uint32_t val;
    cinside_variable *var;
    uint32_t *tmp_addr;
    char *name;

    CINSIDE_DEBUG("<BASE_EXPR ==> NAME [ EXPR ]>\n");
    name = (char *)(info->token[first_token + 1]);
    ret = _cinside_get_variable(info, name, &var, 0);
    if (ret != CINSIDE_SUCCESS)
        return ret;

    ret = _cinside_eval_expr(info, first_token + 4, last_token - 2,
                             NULL, NULL);

    if (CINSIDE_NO_RESULT(ret))
        return _cinside_error(info, CINSIDE_ERR_SYNTAX, "invalid array index");

    if (CINSIDE_RET_ERROR(ret))
        return ret;

    tmp_addr = (var->addr + info->token[first_token + 5]);
    val = *tmp_addr;

    if (lval_addr != NULL)
        *lval_addr = tmp_addr;

    info->token[first_token] = CINSIDE_TOKEN_DATA;
    info->token[first_token + 1] = val;
    info->token[first_token + 2] = CINSIDE_TOKEN_NONE;
    info->token[first_token + 3] = 0;
    info->token[first_token + 4] = CINSIDE_TOKEN_NONE;
    info->token[first_token + 5] = 0;
    info->token[last_token] = CINSIDE_TOKEN_NONE;
    info->token[last_token + 1] = 0;

    CINSIDE_DEBUG("( = 0x%X/@0x%X)\n", val, tmp_addr);
    return CINSIDE_SUCCESS;
}

int _cinside_eval_vals(cinside_info *info, size_t first_token,
                       size_t last_token, size_t *num, uint32_t **lval_addr)
{
    int ret;
    size_t idx, count, next_idx, end_idx, first_comma, num_vals, tmp_num;
    uint32_t token, match, this_val;
    uint32_t *list_addr, *tmp_addr;

    CINSIDE_DEBUG("%u to %u: VALS\n", first_token, last_token);
    if ((ret = _cinside_list_reset(info, info->vals_stack)) != CINSIDE_SUCCESS)
        return ret;

    if ((info->token[last_token] == CINSIDE_TOKEN_COMMA) ||
        (first_token > last_token))
    {
        return _cinside_error(info, CINSIDE_ERR_SYNTAX,
                              "missing list value(s)");
    }

    next_idx = first_token;
    end_idx = first_token;
    num_vals = 0;
    while (next_idx <= last_token)
    {
        token = info->token[next_idx];
        if (token == CINSIDE_TOKEN_COMMA)
        {
            return _cinside_error(info, CINSIDE_ERR_SYNTAX,
                                  "missing list value(s)");
        }

        first_comma = 0;
        for (idx = next_idx; idx <= last_token; idx += 2)
        {
            token = info->token[idx];
            if ((token == CINSIDE_TOKEN_LPAREN) ||
                (token == CINSIDE_TOKEN_LBRACE))
            {
                ret = _cinside_list_push(info, info->vals_stack, token);
                if (ret != CINSIDE_SUCCESS)
                    return ret;
            }
            else if ((token == CINSIDE_TOKEN_RPAREN) ||
                     (token == CINSIDE_TOKEN_RBRACE))
            {
                ret = _cinside_list_pop(info, info->vals_stack, &match);
                if (ret != CINSIDE_SUCCESS)
                    return ret;
            }
            else if (token == CINSIDE_TOKEN_COMMA)
            {
                ret = _cinside_list_count(info, info->vals_stack, &count);
                if (ret != CINSIDE_SUCCESS)
                    return ret;

                if ((count == 0) && (first_comma == 0))
                {
                    first_comma = idx;
                    break;
                }
            }
        }

        if ((end_idx = idx) > last_token)
        {
            CINSIDE_DEBUG("<VALS ==> EXPR>\n");
            end_idx -= 2;
        }
        else if (end_idx < last_token)
        {
            CINSIDE_DEBUG("<VALS ==> EXPR , VALS>\n");
            if ((token == CINSIDE_TOKEN_RPAREN) ||
                (token == CINSIDE_TOKEN_RBRACE))
            {
                token = info->token[end_idx + 2];
                if (token != CINSIDE_TOKEN_COMMA)
                {
                    return _cinside_error(info, CINSIDE_ERR_SYNTAX,
                                          "missing ',' between list values");
                }
            }
            else if (first_comma != 0)
            {
                end_idx = (first_comma - 2);
            }
        }

        if (end_idx < last_token)
            info->token[end_idx + 2] = CINSIDE_TOKEN_NONE;

        ret = _cinside_eval_expr(info, next_idx, end_idx, &tmp_num, &tmp_addr);
        if (CINSIDE_NO_RESULT(ret))
        {
            return _cinside_error(info, CINSIDE_ERR_SYNTAX,
                                  "invalid expression in list");
        }

        if (CINSIDE_RET_ERROR(ret))
            return ret;

        num_vals++;
        next_idx = end_idx + 4;
    }

    ret = _cinside_list_reserve(info, info->lists, num_vals, &list_addr);
    if (ret != CINSIDE_SUCCESS)
        return ret;

    for (idx = first_token; idx <= last_token; idx += 2)
    {
        while ((info->token[idx] == CINSIDE_TOKEN_NONE) && (idx <= last_token))
            idx += 2;

        if (idx > last_token)
            break;

        token = info->token[idx];
        if (token != CINSIDE_TOKEN_DATA)
        {
            return _cinside_error(info, CINSIDE_ERR_GENERAL,
                                  "non-data token 0x%X", token);
        }

        this_val = info->token[idx + 1];
        info->token[idx] = CINSIDE_TOKEN_NONE;
        info->token[idx + 1] = 0;

        ret = _cinside_list_push(info, info->lists, this_val);
        if (ret != CINSIDE_SUCCESS)
            return ret;
    }

    info->token[first_token] = CINSIDE_TOKEN_DATA;
    info->token[first_token + 1] = (uint32_t)list_addr;

    if (lval_addr != NULL)
        *lval_addr = list_addr;

    if (num != NULL)
        *num = num_vals;

    CINSIDE_DEBUG("( = 0x%X)\n", list_addr);
    return CINSIDE_SUCCESS;
}
