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

/* keyword.c - parsing and evaluation of language keywords */

#include <stdlib.h>         /* malloc, free */
#include <string.h>         /* strcmp, memcpy */

#include "language.h"

static int _cinside_eval_if(cinside_info *info, size_t first_token,
                            size_t rparen_idx, size_t *body1_last,
                            size_t *body2_last);
static int _cinside_eval_while(cinside_info *info, size_t first_token,
                               size_t rparen_idx, size_t *body1_last,
                               size_t *body2_last);
static int _cinside_eval_do(cinside_info *info, size_t first_token,
                            size_t rparen_idx, size_t *body1_last,
                            size_t *body2_last);
static int _cinside_eval_for(cinside_info *info, size_t first_token,
                             size_t rparen_idx, size_t *body1_last,
                             size_t *body2_last);
static int _cinside_eval_break(cinside_info *info, size_t first_token,
                               size_t rparen_idx, size_t *body1_last,
                               size_t *body2_last);
static int _cinside_eval_cont(cinside_info *info, size_t first_token,
                              size_t rparen_idx, size_t *body1_last,
                              size_t *body2_last);
static void _cinside_swap_tokens(cinside_info *info, uint32_t *new_buf,
                                 size_t new_max, size_t new_num,
                                 uint32_t **old_buf, size_t *old_max,
                                 size_t *old_num);

int _cinside_get_keyword(cinside_info *info, size_t first_token,
                         size_t *body1_last, size_t *remove_last,
                         size_t *body2_last)
{
    int ret, is_if, is_while, is_do, is_for, is_break, is_continue;
    char *keyword;
    uint32_t next_token;
    size_t lparen_idx, rparen_idx, body1_first, else_idx;

    if ((first_token + 2) == info->num_tokens)
        return CINSIDE_PARTIAL;

    keyword = (char *)(info->token[first_token + 1]);
    next_token = info->token[first_token + 2];
    rparen_idx = 0;
    if (next_token == CINSIDE_TOKEN_LPAREN)
    {
        rparen_idx = info->token[first_token + 3] & 0x00FFFFFF;
        rparen_idx += (first_token + 2);
    }

    is_if = 0;
    is_while = 0;
    is_do = 0;
    is_for = 0;
    is_break = 0;
    is_continue = 0;
    if (strcmp(keyword, "if") == 0)
        is_if = 1;
    else if (strcmp(keyword, "while") == 0)
        is_while = 1;
    else if (strcmp(keyword, "do") == 0)
        is_do = 1;
    else if (strcmp(keyword, "for") == 0)
        is_for = 1;
    else if (strcmp(keyword, "break") == 0)
        is_break = 1;
    else if (strcmp(keyword, "continue") == 0)
        is_continue = 1;

    body1_first = 0;
    *body2_last = 0;
    if (is_if || is_while || is_for)
    {
        if (rparen_idx == 0)
        {
            return _cinside_error(info, CINSIDE_ERR_SYNTAX,
                                  "(expression%s) required after \"%s\"",
                                  (is_for ? "s" : ""), keyword);
        }

        body1_first = rparen_idx + 2;
        if (body1_first == info->num_tokens)
            return CINSIDE_PARTIAL;
    }
    else if (is_do)
    {
        body1_first = first_token + 2;
    }
    else if (is_break || is_continue)
    {
        if (next_token != CINSIDE_TOKEN_SEMICOLON)
        {
            return _cinside_error(info, CINSIDE_ERR_SYNTAX,
                                  "semicolon required after \"%s\"", keyword);
        }

        *remove_last = first_token + 2;
        return CINSIDE_SUCCESS;
    }

    if (is_if || is_while || is_do || is_for)
    {
        ret = _cinside_get_statement(info, body1_first, NULL, body1_last,
                                     NULL);

        if (ret != CINSIDE_SUCCESS)
            return ret;

        *remove_last = *body1_last;     /* will be updated for "if" and "do" */
    }

    if (is_if)
    {
        else_idx = *body1_last + 2;
        if ((else_idx == info->num_tokens) &&
            !(info->flags & CINSIDE_FLAG_INPUT_DONE))
        {
            return CINSIDE_PARTIAL;                 /* not enough info yet */
        }

        if ((else_idx == info->num_tokens) ||
            (info->token[else_idx] != CINSIDE_TOKEN_KEYWORD) ||
            (strcmp((char *)(info->token[else_idx + 1]), "else") != 0))
        {
            return CINSIDE_SUCCESS;
        }

        ret = _cinside_get_statement(info, else_idx + 2, NULL, body2_last,
                                     NULL);

        *remove_last = *body2_last;
        return ret;
    }
    else if (is_while || is_for)
    {
        return CINSIDE_SUCCESS;
    }
    else if (is_do)
    {
        lparen_idx = *body1_last + 4;
        if (lparen_idx >= info->num_tokens)
            return CINSIDE_PARTIAL;

        if ((info->token[lparen_idx - 2] != CINSIDE_TOKEN_KEYWORD) ||
            (strcmp((char *)(info->token[lparen_idx - 1]), "while") != 0) ||
            (info->token[lparen_idx] != CINSIDE_TOKEN_LPAREN))
        {
            return _cinside_error(info, CINSIDE_ERR_SYNTAX,
                                  "\"while (expression);\" required after \"do ...\"");
        }

        rparen_idx = lparen_idx + (info->token[lparen_idx + 1] & 0x00FFFFFF);
        if ((rparen_idx + 2) == info->num_tokens)
            return CINSIDE_PARTIAL;

        if (info->token[rparen_idx + 2] != CINSIDE_TOKEN_SEMICOLON)
        {
            return _cinside_error(info, CINSIDE_ERR_SYNTAX,
                                  "semicolon required after \"do ... while\" statement");
        }

        *remove_last = rparen_idx + 2;
        return CINSIDE_SUCCESS;
    }

    return CINSIDE_SUCCESS;
}

int _cinside_eval_keyword(cinside_info *info, size_t first_token,
                          size_t *body1_last, size_t *body2_last)
{
    char *keyword;
    uint32_t lparen, rparen_idx;

    if ((first_token + 2) == info->num_tokens)
        return CINSIDE_PARTIAL;

    keyword = (char *)(info->token[first_token + 1]);
    lparen = info->token[first_token + 2];
    rparen_idx = 0;
    if (lparen == CINSIDE_TOKEN_LPAREN)
    {
        rparen_idx = info->token[first_token + 3] & 0x00FFFFFF;
        rparen_idx += (first_token + 2);
    }

    if ((rparen_idx == 0) &&
        ((strcmp(keyword, "if") == 0) || (strcmp(keyword, "while") == 0) ||
         (strcmp(keyword, "for") == 0)))
    {
        return _cinside_error(info, CINSIDE_ERR_SYNTAX,
                              "(expression%s) required after \"%s\"",
                              ((strcmp(keyword, "for") == 0) ? "s" : ""),
                              keyword);
    }

    if (strcmp(keyword, "if") == 0)
    {
        return _cinside_eval_if(info, first_token, rparen_idx, body1_last, body2_last);
    }
    else if (strcmp(keyword, "while") == 0)
    {
        return _cinside_eval_while(info, first_token, rparen_idx, body1_last, body2_last);
    }
    else if (strcmp(keyword, "do") == 0)
    {
        return _cinside_eval_do(info, first_token, rparen_idx, body1_last, body2_last);
    }
    else if (strcmp(keyword, "for") == 0)
    {
        return _cinside_eval_for(info, first_token, rparen_idx, body1_last, body2_last);
    }
    else if (strcmp(keyword, "break") == 0)
    {
        return _cinside_eval_break(info, first_token, rparen_idx, body1_last, body2_last);
    }
    else if (strcmp(keyword, "continue") == 0)
    {
        return _cinside_eval_cont(info, first_token, rparen_idx, body1_last, body2_last);
    }
    else
    {
        return _cinside_error(info, CINSIDE_ERR_SYNTAX,
                              "unexpected keyword \"%s\"", keyword);
    }
}

static int _cinside_eval_if(cinside_info *info, size_t first_token,
                            size_t rparen_idx, size_t *body1_last,
                            size_t *body2_last)
{
    int ret;

    ret = _cinside_eval_expr(info, first_token + 4, rparen_idx - 2, NULL,
                             NULL);

    if (CINSIDE_NO_RESULT(ret))
    {
        return _cinside_error(info, CINSIDE_ERR_SYNTAX,
                              "invalid expression in \"if\" statement");
    }

    if (CINSIDE_RET_ERROR(ret))
        return ret;

    if (info->token[first_token + 5])
    {
        ret = _cinside_eval_tokens(info, rparen_idx + 2, *body1_last, NULL);
        if ((ret != CINSIDE_SUCCESS) && (ret != CINSIDE_NOP))
            return ret;
    }
    else
    {
        if (*body2_last == 0)
            return CINSIDE_SUCCESS;

        ret = _cinside_eval_tokens(info, *body1_last + 4, *body2_last, NULL);
        if ((ret != CINSIDE_SUCCESS) && (ret != CINSIDE_NOP))
            return ret;
    }

    return CINSIDE_SUCCESS;
}

static int _cinside_eval_while(cinside_info *info, size_t first_token,
                               size_t rparen_idx, size_t *body1_last,
                               size_t *body2_last)
{
    int ret;
    size_t cond_len, body_len, new_max_tokens, old_max_tokens, old_num_tokens;
    uint32_t *old_tokens, *new_tokens;

    cond_len = ((rparen_idx - 2) - (first_token + 4)) + 2;
    body_len = (*body1_last - (rparen_idx + 2)) + 2;
    if (cond_len > body_len)
        new_max_tokens = cond_len;
    else
        new_max_tokens = body_len;

    ret = _cinside_alloc_tokens(info, &new_tokens, new_max_tokens);
    if (ret != CINSIDE_SUCCESS)
        return ret;

    while (1)
    {
        _cinside_swap_tokens(info, new_tokens, new_max_tokens, cond_len,
                             &old_tokens, &old_max_tokens, &old_num_tokens);

        memcpy(new_tokens, &(old_tokens[first_token + 4]),
               cond_len * sizeof(uint32_t));

        ret = _cinside_eval_expr(info, 0, cond_len - 2, NULL, NULL);
        _cinside_swap_tokens(info, old_tokens, old_max_tokens, old_num_tokens,
                             &new_tokens, &new_max_tokens, NULL);

        if (CINSIDE_NO_RESULT(ret))
        {
            ret = _cinside_error(info, CINSIDE_ERR_SYNTAX,
                                 "invalid expression in \"while\" statement");

            break;
        }

        if (CINSIDE_RET_ERROR(ret))
            break;

        if (!new_tokens[1])
            break;

        _cinside_swap_tokens(info, new_tokens, new_max_tokens, body_len, NULL,
                             NULL, NULL);

        memcpy(new_tokens, &(old_tokens[rparen_idx + 2]),
               body_len * sizeof(uint32_t));

        ret = _cinside_eval_tokens(info, 0, body_len - 2, NULL);
        _cinside_swap_tokens(info, old_tokens, old_max_tokens, old_num_tokens,
                             &new_tokens, &new_max_tokens, NULL);

        if (ret == CINSIDE_BREAK)
        {
            ret = CINSIDE_SUCCESS;
            break;
        }
        else if (ret == CINSIDE_CONTINUE)
        {
            continue;
        }
        else if ((ret != CINSIDE_SUCCESS) && (ret != CINSIDE_NOP))
        {
            break;                          /* allow CINSIDE_SUCCESS_EXIT */
        }
    }

    free(new_tokens);
    return ret;
}

static int _cinside_eval_do(cinside_info *info, size_t first_token,
                            size_t rparen_idx, size_t *body1_last,
                            size_t *body2_last)
{
    int ret;
    size_t cond_len, body_len, new_max_tokens, old_max_tokens, old_num_tokens;
    size_t lparen_idx;
    uint32_t *old_tokens, *new_tokens;

    lparen_idx = *body1_last + 4;
    rparen_idx = lparen_idx + (info->token[lparen_idx + 1] & 0x00FFFFFF);

    cond_len = ((rparen_idx - 2) - (lparen_idx + 2)) + 2;
    body_len = (*body1_last - (first_token + 2)) + 2;
    if (cond_len > body_len)
        new_max_tokens = cond_len;
    else
        new_max_tokens = body_len;

    ret = _cinside_alloc_tokens(info, &new_tokens, new_max_tokens);
    if (ret != CINSIDE_SUCCESS)
        return ret;

    while (1)
    {
        _cinside_swap_tokens(info, new_tokens, new_max_tokens, body_len,
                             &old_tokens, &old_max_tokens, &old_num_tokens);

        memcpy(new_tokens, &(old_tokens[first_token + 2]),
               body_len * sizeof(uint32_t));

        ret = _cinside_eval_tokens(info, 0, body_len - 2, NULL);
        _cinside_swap_tokens(info, old_tokens, old_max_tokens, old_num_tokens,
                             &new_tokens, &new_max_tokens, NULL);

        if (ret == CINSIDE_BREAK)
        {
            ret = CINSIDE_SUCCESS;
            break;
        }
        else if ((ret != CINSIDE_SUCCESS) && (ret != CINSIDE_NOP) &&
                 (ret != CINSIDE_CONTINUE))
        {
            break;                          /* allow CINSIDE_SUCCESS_EXIT */
        }

        _cinside_swap_tokens(info, new_tokens, new_max_tokens, cond_len, NULL,
                             NULL, NULL);

        memcpy(new_tokens, &(old_tokens[lparen_idx + 2]),
               cond_len * sizeof(uint32_t));

        ret = _cinside_eval_expr(info, 0, cond_len - 2, NULL, NULL);
        _cinside_swap_tokens(info, old_tokens, old_max_tokens, old_num_tokens,
                             &new_tokens, &new_max_tokens, NULL);

        if (CINSIDE_NO_RESULT(ret))
        {
            ret = _cinside_error(info, CINSIDE_ERR_SYNTAX,
                                 "invalid expression in \"do ... while\" statement");

            break;
        }

        if (CINSIDE_RET_ERROR(ret))
            break;

        if (!new_tokens[1])
            break;
    }

    free(new_tokens);
    return ret;
}

static int _cinside_eval_for(cinside_info *info, size_t first_token,
                             size_t rparen_idx, size_t *body1_last,
                             size_t *body2_last)
{
    int ret;
    size_t i, semi1, semi2, cond_len, body_len, post_len, new_max_tokens;
    size_t old_max_tokens, old_num_tokens;
    uint32_t *old_tokens, *new_tokens;

    semi1 = 0;
    semi2 = 0;
    for (i = first_token + 4; i < rparen_idx; i += 2)
    {
        if (info->token[i] != CINSIDE_TOKEN_SEMICOLON)
            continue;

        if (semi1 == 0)
        {
            semi1 = i;
        }
        else if (semi2 == 0)
        {
            semi2 = i;
        }
        else
        {
            return _cinside_error(info, CINSIDE_ERR_SYNTAX,
                                  "extra semicolon in \"for\" statement");
        }
    }

    if (semi2 == 0)
    {
        return _cinside_error(info, CINSIDE_ERR_SYNTAX,
                              "missing semicolon%s in \"for\" statement",
                              ((semi1 == 0) ? "s" : ""));
    }

    old_num_tokens = info->num_tokens;
    ret = _cinside_eval_expr(info, first_token + 4, semi1 - 2, NULL, NULL);

    if ((ret == CINSIDE_BREAK) || (ret == CINSIDE_CONTINUE))
    {
        return _cinside_error(info, CINSIDE_ERR_SYNTAX,
                              "invalid expression in \"for\" statement");
    }

    /* _NOP and _SUCCESS_EXIT are ok here */
    if ((ret != CINSIDE_SUCCESS) && (ret != CINSIDE_NOP))
        return ret;

    semi1 += (info->num_tokens - old_num_tokens);
    semi2 += (info->num_tokens - old_num_tokens);
    rparen_idx += (info->num_tokens - old_num_tokens);

    post_len = ((rparen_idx - 2) - (semi2 + 2)) + 2;
    cond_len = ((semi2 - 2) - (semi1 + 2)) + 2;
    body_len = (*body1_last - (rparen_idx + 2)) + 2;
    if (cond_len > body_len)
        new_max_tokens = cond_len;
    else
        new_max_tokens = body_len;

    if (post_len > new_max_tokens)
        new_max_tokens = post_len;

    ret = _cinside_alloc_tokens(info, &new_tokens, new_max_tokens);
    if (ret != CINSIDE_SUCCESS)
        return ret;

    while (1)
    {
        _cinside_swap_tokens(info, new_tokens, new_max_tokens, cond_len,
                             &old_tokens, &old_max_tokens, &old_num_tokens);

        memcpy(new_tokens, &(old_tokens[semi1 + 2]),
               cond_len * sizeof(uint32_t));

        ret = _cinside_eval_expr(info, 0, cond_len - 2, NULL, NULL);
        _cinside_swap_tokens(info, old_tokens, old_max_tokens, old_num_tokens,
                             &new_tokens, &new_max_tokens, NULL);

        if ((ret == CINSIDE_BREAK) || (ret == CINSIDE_CONTINUE))
        {
            ret = _cinside_error(info, CINSIDE_ERR_SYNTAX,
                                 "invalid expression in \"for\" statement");

            break;
        }

        /* _NOP and _SUCCESS_EXIT are ok here */
        if ((ret != CINSIDE_SUCCESS) && (ret != CINSIDE_NOP))
            break;

        if ((ret == CINSIDE_SUCCESS) && !new_tokens[1])
            break;

        _cinside_swap_tokens(info, new_tokens, new_max_tokens, body_len, NULL,
                             NULL, NULL);

        memcpy(new_tokens, &(old_tokens[rparen_idx + 2]),
               body_len * sizeof(uint32_t));

        ret = _cinside_eval_tokens(info, 0, body_len - 2, NULL);
        _cinside_swap_tokens(info, old_tokens, old_max_tokens, old_num_tokens,
                             &new_tokens, &new_max_tokens, NULL);

        if (ret == CINSIDE_BREAK)
        {
            ret = CINSIDE_SUCCESS;
            break;
        }
        else if ((ret != CINSIDE_SUCCESS) && (ret != CINSIDE_NOP) &&
                 (ret != CINSIDE_CONTINUE))
        {
            break;                          /* allow CINSIDE_SUCCESS_EXIT */
        }

        _cinside_swap_tokens(info, new_tokens, new_max_tokens, post_len, NULL,
                             NULL, NULL);

        memcpy(new_tokens, &(old_tokens[semi2 + 2]),
               post_len * sizeof(uint32_t));

        ret = _cinside_eval_expr(info, 0, post_len - 2, NULL, NULL);
        _cinside_swap_tokens(info, old_tokens, old_max_tokens, old_num_tokens,
                             &new_tokens, &new_max_tokens, NULL);

        if ((ret == CINSIDE_BREAK) || (ret == CINSIDE_CONTINUE))
        {
            ret = _cinside_error(info, CINSIDE_ERR_SYNTAX,
                                 "invalid expression in \"for\" statement");

            break;
        }

        if ((ret != CINSIDE_SUCCESS) && (ret != CINSIDE_NOP))
            break;                          /* allow CINSIDE_SUCCESS_EXIT */
    }

    free(new_tokens);
    return ret;
}

static int _cinside_eval_break(cinside_info *info, size_t first_token,
                               size_t rparen_idx, size_t *body1_last,
                               size_t *body2_last)
{
    return CINSIDE_BREAK;
}

static int _cinside_eval_cont(cinside_info *info, size_t first_token,
                              size_t rparen_idx, size_t *body1_last,
                              size_t *body2_last)
{
    return CINSIDE_CONTINUE;
}

static void _cinside_swap_tokens(cinside_info *info, uint32_t *new_buf,
                                 size_t new_max, size_t new_num,
                                 uint32_t **old_buf, size_t *old_max,
                                 size_t *old_num)
{
    if (old_buf != NULL)
        *old_buf = info->token;

    if (old_max != NULL)
        *old_max = info->max_tokens;

    if (old_num != NULL)
        *old_num = info->num_tokens;

    info->token = new_buf;
    info->max_tokens = new_max;
    info->num_tokens = new_num;
}
