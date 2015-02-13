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

/* parse.c - functions for tokenizing and working with tokens */

#include <stdlib.h>         /* malloc, free, strtoul */
#include <string.h>         /* memset, memcpy, strlen, strchr */

#include "language.h"

static const cinside_token_def _cinside_symbol[] = CINSIDE_SYMBOLS;
static const uint32_t _cinside_value_end[] = CINSIDE_VALUE_END;
static const char *_cinside_valid_token_separators = CINSIDE_SEPARATORS;

/* many of these will be handled in future versions of libc-inside */
static const char *_cinside_reserved_keyword[] =
{
    "auto", "break", "case", "char", "const", "continue", "default", "do",
    "double", "else", "enum", "extern", "float", "for", "goto", "if", "int",
    "long", "register", "return", "short", "signed", "sizeof", "static",
    "struct", "switch", "typedef", "union", "unsigned", "void", "volatile",
    "while"
};

#define CINSIDE_NUM_KEYWORDS \
    (sizeof(_cinside_reserved_keyword) / sizeof(char *))

/* tokenize cmd into info->token, do not modify anything in *cmd */
/* returns CINSIDE_PARTIAL if in the middle of a slash-star comment */
int _cinside_tokenize(cinside_info *info, char *cmd)
{
    int ret;
    size_t i, j, len, prev_len, new_max_tokens, level;
    char c;
    char *next, *tmp_str;
    _cinside_string_hdr *new_str, *prev_str, *name_str;
    uint32_t *new_tokens;
    const cinside_token_def *sym;
    uint32_t token, token_arg, match;

    next = cmd;
    skip_wspace(next);
    if (info->flags & CINSIDE_FLAG_PARTIAL)
    {
        if (info->flags & CINSIDE_FLAG_COMMENT)
        {
            while ((c = *next) != '\0')
            {
                next++;
                if ((c == '*') && (*next == '/'))
                {
                    next++;
                    break;
                }
            }

            if (c == '\0')
            {
                info->flags |= CINSIDE_FLAG_COMMENT;
                return CINSIDE_PARTIAL;
            }
        }
    }
    else
    {
        info->num_tokens = 0;
        ret = _cinside_list_reset(info, info->match_stack);
        if (ret != CINSIDE_SUCCESS)
            return ret;
    }

    ret = _cinside_list_count(info, info->match_stack, &level);
    if (ret != CINSIDE_SUCCESS)
        return ret;

    while ((*next != '\0') || (info->flags & CINSIDE_FLAG_ADD_SEMI))
    {
        if ((info->num_tokens + 2) >= info->max_tokens)
        {
            new_max_tokens = info->max_tokens << 1;

            /*
             * Freed in _cinside_tokenize(), _cinside_parenthesize(), or
             * _cinside_destroy().
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

        if ((*next == '\0') && (info->flags & CINSIDE_FLAG_ADD_SEMI))
        {
            info->token[info->num_tokens++] = CINSIDE_TOKEN_SEMICOLON;
            info->token[info->num_tokens++] = 0;
            break;
        }

        skip_wspace(next);
        c = *next;
        if ((c >= '0') && (c <= '9'))
        {
            info->token[info->num_tokens++] = CINSIDE_TOKEN_INT;
            info->token[info->num_tokens++] = strtoul(next, &tmp_str, 0);
            CINSIDE_DEBUG("int: 0x%08X/%d\n",
                          info->token[info->num_tokens - 1],
                          info->token[info->num_tokens - 1]);

            next = tmp_str;
        }
        else if (c == '"')
        {
            next++;
            tmp_str = next;
            len = 0;
            while ((*next != '"') ||
                   ((*(next - 1) == '\\') && (*(next - 2) != '\\')))
            {
                if (*next == '\0')
                {
                    return _cinside_error(info, CINSIDE_ERR_SYNTAX,
                                          "missing '\"' at end of string literal");
                }

                next++;
                len++;
            }

            next++;
            ret = _cinside_string(info, tmp_str, len, CINSIDE_STRING_LITERAL,
                                  &new_str);

            if (ret != CINSIDE_SUCCESS)
                return ret;

            if (info->token[info->num_tokens - 2] == CINSIDE_TOKEN_STRING)
            {
                prev_str = (_cinside_string_hdr *)(info->token[info->num_tokens - 1]);
                prev_len = prev_str->len;

                /* freed in _cinside_tokenize() */
                if ((tmp_str = malloc(prev_len + new_str->len + 1)) == NULL)
                    return _cinside_error(info, CINSIDE_ERR_RESOURCES, NULL);

                memcpy(tmp_str, prev_str->str, prev_len);
                memcpy(tmp_str + prev_len, new_str->str, new_str->len);
                tmp_str[prev_len + new_str->len] = '\0';

                ret = _cinside_string(info, tmp_str, prev_len + new_str->len,
                                      CINSIDE_STRING_LITERAL | CINSIDE_STRING_NOESC,
                                      &new_str);

                free(tmp_str);
                if (ret != CINSIDE_SUCCESS)
                    return ret;

                /*
                 * Never free old strings, since there's no way to keep track
                 * of all references.
                 */
                info->token[info->num_tokens - 1] = (uint32_t)new_str;
                CINSIDE_DEBUG("multi-part string literal (%u bytes)\n",
                              new_str->len);
            }
            else
            {
                info->token[info->num_tokens++] = CINSIDE_TOKEN_STRING;
                info->token[info->num_tokens++] = (uint32_t)new_str;
                CINSIDE_DEBUG("string literal (%u bytes)\n", new_str->len);
            }
        }
        else if (c == '\'')
        {
            next++;
            c = *next;
            if (c == '\\')
            {
                len = 2;
                if (next[2] != '\'')
                {
                    len++;
                    if (next[3] != '\'')
                        len++;
                }

                if (next[len] == '\'')
                {
                    ret = _cinside_unescape_char(info, next, len, &c);
                    if (ret != CINSIDE_SUCCESS)
                        return ret;
                }

                next += (len - 1);
            }

            next++;
            if ((*next != '\'') || (*(next - 1) == '\0'))
            {
                return _cinside_error(info, CINSIDE_ERR_SYNTAX,
                                      "invalid character literal");
            }

            next++;
            info->token[info->num_tokens++] = CINSIDE_TOKEN_INT; /* char=int */
            info->token[info->num_tokens++] = c;
            CINSIDE_DEBUG("char: 0x%X\n", c);
        }
        else if (((c >= 'a') && (c <= 'z')) || ((c >= 'A') && (c <= 'Z')) ||
                 (c == '_'))
        {
            tmp_str = next;
            next++;
            len = 1;
            while ((((c = *next) >= 'a') && (c <= 'z')) ||
                   ((c >= 'A') && (c <= 'Z')) ||
                   ((c >= '0') && (c <= '9')) || (c == '_'))
            {
                next++;
                len++;
            }

            ret = _cinside_string(info, tmp_str, len, 0, &name_str);
            if (ret != CINSIDE_SUCCESS)
                return ret;

            token = CINSIDE_TOKEN_NAME;
            for (i = 0; i < CINSIDE_NUM_KEYWORDS; i++)
            {
                if (strcmp(name_str->str, _cinside_reserved_keyword[i]) == 0)
                {
                    token = CINSIDE_TOKEN_KEYWORD;
                    break;
                }
            }

            info->token[info->num_tokens++] = token;
            info->token[info->num_tokens++] = (uint32_t)name_str->str;
            CINSIDE_DEBUG("%s: '%s'\n",
                          ((token == CINSIDE_TOKEN_NAME) ? "name" : "keyword"),
                          name_str->str);
        }
        else if (((c == '$') || (c == '/')) &&
                 (*(next + 1) >= 'a') && (*(next + 1) <= 'z'))
        {
            next++;
            tmp_str = next;
            len = 0;
            while ((((c = *next) >= 'a') && (c <= 'z')) ||
                   ((c >= 'A') && (c <= 'Z')) ||
                   ((c >= '0') && (c <= '9')) || (c == '_'))
            {
                next++;
                len++;
            }

            ret = _cinside_string(info, tmp_str, len, 0, &name_str);
            if (ret != CINSIDE_SUCCESS)
                return ret;

            info->token[info->num_tokens++] = CINSIDE_TOKEN_BUILTIN;
            info->token[info->num_tokens++] = (uint32_t)name_str->str;
            CINSIDE_DEBUG("built-in: '%s'\n", name_str->str);
        }
        else if ((c == '/') && (*(next + 1) == '*'))
        {
            CINSIDE_DEBUG("/* comment */\n");
            next += 2;
            while ((c = *next) != '\0')
            {
                next++;
                if ((c == '*') && (*next == '/'))
                {
                    next++;
                    break;
                }
            }

            if (c == '\0')
            {
                info->flags |= CINSIDE_FLAG_COMMENT;
                return CINSIDE_PARTIAL;
            }
        }
        else if ((c == '/') && (*(next + 1) == '/'))
        {
            CINSIDE_DEBUG("// comment\n");
            while ((*next != '\0') && (*next != '\n'))
                next++;
        }

        c = *(next++);
        if (c == '\0')
        {
            next--;
            continue;
        }

        if (strchr(_cinside_valid_token_separators, c) == NULL)
        {
            return _cinside_error(info, CINSIDE_ERR_SYNTAX,
                                  "unexpected character '%c'", c);
        }

        if ((c == ' ') || (c == '\t') || (c == '\n') || (c == '\r') ||
            ((c == '\\') && ((*next == '\n') || (*next == '\0'))))
        {
            skip_wspace(next);
        }
        else if ((c == '/') && ((*next == '*') || (*next == '/')))
        {
            /* adjacent comment */
            next--;         /* back up so the comment is caught on next iter */
        }
        else
        {
            for (i = 0; i < CINSIDE_NUM_SYMBOLS; i++)
            {
                sym = &(_cinside_symbol[i]);
                if ((c == sym->ch1) &&
                    (((*next != 0) && (*next == sym->ch2) &&
                      ((*(next + 1) == sym->ch3) || (sym->ch3 == 0))) ||
                     (sym->ch2 == 0)))
                {
                    if (sym->flags & CINSIDE_AFTER_VALUE)
                    {
                        if (info->num_tokens < 2)
                            continue;

                        for (j = 0; j < CINSIDE_NUM_VALUE_END; j++)
                        {
                            if (info->token[info->num_tokens - 2] == _cinside_value_end[j])
                                break;
                        }

                        if (j == CINSIDE_NUM_VALUE_END)
                            continue;
                    }

                    if (sym->ch2 != 0)
                        next++;

                    if (sym->ch3 != 0)
                        next++;

                    token = sym->token;
                    token_arg = 0;
                    if ((token == CINSIDE_TOKEN_LPAREN) ||
                        (token == CINSIDE_TOKEN_LBRACE) ||
                        (token == CINSIDE_TOKEN_LBRACKET) ||
                        (token == CINSIDE_TOKEN_QUESTION))
                    {
                        /* NOTE: hard-coded ternary above (_QUESTION) */
                        level++;
                        ret = _cinside_list_push(info, info->match_stack,
                                                 (uint32_t)(info->num_tokens));

                        if (ret != CINSIDE_SUCCESS)
                            return ret;
                    }
                    else if ((token == CINSIDE_TOKEN_RPAREN) ||
                             (token == CINSIDE_TOKEN_RBRACE) ||
                             (token == CINSIDE_TOKEN_RBRACKET) ||
                             (token == CINSIDE_TOKEN_COLON))
                    {
                        /* NOTE: hard-coded ternary above (_COLON) */
                        if (level == 0)
                        {
                            return _cinside_error(info, CINSIDE_ERR_SYNTAX,
                                                  "unmatched )/}/]/:");
                        }

                        ret = _cinside_list_pop(info, info->match_stack,
                                                (uint32_t *)&j);

                        if (ret != CINSIDE_SUCCESS)
                            return ret;

                        token_arg = (level << 24) | (info->num_tokens - j);
                        level--;
                        info->token[j + 1] = token_arg;
                        match = info->token[j];
                        if (((token == CINSIDE_TOKEN_RPAREN) &&
                             (match != CINSIDE_TOKEN_LPAREN)) ||
                            ((token == CINSIDE_TOKEN_RBRACE) &&
                             (match != CINSIDE_TOKEN_LBRACE)) ||
                            ((token == CINSIDE_TOKEN_RBRACKET) &&
                             (match != CINSIDE_TOKEN_LBRACKET)) ||
                            ((token == CINSIDE_TOKEN_COLON) &&
                             (match != CINSIDE_TOKEN_QUESTION)))
                        {
                            /* hard-coded ternary above (_COLON, _QUESTION) */
                            return _cinside_error(info, CINSIDE_ERR_SYNTAX,
                                                  "mismatched ()/{}/[]/?:");
                        }
                    }

                    CINSIDE_DEBUG("token: 0x%X\n", token);
                    info->token[info->num_tokens++] = token;
                    info->token[info->num_tokens++] = token_arg;
                    break;
                }
            }

            if (i == CINSIDE_NUM_SYMBOLS)
            {
                return _cinside_error(info, CINSIDE_ERR_SYNTAX,
                                      "unexpected character '%c'", c);
            }
        }
    }

    IF_CINSIDE_DEBUG()
    {
        CINSIDE_DEBUG("Tokenizing succeeded with %u tokens (%u token pairs):\n",
                      info->num_tokens, info->num_tokens / 2);

        for (i = 0; i < info->num_tokens; i += 2)
            _cinside_dump_token(info, info->token[i], i);

        CINSIDE_DEBUG("\n");
    }

    if (level > 0)
        return CINSIDE_PARTIAL;

    return CINSIDE_SUCCESS;
}

int _cinside_dump_tokens(cinside_info *info, size_t first_token,
                         size_t last_token)
{
    int ret;
    size_t i;

    if (info->num_tokens == 0)
        return CINSIDE_NOP;

    for (i = first_token; i <= last_token; i += 2)
    {
        ret = _cinside_dump_token(info, info->token[i], i);
        if (ret != CINSIDE_SUCCESS)
            return _cinside_error(info, ret, NULL);     /* was silent error */
    }

    _cinside_output(info, "%s\n",
                    ((first_token == last_token) ? "(no tokens)" : ""));

    return CINSIDE_SUCCESS;
}

int _cinside_dump_token(cinside_info *info, uint32_t token, size_t idx)
{
    int ret;
    const cinside_token_def *sym;
    _cinside_string_hdr *hdr;

    if (token == CINSIDE_TOKEN_DATA)
    {
        _cinside_output(info, " eval:0x%X", info->token[idx + 1]);
    }
    else if (token == CINSIDE_TOKEN_INT)
    {
        _cinside_output(info, " 0x%X", info->token[idx + 1]);
    }
    else if (token == CINSIDE_TOKEN_STRING)
    {
        hdr = (_cinside_string_hdr *)(info->token[idx + 1]);
        _cinside_output(info, " \"%s\"", hdr->str);
    }
    else if ((token == CINSIDE_TOKEN_NAME) || (token == CINSIDE_TOKEN_KEYWORD))
    {
        _cinside_output(info, " %s", (char *)(info->token[idx + 1]));
    }
    else if (token == CINSIDE_TOKEN_BUILTIN)
    {
        _cinside_output(info, " $%s", (char *)(info->token[idx + 1]));
    }
    else if (token == CINSIDE_TOKEN_NONE)
    {
        _cinside_output(info, " empty");
    }
    else
    {
        ret = _cinside_get_token_def(info, token, &sym);
        if (ret != CINSIDE_SUCCESS)
            return ret;                             /* NOTE: silent error */

        _cinside_output(info, " %c", sym->ch1);
        if (sym->ch2 != 0)
            _cinside_output(info, "%c", sym->ch2);

        if (sym->ch3 != 0)
            _cinside_output(info, "%c", sym->ch3);
    }

    return CINSIDE_SUCCESS;
}

int _cinside_get_token_def(cinside_info *info, uint32_t cur,
                           const cinside_token_def **sym)
{
    size_t j;

    for (j = 0; j < CINSIDE_NUM_SYMBOLS; j++)
    {
        if (cur == _cinside_symbol[j].token)
            break;
    }

    if (j == CINSIDE_NUM_SYMBOLS)
        return CINSIDE_ERR_NOT_FOUND;               /* NOTE: silent error */

    if (sym != NULL)
        *sym = &(_cinside_symbol[j]);

    return CINSIDE_SUCCESS;
}
