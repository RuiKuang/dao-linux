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

/* iterators.c - functions to iterate on filenames and words */

#include <glob.h>           /* glob, globfree */
#include <string.h>         /* memset, memcpy, strcpy, strchr */
#include <stdlib.h>         /* malloc, free */

#include "c-inside.h"

typedef struct __cinside_iterator
{
    uint32_t marker;                    /* 0x12345678 */
    uint32_t type;                      /* CINSIDE_ITER_* */
    size_t count;                       /* total number of items */
    size_t index;                       /* current index */
    size_t str_len;                     /* length of preceding string buffer */
} _cinside_iterator;

#define CINSIDE_ITER_MARKER     0x12345678

#define CINSIDE_ITER_FILES      1
#define CINSIDE_ITER_WORDS      2
#define CINSIDE_MAX_ITER        2

char *_cinside_files(char **path, size_t num_paths)
{
    size_t i, bytes, max_len;
    glob_t tmp_glob, *buf_glob;
    _cinside_iterator *iter;
    char *buf;

    memset(&tmp_glob, 0, sizeof(tmp_glob));
    for (i = 0; i < num_paths; i++)
        glob(path[i], ((i == 0) ? 0 : GLOB_APPEND), NULL, &tmp_glob);

    if (num_paths == 0)
        glob("*", 0, NULL, &tmp_glob);

    max_len = 0;
    for (i = 0; i < tmp_glob.gl_pathc; i++)
    {
        bytes = strlen(tmp_glob.gl_pathv[i]) + 1;
        if (bytes > max_len)
            max_len = bytes;
    }

    bytes = max_len + 7 + sizeof(_cinside_iterator) + sizeof(tmp_glob);
    buf = malloc(bytes);
    if (buf == NULL)
        return NULL;

    memset(buf, 0, bytes);
    iter = (_cinside_iterator *)(((uint32_t)buf + max_len + 7) & ~7);
    buf_glob = (glob_t *)(iter + 1);

    iter->marker = CINSIDE_ITER_MARKER;
    iter->type = CINSIDE_ITER_FILES;
    iter->count = tmp_glob.gl_pathc;
    iter->str_len = max_len;
    memcpy(buf_glob, &tmp_glob, sizeof(tmp_glob));
    if (iter->count > 0)
        strcpy(buf, buf_glob->gl_pathv[iter->index]);

    return buf;
}

char *_cinside_words(char *str, char *ifs)
{
    char *next, *buf, *copy_buf;
    size_t count, bytes, max_len, total_len;
    _cinside_iterator *iter;
    char **ptr;

    if ((ifs == NULL) || (*ifs == '\0'))
        ifs = " \t\n";

    next = str;
    count = 0;
    max_len = 0;
    total_len = 0;
    while (*next != '\0')
    {
        while ((*next != '\0') && (strchr(ifs, *next) != NULL))
            next++;

        if (*next == '\0')
            break;

        count++;
        bytes = 1;
        while ((*next != '\0') && (strchr(ifs, *next) == NULL))
        {
            next++;
            bytes++;
        }

        total_len += bytes;
        if (bytes > max_len)
            max_len = bytes;
    }

    bytes = max_len + 7 + sizeof(_cinside_iterator) +
            (count * sizeof(char *)) + total_len;

    buf = malloc(bytes);
    if (buf == NULL)
        return NULL;

    memset(buf, 0, bytes);
    iter = (_cinside_iterator *)(((uint32_t)buf + max_len + 7) & ~7);
    ptr = (char **)(iter + 1);
    copy_buf = (char *)((uint32_t)ptr + (count * sizeof(char *)));

    iter->marker = CINSIDE_ITER_MARKER;
    iter->type = CINSIDE_ITER_WORDS;
    iter->str_len = max_len;

    next = str;
    while (*next != '\0')
    {
        while ((*next != '\0') && (strchr(ifs, *next) != NULL))
            next++;

        if (*next == '\0')
            break;

        ptr[iter->count++] = copy_buf;
        while ((*next != '\0') && (strchr(ifs, *next) == NULL))
        {
            *(copy_buf++) = *(next++);
        }

        *(copy_buf++) = '\0';
    }

    if (iter->count > 0)
        strcpy(buf, ptr[iter->index]);

    return buf;
}

static _cinside_iterator *_cinside_get_iter(char *buf)
{
    char *next;
    _cinside_iterator *ret;

    next = buf;
    while (*next != '\0')
        next++;

    while (*next == '\0')
        next++;

    ret = (_cinside_iterator *)next;
    if ((ret->marker != CINSIDE_ITER_MARKER) || (ret->type > CINSIDE_MAX_ITER))
        return NULL;

    return ret;
}

size_t _cinside_count(char *buf)
{
    _cinside_iterator *iter;

    if ((iter = _cinside_get_iter(buf)) == NULL)
        return 0;

    return iter->count;
}

char *_cinside_next(char *buf)
{
    _cinside_iterator *iter;
    glob_t *buf_glob;
    char *src;
    char **ptr;

    if ((iter = _cinside_get_iter(buf)) == NULL)
        return NULL;

    memset(buf, 0, iter->str_len);
    if (++(iter->index) == iter->count)
        return buf;

    src = NULL;
    buf_glob = (glob_t *)(iter + 1);
    ptr = (char **)(iter + 1);

    if (iter->type == CINSIDE_ITER_FILES)
        src = buf_glob->gl_pathv[iter->index];
    else if (iter->type == CINSIDE_ITER_WORDS)
        src = ptr[iter->index];

    if (src != NULL)
        strcpy(buf, src);

    return buf;
}

int _cinside_last(char *buf)
{
    int ret;
    _cinside_iterator *iter;
    glob_t *buf_glob;

    if ((iter = _cinside_get_iter(buf)) == NULL)
        return 1;

    ret = (iter->index == iter->count);
    if (ret)
    {
        buf_glob = (glob_t *)(iter + 1);
        if (iter->type == CINSIDE_ITER_FILES)
            globfree(buf_glob);

        free(buf);
    }

    return ret;
}
