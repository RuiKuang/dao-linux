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

/* list.c - list (and stack) management functions */

#include <stdlib.h>         /* malloc, free */
#include <string.h>         /* memset, memcpy */

#include "internal.h"

#define CINSIDE_LIST_GROW_COUNT 1000

static int _cinside_list_check(cinside_info *info, cinside_list_segment *list,
                               size_t count);

int _cinside_list_init(cinside_info *info, cinside_list_segment **list)
{
    size_t bytes;
    cinside_list_segment *new_list;

    bytes = ((CINSIDE_LIST_GROW_COUNT * sizeof(uint32_t)) +
             sizeof(cinside_list_segment));

    /* freed in _cinside_list_destroy() */
    if ((new_list = malloc(bytes)) == NULL)
        return _cinside_error(info, CINSIDE_ERR_RESOURCES, NULL);

    memset(new_list, 0, bytes);
    new_list->cur = new_list;
    new_list->max_items = CINSIDE_LIST_GROW_COUNT;
    *list = new_list;
    return CINSIDE_SUCCESS;
}

int _cinside_list_reserve(cinside_info *info, cinside_list_segment *list,
                          size_t count, uint32_t **addr)
{
    int ret;
    cinside_list_segment *cur;
    uint32_t *vals;

    if ((ret = _cinside_list_check(info, list, count)) != CINSIDE_SUCCESS)
        return ret;

    cur = list->cur;
    vals = (uint32_t *)(cur + 1);
    *addr = &(vals[cur->num_items]);

    return CINSIDE_SUCCESS;
}

static int _cinside_list_check(cinside_info *info, cinside_list_segment *list,
                               size_t count)
{
    uint32_t new_count;
    size_t bytes;
    cinside_list_segment *cur, *new_list;

    cur = list->cur;
    if ((cur->num_items + count) > cur->max_items)
    {
        new_count = CINSIDE_LIST_GROW_COUNT;
        if (count > new_count)
            new_count = count;

        bytes = ((count * sizeof(uint32_t)) + sizeof(cinside_list_segment));

        /* freed in _cinside_list_destroy() */
        if ((new_list = malloc(bytes)) == NULL)
            return _cinside_error(info, CINSIDE_ERR_RESOURCES, NULL);

        memset(new_list, 0, bytes);
        new_list->prev = cur;
        new_list->max_items = new_count;
        cur->next = new_list;
        list->cur = new_list;
    }

    return CINSIDE_SUCCESS;
}

int _cinside_list_return(cinside_info *info, cinside_list_segment *list,
                         size_t count)
{
    int ret;
    uint32_t i;

    for (i = 0; i < count; i++)
    {
        if ((ret = _cinside_list_pop(info, list, NULL)) != CINSIDE_SUCCESS)
            return ret;
    }

    return CINSIDE_SUCCESS;
}

int _cinside_list_count(cinside_info *info, cinside_list_segment *list,
                        size_t *count)
{
    size_t ct;
    cinside_list_segment *cur;

    ct = 0;
    cur = list;
    while (cur != NULL)
    {
        ct += cur->num_items;
        cur = cur->next;
    }

    *count = ct;
    return CINSIDE_SUCCESS;
}

int _cinside_list_push(cinside_info *info, cinside_list_segment *list,
                       uint32_t val)
{
    int ret;
    cinside_list_segment *cur;
    uint32_t *vals;

    if ((ret = _cinside_list_check(info, list, 1)) != CINSIDE_SUCCESS)
        return ret;

    cur = list->cur;
    vals = (uint32_t *)(cur + 1);
    vals[cur->num_items++] = val;

    return CINSIDE_SUCCESS;
}

int _cinside_list_pop(cinside_info *info, cinside_list_segment *list,
                      uint32_t *val)
{
    cinside_list_segment *cur, *prev;
    uint32_t *vals;
    uint32_t tmp_val;

    cur = list->cur;
    while ((cur != NULL) && (cur->num_items == 0))
    {
        prev = cur->prev;
        free(cur);
        cur = prev;
        if (cur != NULL)
            cur->next = NULL;

        list->cur = cur;
    }

    if (cur == NULL)
        return _cinside_error(info, CINSIDE_ERR_GENERAL, "helper stack error");

    vals = (uint32_t *)(cur + 1);
    tmp_val = vals[--(cur->num_items)];
    if (val != NULL)
        *val = tmp_val;

    return CINSIDE_SUCCESS;
}

int _cinside_list_destroy(cinside_info *info, cinside_list_segment *list)
{
    cinside_list_segment *cur, *prev;

    cur = list->cur;
    while (cur != NULL)
    {
        prev = cur->prev;
        free(cur);
        cur = prev;
    }

    free(list);
    return CINSIDE_SUCCESS;
}

int _cinside_list_reset(cinside_info *info, cinside_list_segment *list)
{
    cinside_list_segment *cur, *prev;

    cur = list->cur;
    while (cur != list)
    {
        prev = cur->prev;
        free(cur);
        cur = prev;
    }

    list->next = NULL;
    list->cur = list;
    list->max_items = CINSIDE_LIST_GROW_COUNT;
    list->num_items = 0;
    return CINSIDE_SUCCESS;
}
