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

/* namespace.c - namespace resolution of existing global variables/functions */

#include <stddef.h>         /* NULL */

#include "internal.h"

#if HAVE_LIBDL
#include <dlfcn.h>
#endif

#if HAVE_LIBDL

int _cinside_lkup_init(cinside_info *info)
{
    if ((info->lkup_handle = dlopen(NULL, RTLD_LAZY | RTLD_GLOBAL)) == NULL)
    {
        return _cinside_error(info, CINSIDE_ERR_GENERAL,
                              "namespace initialization failed");
    }

    return CINSIDE_SUCCESS;
}

int _cinside_lkup_variable(cinside_info *info, char *name, uint32_t **addr)
{
    uint32_t *tmp_addr;

    dlerror();
    tmp_addr = dlsym(info->lkup_handle, name);
    if (dlerror() != NULL)
        return CINSIDE_ERR_NOT_FOUND;   /* variable lookup errors: silent */

    *addr = tmp_addr;
    return CINSIDE_SUCCESS;
}

int _cinside_lkup_function(cinside_info *info, char *name, cinside_fp *addr)
{
    uint32_t tmp_addr;

    if ((void *)(tmp_addr = (uint32_t)dlsym(info->lkup_handle, name)) == NULL)
    {
        /* no need to check dlerror() since we don't allow NULL functions */
        return _cinside_error(info, CINSIDE_ERR_NOT_FOUND,
                              "function '%s' not defined", name);
    }

    *addr = (cinside_fp)tmp_addr;
    return CINSIDE_SUCCESS;
}

int _cinside_lkup_load(cinside_info *info, char *name)
{
    if (dlopen(name, RTLD_LAZY | RTLD_GLOBAL) == NULL)
    {
        return _cinside_error(info, CINSIDE_ERR_NOT_FOUND,
                              "shared object '%s' not found", name);
    }

    return CINSIDE_SUCCESS;
}

int _cinside_lkup_destroy(cinside_info *info)
{
    dlclose(info->lkup_handle);
    return CINSIDE_SUCCESS;
}

#else

int _cinside_lkup_init(cinside_info *info)
{
    return CINSIDE_SUCCESS;
}

int _cinside_lkup_variable(cinside_info *info, char *name, uint32_t **addr)
{
    return CINSIDE_ERR_NOT_FOUND;   /* variable lookup errors: silent */
}

int _cinside_lkup_function(cinside_info *info, char *name, cinside_fp *addr)
{
    return _cinside_error(info, CINSIDE_ERR_NOT_FOUND,
                          "function '%s' not defined", name);
}

int _cinside_lkup_load(cinside_info *info, char *name)
{
    return _cinside_error(info, CINSIDE_ERR_CANNOT,
                          "namespace module loading not available");
}

int _cinside_lkup_destroy(cinside_info *info)
{
    return CINSIDE_SUCCESS;
}

#endif
