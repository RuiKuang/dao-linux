/*
 * linja - Stealthy Linux Debugger
 * Copyright (C) 2009-2015 Caesar Creek Software, Inc. <http://www.cc-sw.com>
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

/* syscalls.h - declarations for system call definitions */

#ifndef __SYSCALLS_H__
#define __SYSCALLS_H__

#include <unistd.h>         /* size_t */

#define SCPARAM_STR 8

typedef struct _syscall_info
{
    const char *name;
    int show_ret;
    size_t num_params;
    int param_type[6];
} syscall_info;

extern const syscall_info sc_info[];
extern const size_t num_syscalls;

#endif  /* __SYSCALLS_H__ */
