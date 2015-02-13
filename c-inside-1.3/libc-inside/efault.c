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

/* efault.c - fault handling code (may move into system.c in the future) */

#include <stdlib.h>         /* malloc, free */
#include <string.h>         /* memset */
#include <signal.h>         /* sigaction, sigemptyset */

#include "internal.h"

sigjmp_buf _cinside_signal_jump;
static struct sigaction _cinside_sigaction;
static void *_cinside_fault_addr;
static int _cinside_fault_reason;

static void _cinside_signal_handler(int sig_num, siginfo_t *sig_info, void *v);

int _cinside_setup_signals(cinside_info *info, void **old_handlers)
{
    struct sigaction *old_segv, *old_bus;

    /* freed in _cinside_setup_signals() or _cinside_restore_signals() */
    if ((old_segv = malloc(2 * sizeof(*old_segv))) == NULL)
        return _cinside_error(info, CINSIDE_ERR_RESOURCES, NULL);

    memset(old_segv, 0, 2 * sizeof(*old_segv));
    old_bus = old_segv + 1;

    memset(&_cinside_sigaction, 0, sizeof(_cinside_sigaction));
    _cinside_sigaction.sa_sigaction = _cinside_signal_handler;
    sigemptyset(&(_cinside_sigaction.sa_mask));
    _cinside_sigaction.sa_flags = SA_SIGINFO;

    if (sigaction(SIGSEGV, &_cinside_sigaction, old_segv) != 0)
    {
        free(old_segv);
        return _cinside_error(info, CINSIDE_ERR_GENERAL,
                              "failed to set up SIGSEGV handler");
    }

    if (sigaction(SIGBUS, &_cinside_sigaction, old_bus) != 0)
    {
        sigaction(SIGSEGV, old_segv, NULL);
        free(old_segv);
        return _cinside_error(info, CINSIDE_ERR_GENERAL,
                              "failed to set up SIGBUS handler");
    }

    *old_handlers = old_segv;
    return CINSIDE_SUCCESS;
}

static void _cinside_signal_handler(int sig_num, siginfo_t *sig_info, void *v)
{
    /* these, somewhat unfortunately, must be globals */
    _cinside_fault_addr = sig_info->si_addr;
    _cinside_fault_reason = sig_info->si_code;  /* to-do: fix by re-mapping */
    siglongjmp(_cinside_signal_jump, 1);
}

int _cinside_restore_signals(cinside_info *info, void *old_handlers)
{
    struct sigaction *old_segv, *old_bus;

    old_segv = (struct sigaction *)old_handlers;
    old_bus = old_segv + 1;

    if (sigaction(SIGBUS, old_bus, NULL) != 0)
    {
        /* don't free(old_segv)... didn't complete successfully */
        return _cinside_error(info, CINSIDE_ERR_GENERAL,
                              "failed to restore SIGBUS handler");
    }

    if (sigaction(SIGSEGV, old_segv, NULL) != 0)
    {
        /* don't free(old_segv)... didn't complete successfully */
        return _cinside_error(info, CINSIDE_ERR_GENERAL,
                              "failed to restore SIGBUS handler");
    }

    free(old_segv);
    return CINSIDE_SUCCESS;
}

int _cinside_get_fault(cinside_info *info, void **addr, int *reason)
{
    if (addr != NULL)
        *addr = _cinside_fault_addr;

    if (reason != NULL)
        *reason = _cinside_fault_reason;

    return CINSIDE_SUCCESS;
}
