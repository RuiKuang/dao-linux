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

/* linja.c - main application source */

#include <stdio.h>
#include <unistd.h>         /* fork, execvp */
#include <string.h>         /* strerror */
#include <errno.h>          /* errno */
#include <sys/ptrace.h>     /* ptrace */
#include <stdlib.h>         /* exit */
#include <sys/types.h>      /* waitpid */
#include <sys/wait.h>       /* waitpid */
#include <sys/user.h>       /* user_regs_struct */
#include <asm/unistd.h>
#include <sys/prctl.h>
#include <stdarg.h>

#include "syscalls.h"
#include "c-inside.h"
#include "udis86.h"

/* whether to display system calls */
#define LOG_SYSCALLS    0

#define TSC_INCREMENT   0x100
#define MAX_STR_LEN     32
#define MAX_BREAKPOINTS 32
#define MAX_UD_CODE     1024

#define LOG_FORMAT_CLS          "\033[m\033[H\033[2J"
#define LOG_PID_FORMAT_COLOR    "\033[34;47m\033[K%5u: "
#define LOG_FORMAT_COLOR        "\033[30;47m\033[K"
#define LOG_FORMAT_ERROR        "\033[31;47m\033[K"
#define LOG_FORMAT_RESTORE      "\033[m\033[K"

#define APP_NAME        "linja"
#define VERSION_STRING  APP_NAME " v0.9"

typedef struct _bpinfo
{
    uint32_t addr;
    uint8_t orig_code[2];
    char *expr;
} bpinfo;

cinside_info *info;
pid_t pid;
bpinfo brkpts[MAX_BREAKPOINTS];
ud_t ud;
uint8_t ud_code[MAX_UD_CODE];
volatile size_t ud_offset;
static const uint16_t rdtsc_code = 0x310F;
static const uint8_t cli_code = 0xFA;

int get_syscall(char *buf, size_t len,
                struct user_regs_struct *regs);

int get_param(char *buf, size_t len, size_t *offset_ret,
              const syscall_info *sc, size_t param_num, unsigned long val);

size_t get_data(char *dest, unsigned long src, size_t n);
size_t put_data(char *src, unsigned long dest, size_t n);

void log_(pid_t pid, const char *format, ...);
int do_error(char *str);
int do_output(char *str);

void dump_state(struct user_regs_struct *regs);
void set_reg_vars(struct user_regs_struct *regs);
void get_reg_vars(struct user_regs_struct *regs);
int interact();

int set_bp(uint32_t addr, char *expr);

int disasm(uint32_t addr, uint32_t lines);
int ud_input_hook(ud_t *u);

int main(int argc, char *argv[])
{
    int status, pt_data, ret;
    struct user_regs_struct regs;
    char syscall_disp[160];
    uint8_t check_code[16];
    unsigned int tsc;
    char *msg;
    size_t i, bp_keep_idx;
    uint32_t bp_expr_result;

    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s <cmd> [arg...]\n", argv[0]);
        return 1;
    }

    for (i = 0; i < MAX_BREAKPOINTS; i++)
        brkpts[i].addr = 0xFFFFFFFF;

    if ((ret = cinside_init(&info, NULL, NULL, 0, 0)) != CINSIDE_SUCCESS)
    {
        if (cinside_get(info, CINSIDE_ID_ERROR,
                        (uint32_t *)&msg) == CINSIDE_SUCCESS)
        {
            fprintf(stderr, "%s", msg);
        }
        else
        {
            fprintf(stderr, "%s: initialization error %d\n", argv[0], ret);
        }

        return ret;
    }

    ret = cinside_set(info, CINSIDE_ID_ERROR_FUNC, (uint32_t)do_error);
    if (ret != CINSIDE_SUCCESS)
        return ret;

    ret = cinside_set(info, CINSIDE_ID_OUTPUT_FUNC, (uint32_t)do_output);
    if (ret != CINSIDE_SUCCESS)
        return ret;

    ret = cinside_set(info, CINSIDE_ID_ADD_SEMI, 1);
    if (ret != CINSIDE_SUCCESS)
        return ret;

    ret = cinside_set(info, CINSIDE_ID_GETDATA_FUNC, (uint32_t)get_data);
    if (ret != CINSIDE_SUCCESS)
        return ret;

    ret = cinside_set(info, CINSIDE_ID_PUTDATA_FUNC, (uint32_t)put_data);
    if (ret != CINSIDE_SUCCESS)
        return ret;

    ret = cinside_set(info, CINSIDE_ID_SETBP_FUNC, (uint32_t)set_bp);
    if (ret != CINSIDE_SUCCESS)
        return ret;

    ret = cinside_set(info, CINSIDE_ID_DISASM_FUNC, (uint32_t)disasm);
    if (ret != CINSIDE_SUCCESS)
        return ret;

    ret = cinside_set(info, CINSIDE_ID_ENABLE_CTRLR, 1);
    if (ret != CINSIDE_SUCCESS)
        return ret;

    ud_init(&ud);
    ud_set_mode(&ud, 32);
    ud_set_syntax(&ud, UD_SYN_INTEL);
    ud_set_input_hook(&ud, ud_input_hook);

    log_(0, LOG_FORMAT_CLS);
    log_(0, "%s\n", VERSION_STRING);
    if ((pid = fork()) == -1)
    {
        fprintf(stderr, "Could not fork: %s.\n", strerror(errno));
        return 2;
    }
    else if (pid == 0)
    {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        prctl(PR_SET_TSC, PR_TSC_SIGSEGV);
        execvp(argv[1], &(argv[1]));
        exit(errno);
    }

    waitpid(-1, &status, __WALL);
    if (WIFEXITED(status) || WIFSIGNALED(status))
    {
        log_(pid, "Failed to load %s: %s.\n", argv[1],
             strerror(WEXITSTATUS(status)));

        if (WIFSIGNALED(status))
            return 2;

        return WEXITSTATUS(status);
    }

    log_(pid, "Loaded %s successfully, PID %u.\n", argv[1], pid);
    if (interact() == CINSIDE_SUCCESS_EXIT)
        return 0;

    status = 0;
    pt_data = 0;
    tsc = 0x2B84F00D;
    bp_keep_idx = MAX_BREAKPOINTS;
    while (1)
    {
        ptrace(PTRACE_SETOPTIONS, pid, NULL,
               PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE | PTRACE_O_TRACESYSGOOD);

        ptrace(PTRACE_SYSCALL, pid, NULL, pt_data);

        pt_data = 0;
        pid = waitpid(-1, &status, __WALL);
        ptrace(PTRACE_GETREGS, pid, NULL, &regs);
        if ((bp_keep_idx < MAX_BREAKPOINTS) &&
            ((unsigned long)(regs.eip) != brkpts[bp_keep_idx].addr))
        {
#if 1
            put_data((char *)&cli_code, brkpts[bp_keep_idx].addr, 1);
#endif
            bp_keep_idx = MAX_BREAKPOINTS;
            continue;
        }

        if (WIFEXITED(status))
        {
            log_(pid, "Exited with status %d.\n", WEXITSTATUS(status));
            break;
        }

        if (WIFSIGNALED(status))
        {
            log_(pid, "Killed.\n");
            break;
        }

        if (!(WSTOPSIG(status) & 0x80))
        {
            if (WSTOPSIG(status) == SIGSEGV)
            {
                memset(check_code, 0, sizeof(check_code));
                get_data((char *)check_code, regs.eip, 2);
                if (*(uint16_t *)(check_code) == rdtsc_code)
                {
                    log_(pid, "RDTSC: simulating with 0xDEADBEEF%08X.\n", tsc);
                    regs.edx = 0xDEADBEEF;
                    regs.eax = tsc;
                    regs.eip += 2;
                    tsc += TSC_INCREMENT;
                    ptrace(PTRACE_SETREGS, pid, NULL, &regs);
                    continue;
                }

                if (*(uint8_t *)(check_code) == cli_code)
                {
                    log_(pid, "CLI");
                    for (i = 0; i < MAX_BREAKPOINTS; i++)
                    {
                        if ((unsigned long)(regs.eip) == brkpts[i].addr)
                            break;
                    }

                    if (i < MAX_BREAKPOINTS)
                    {
                        log_(0, " breakpoint at 0x%lX", regs.eip);
                        put_data((char *)&(brkpts[i].orig_code), regs.eip, 1);
                        bp_keep_idx = i;

                        bp_expr_result = 0;
                        if (brkpts[i].expr != NULL)
                        {
                            set_reg_vars(&regs);
                            ret = cinside_eval(info, brkpts[i].expr,
                                               &bp_expr_result);

                            if (ret != CINSIDE_SUCCESS)
                                bp_expr_result = 1;
                        }

                        if ((brkpts[i].expr == NULL) || bp_expr_result)
                        {
                            log_(0, ".\n");
                            if (interact() == CINSIDE_SUCCESS_EXIT)
                                break;
                        }
                        else
                        {
                            log_(0, ", condition false.\n");
                        }

#if 1
                        ptrace(PTRACE_SINGLESTEP, pid, NULL, 0);
#endif
                        continue;
                    }
                }
            }

            log_(pid, "Received signal %d, passing through.\n",
                 WSTOPSIG(status));

            pt_data = WSTOPSIG(status);
            continue;
        }

        if (regs.eax != -ENOSYS)
        {
#if LOG_SYSCALLS
            if ((regs.orig_eax == 0xFFFFFFFF) ||
                sc_info[regs.orig_eax].show_ret)
            {
                log_(pid, " ==> 0x%lX/%ld\n", regs.eax, regs.eax);
            }
#endif

            continue;
        }

        get_syscall(syscall_disp, sizeof(syscall_disp), &regs);
#if LOG_SYSCALLS
        log_(pid, "%s", syscall_disp);
#endif

        if (regs.orig_eax != __NR_ptrace)
        {
#if LOG_SYSCALLS
            log_(0, "\n");
#endif
            continue;
        }

        /* always log the interesting system calls */
#if !LOG_SYSCALLS
        log_(pid, "%s", syscall_disp);
#endif

        regs.eax = 0;
        log_(0, ": short-circuiting to return 0\n");
        regs.orig_eax = 0xFFFFFFFF;
        ptrace(PTRACE_SETREGS, pid, NULL, &regs);
    }

    return 0;
}

int get_syscall(char *buf, size_t len,
                struct user_regs_struct *regs)
{
    size_t offset;
    const syscall_info *sc;

    sc = &(sc_info[regs->orig_eax]);
    offset = snprintf(buf, len, "%s(", sc->name);
    get_param(buf, len, &offset, sc, 0, regs->ebx);
    get_param(buf, len, &offset, sc, 1, regs->ecx);
    get_param(buf, len, &offset, sc, 2, regs->edx);
    get_param(buf, len, &offset, sc, 3, regs->esi);
    get_param(buf, len, &offset, sc, 4, regs->edi);
    get_param(buf, len, &offset, sc, 5, regs->ebp);

    snprintf(buf + offset, len - offset, ")");
    return 1;
}

int get_param(char *buf, size_t len, size_t *offset_ret,
              const syscall_info *sc, size_t param_num, unsigned long val)
{
    int truncated;
    size_t offset;
    char str_buf[MAX_STR_LEN];

    if (sc->num_params <= param_num)
        return 0;

    offset = *offset_ret;
    if (param_num > 0)
        offset += snprintf(buf + offset, len - offset, ", ");

    if (offset == len)
        return 1;

    if (sc->param_type[param_num] == SCPARAM_STR)
    {
        memset(str_buf, 0, sizeof(str_buf));
        if (get_data(str_buf, val, sizeof(str_buf)) != 0)
        {
            truncated = 0;
            if (str_buf[sizeof(str_buf) - 1] != '\0')
            {
                str_buf[sizeof(str_buf) - 1] = '\0';
                if (strlen(str_buf) == (sizeof(str_buf) - 1))
                    truncated = 1;
            }

            offset += snprintf(buf + offset, len - offset, "\"%s%s\"",
                               str_buf, (truncated ? "..." : ""));
        }
        else
        {
            offset += snprintf(buf + offset, len - offset, "0x%lX", val);
        }
    }
    else
    {
        offset += snprintf(buf + offset, len - offset, "0x%lX", val);
    }

    *offset_ret = offset;
    return 1;
}

size_t get_data(char *dest, unsigned long src, size_t n)
{
    unsigned long dword;
    char *byte;
    size_t i, out_idx, offset;

    out_idx = 0;
    offset = src & 3;
    if (offset != 0)
    {
        src &= ~3;
        errno = 0;
        dword = ptrace(PTRACE_PEEKDATA, pid, src, NULL);
        if (errno != 0)
            return out_idx;

        byte = (char *)&dword + offset;
        for (i = offset; (i < 4) && (out_idx < n); i++)
            dest[out_idx++] = *(byte++);

        src += 4;
    }

    while (out_idx < n)
    {
        errno = 0;
        dword = ptrace(PTRACE_PEEKDATA, pid, src, NULL);
        if (errno != 0)
            return out_idx;

        byte = (char *)&dword;
        for (i = 0; (i < 4) && (out_idx < n); i++)
            dest[out_idx++] = *(byte++);

        src += 4;
    }

    return out_idx;
}

size_t put_data(char *src, unsigned long dest, size_t n)
{
    unsigned long dword;
    char *byte;
    size_t i, in_idx, offset;

    in_idx = 0;
    offset = dest & 3;
    if (offset != 0)
    {
        dest &= ~3;
        errno = 0;
        dword = ptrace(PTRACE_PEEKDATA, pid, dest, NULL);
        if (errno != 0)
            return in_idx;

        byte = (char *)&dword + offset;
        for (i = offset; (i < 4) && (in_idx < n); i++)
            *(byte++) = src[in_idx++];

        if (ptrace(PTRACE_POKEDATA, pid, dest, dword) != 0)
            return in_idx;

        dest += 4;
    }

    while (in_idx < n)
    {
        errno = 0;
        dword = ptrace(PTRACE_PEEKDATA, pid, dest, NULL);
        if (errno != 0)
            return in_idx;

        byte = (char *)&dword;
        for (i = 0; (i < 4) && (in_idx < n); i++)
            *(byte++) = src[in_idx++];

        if (ptrace(PTRACE_POKEDATA, pid, dest, dword) != 0)
            return in_idx;

        dest += 4;
    }

    return in_idx;
}

void log_(pid_t pid, const char *format, ...)
{
    va_list arg;

    if (pid != 0)
        printf(LOG_PID_FORMAT_COLOR, pid);

    printf(LOG_FORMAT_COLOR);

    va_start(arg, format);
    vprintf(format, arg);
    va_end(arg);
    if ((format[0] != '\0') && (format[strlen(format) - 1] == '\n'))
        printf(LOG_FORMAT_RESTORE);

    fflush(stdout);
}

int do_error(char *str)
{
    printf("%s%s: %s\n%s", LOG_FORMAT_ERROR, APP_NAME, str, LOG_FORMAT_RESTORE);
    return CINSIDE_SUCCESS;
}

int do_output(char *str)
{
    printf("%s%s", LOG_FORMAT_COLOR, str);
    if ((str[0] != '\0') && (str[strlen(str) - 1] == '\n'))
        printf(LOG_FORMAT_RESTORE);

    fflush(stdout);
    return CINSIDE_SUCCESS;
}

void dump_state(struct user_regs_struct *regs)
{
    uint32_t e = regs->eflags;

    log_(pid,
         "CS: %04lX, DS: %04lX, ES: %04lX, FS: %04lX, GS: %04lX, SS: %04lX\n",
         regs->xcs, regs->xds, regs->xes, regs->xfs, regs->xgs, regs->xss);

    log_(pid, "ESP: %08lX, EBP: %08lX, ESI: %08lX, EDI: %08lX\n",
         regs->esp, regs->ebp, regs->esi, regs->edi);

    log_(pid, "EAX: %08lX, EBX: %08lX, ECX: %08lX, EDX: %08lX\n",
         regs->eax, regs->ebx, regs->ecx, regs->edx);

    log_(pid,
         "EFLAGS: %08lX (OF=%u DF=%u TF=%u SF=%u ZF=%u AF=%u PF=%u CF=%u)\n",
         e, (e & 0x800) >> 11, (e & 0x400) >> 10, (e & 0x100) >> 8,
         (e & 0x80) >> 7, (e & 0x40) >> 6, (e & 0x10) >> 4, (e & 0x4) >> 2,
         e & 1);

    log_(pid, "EIP: %08lX:", regs->eip);
    ud_set_pc(&ud, regs->eip);
    if (get_data((char *)ud_code, regs->eip, sizeof(ud_code)) == 0)
    {
        log_(pid, " ???\n");
    }
    else
    {
        ud_offset = 0;
        ud_disassemble(&ud);
        log_(0, " %s\n", ud_insn_asm(&ud));
        info->disasm_addr = (uint8_t *)(regs->eip);
    }
}

void set_reg_vars(struct user_regs_struct *regs)
{
    char reg_buf[32];

    snprintf(reg_buf, sizeof(reg_buf), "cs = 0x%lX", regs->xcs);
    cinside_eval(info, reg_buf, NULL);
    snprintf(reg_buf, sizeof(reg_buf), "ds = 0x%lX", regs->xds);
    cinside_eval(info, reg_buf, NULL);
    snprintf(reg_buf, sizeof(reg_buf), "es = 0x%lX", regs->xes);
    cinside_eval(info, reg_buf, NULL);
    snprintf(reg_buf, sizeof(reg_buf), "fs = 0x%lX", regs->xfs);
    cinside_eval(info, reg_buf, NULL);
    snprintf(reg_buf, sizeof(reg_buf), "gs = 0x%lX", regs->xgs);
    cinside_eval(info, reg_buf, NULL);
    snprintf(reg_buf, sizeof(reg_buf), "ss = 0x%lX", regs->xss);
    cinside_eval(info, reg_buf, NULL);
    snprintf(reg_buf, sizeof(reg_buf), "eip = 0x%lX", regs->eip);
    cinside_eval(info, reg_buf, NULL);
    snprintf(reg_buf, sizeof(reg_buf), "esp = 0x%lX", regs->esp);
    cinside_eval(info, reg_buf, NULL);
    snprintf(reg_buf, sizeof(reg_buf), "ebp = 0x%lX", regs->ebp);
    cinside_eval(info, reg_buf, NULL);
    snprintf(reg_buf, sizeof(reg_buf), "esi = 0x%lX", regs->esi);
    cinside_eval(info, reg_buf, NULL);
    snprintf(reg_buf, sizeof(reg_buf), "edi = 0x%lX", regs->edi);
    cinside_eval(info, reg_buf, NULL);
    snprintf(reg_buf, sizeof(reg_buf), "eax = 0x%lX", regs->eax);
    cinside_eval(info, reg_buf, NULL);
    snprintf(reg_buf, sizeof(reg_buf), "ebx = 0x%lX", regs->ebx);
    cinside_eval(info, reg_buf, NULL);
    snprintf(reg_buf, sizeof(reg_buf), "ecx = 0x%lX", regs->ecx);
    cinside_eval(info, reg_buf, NULL);
    snprintf(reg_buf, sizeof(reg_buf), "edx = 0x%lX", regs->edx);
    cinside_eval(info, reg_buf, NULL);
    snprintf(reg_buf, sizeof(reg_buf), "eflags = 0x%lX", regs->eflags);
    cinside_eval(info, reg_buf, NULL);
}

void get_reg_vars(struct user_regs_struct *regs)
{
    cinside_eval(info, "ds", (uint32_t *)&(regs->xds));
    cinside_eval(info, "es", (uint32_t *)&(regs->xes));
    cinside_eval(info, "fs", (uint32_t *)&(regs->xfs));
    cinside_eval(info, "gs", (uint32_t *)&(regs->xgs));
    cinside_eval(info, "ss", (uint32_t *)&(regs->xss));
    cinside_eval(info, "eip", (uint32_t *)&(regs->eip));
    cinside_eval(info, "esp", (uint32_t *)&(regs->esp));
    cinside_eval(info, "ebp", (uint32_t *)&(regs->ebp));
    cinside_eval(info, "esi", (uint32_t *)&(regs->esi));
    cinside_eval(info, "edi", (uint32_t *)&(regs->edi));
    cinside_eval(info, "eax", (uint32_t *)&(regs->eax));
    cinside_eval(info, "ebx", (uint32_t *)&(regs->ebx));
    cinside_eval(info, "ecx", (uint32_t *)&(regs->ecx));
    cinside_eval(info, "edx", (uint32_t *)&(regs->edx));
    cinside_eval(info, "eflags", (uint32_t *)&(regs->eflags));
    ptrace(PTRACE_SETREGS, pid, NULL, regs);
}

int interact()
{
    int ret;
    struct user_regs_struct regs;

    ptrace(PTRACE_GETREGS, pid, NULL, &regs);
    dump_state(&regs);

    /* hack to treat all registers as variables */
    set_reg_vars(&regs);

    do
    {
        ret = cinside_loop(info, ">> ");
    } while ((ret != CINSIDE_SUCCESS_EXIT) && (ret != CINSIDE_SUCCESS_CONT));

    if (ret == CINSIDE_SUCCESS_EXIT)
    {
        log_(pid, "Terminating.\n");
        ptrace(PTRACE_KILL, pid, NULL, NULL);
    }

    /* hack to treat all registers as variables */
    get_reg_vars(&regs);

    printf(LOG_FORMAT_RESTORE);
    fflush(stdout);

    return ret;
}

int set_bp(uint32_t addr, char *expr)
{
    size_t i;
    int no_breakpoints;

    no_breakpoints = 1;
    for (i = 0; i < MAX_BREAKPOINTS; i++)
    {
        if (addr == 0xFFFFFFFF)
        {
            if (brkpts[i].addr != 0xFFFFFFFF)
            {
                no_breakpoints = 0;
                log_(0, "Break at %08X, condition: %s\n", brkpts[i].addr,
                     ((brkpts[i].expr == NULL) ? "always" : brkpts[i].expr));
            }
        }
        else if (brkpts[i].addr == addr)
        {
            brkpts[i].addr = 0xFFFFFFFF;
            if (expr == NULL)
                log_(0, "Break at %08X deleted.\n", addr);

            break;
        }
    }

    if (addr == 0xFFFFFFFF)
    {
        if (no_breakpoints)
            log_(0, "No breakpoints.\n");

        return CINSIDE_SUCCESS;
    }

    if (expr == NULL)
        return CINSIDE_SUCCESS;

    if (i >= MAX_BREAKPOINTS)
        i = 0;

    for (; i < MAX_BREAKPOINTS; i++)
    {
        if (brkpts[i].addr == 0xFFFFFFFF)
        {
            if (get_data((char *)&(brkpts[i].orig_code), addr, 2) != 2)
                return CINSIDE_ERR_CANNOT;

            if (put_data((char *)&cli_code, addr, 1) != 1)
                return CINSIDE_ERR_CANNOT;

            brkpts[i].addr = addr;
            brkpts[i].expr = expr;
            break;
        }
    }

    return 0;
}

int disasm(uint32_t addr, uint32_t lines)
{
    size_t i;
    char *hex1, *hex2;
    char c;

    ud_set_pc(&ud, addr);
    if (get_data((char *)ud_code, addr, sizeof(ud_code)) != sizeof(ud_code))
        return 0;

    ud_offset = 0;
    for (i = 0; i < lines; i++)
    {
        ud_disassemble(&ud);
        log_(0, "%08X: ", ud_insn_off(&ud));
        hex1 = ud_insn_hex(&ud);
        hex2 = hex1 + 16;
        c = hex1[16];
        hex1[16] = 0;
        log_(0, "%-16s %-24s", hex1, ud_insn_asm(&ud));
        hex1[16] = c;
        if (strlen(hex1) > 16)
        {
            log_(0, "\n");
            log_(0, "%15s -", "");
            log_(0, "%-16s", hex2);
        }

        log_(0, "\n");
    }

    return ud_offset;
}

int ud_input_hook(ud_t *u)
{
    (void)u;
    return ud_code[ud_offset++];
}
