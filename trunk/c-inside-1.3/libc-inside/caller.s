# C-Inside (libc-inside) - C language interpreter library
# Copyright (C) 2008-2015  Jason Todd <jtodd1@earthlink.net>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# caller.s - assembly implementation of _cinside_caller_inner() for 32-bit x86

.section .text

# int _cinside_caller_inner(uint32_t *args, uint32_t args_size,
#                           struct timeval *tv_bp, struct timeval *tv_ap,
#                           int *p_errno, int *p_last_errno,
#                           uint32_t stack_align_offset, uint32_t gtod_fp)
# +00 saved EBP
# +04 return address
# +08 args
# +0C args_size
# +10 tv_bp
# +14 tv_ap
# +18 p_errno
# +1C p_last_errno
# +20 stack_align_offset
# +24 gtod_fp

.global _cinside_caller_inner
_cinside_caller_inner:
  push %ebp
    mov %esp, %ebp
    subl 0x20(%ebp), %esp               # pre-adjust stack ptr for alignment
    mov 0x08(%ebp), %eax                # EAX = argv
    mov 0x0C(%ebp), %ecx                # ECX = modified argc value
    cmp $0, %ecx                        # skip if no arguments
    jz 2f                               # ;
    add %ecx, %eax                      # push the last argument first (skip 0)
    shr $2, %ecx                        # number of arguments
1:                                      # loop:
    pushl (%eax)                        # ; push the current argument
    sub $4, %eax                        # ; and move backward through argv
    loop 1b                             # ;
2:                                      # done pushing arguments
    sub $8, %esp                        # gettimeofday(tv_bp, NULL);
    pushl $0                            # ;
    mov 0x10(%ebp), %eax                # ;
    push %eax                           # ;
    call *0x24(%ebp)                    # ; call through gtod_fp
    add $16, %esp                       # ; remove parameters & alignment
    # pushl $0                          # errno = 0, in case gettimeofday()
    mov 0x18(%ebp), %edx                # ; modified it and function doesn't
    movl $0, (%edx)                     # ;
    mov 0x08(%ebp), %eax                # call (argv[0], skipped above)
    call *(%eax)                        # can't trust ECX/EDX after this!
  pushl %eax                            # save return value
    mov 0x18(%ebp), %eax                # info->last_errno = errno
    mov (%eax), %eax                    # ; since gettimeofday() can change it
    mov 0x1C(%ebp), %edx                # ;
    mov %eax, (%edx)                    # ;
    sub $8, %esp                        # gettimeofday(tv_ap, NULL);
    pushl $0                            # ;
    mov 0x14(%ebp), %eax                # ;
    push %eax                           # ;
    call *0x24(%ebp)                    # ; call through gtod_fp
    add $16, %esp                       # ; remove parameters & alignment
  pop %eax                              # restore return value
    mov 0x0C(%ebp), %ecx                # clean arguments off the stack
    add %ecx, %esp                      # ;
    addl 0x20(%ebp), %esp               # un-adjust stack pointer
  pop %ebp
    ret
