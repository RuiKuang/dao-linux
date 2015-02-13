#include <stdio.h>
#include <sys/ptrace.h>

int main()
{
    printf("Requesting to be traced...\n");
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) < 0)
        printf("ptrace() failed - DEBUGGER DETECTED!\n");
    else
        printf("It looks like I'm not being traced, ALL IS GOOD!\n");

    printf("\nAll done!\n");
    return 0;
}
