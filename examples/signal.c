#include <stdio.h>
#include <signal.h>

static volatile int traced = 1;
void sig_handler(int signo) { (void)signo; traced = 0; }

void test_trap()
{
    __asm__ __volatile__ ( "int3\n\t");
}

int main()
{
    signal(SIGTRAP, sig_handler);
    printf("Causing SIGTRAP...\n");
    test_trap();
    if (traced)
        printf("Signal handler did not run - DEBUGGER DETECTED!\n");
    else
        printf("The signal was NOT interfered with, ALL IS GOOD!\n");

    printf("\nAll done!\n");
    return 0;
}
