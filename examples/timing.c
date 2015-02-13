#include <stdio.h>
#include <signal.h>     /* sigaction */
#include <string.h>     /* memset */
#include <unistd.h>
#include <ucontext.h>

volatile unsigned int t0_tsc_lo;

#define MAX_TSC_DIFF    0xF00000
#define RDTSC(_l) \
    do                          \
    {                           \
        __asm__ __volatile__ (  \
            " rdtsc\n"          \
            " mov %%eax, %0\n"  \
            : "=m" (_l)         \
            :                   \
            : "eax", "edx"      \
        );                      \
    } while (0)

void sigsegv(int signum, siginfo_t *info, void *ctxt);

int main(void)
{
    struct sigaction segv, oldsegv;

    memset(&oldsegv, 0, sizeof(oldsegv));
    segv.sa_flags = SA_SIGINFO;
    segv.sa_sigaction = sigsegv;

    if (sigaction(SIGSEGV, &segv, &oldsegv) < 0)
    {
        perror("Couldn't install signal handler");
        return 1;
    }

    printf("Reading the timestamp counter for the 1st time...\n");
    RDTSC(t0_tsc_lo);

    printf("Forcing a crash...\n");
    *(int *)0 = 0;

    printf("I'm still alive, ALL IS GOOD!\n");
    return 0;
}

#define SUBHACKME_MSG1 "I've 'crashed'...\nReading the timestamp counter for the 2nd time...\n"
#define SUBHACKME_MSG2 "The crash took too long, DEBUGGER DETECTED!\n"
#define SUBHACKME_MSG3 "Everything seems fine... going back to what I was doing...\n"

void sigsegv(int signum, siginfo_t *info, void *ctxt)
{
    ucontext_t *uc = (ucontext_t *)ctxt;
    unsigned int t1_tsc_lo;

    (void)info;

    write(STDOUT_FILENO, SUBHACKME_MSG1, strlen(SUBHACKME_MSG1));
    RDTSC(t1_tsc_lo);
    if (t1_tsc_lo - t0_tsc_lo > MAX_TSC_DIFF)
    {
        write(STDOUT_FILENO, SUBHACKME_MSG2, strlen(SUBHACKME_MSG2));
        t1_tsc_lo /= (signum - SIGSEGV);
    }
    else
    {
        write(STDOUT_FILENO, SUBHACKME_MSG3, strlen(SUBHACKME_MSG3));
        uc->uc_mcontext.gregs[REG_EIP] += 6;
    }
}
