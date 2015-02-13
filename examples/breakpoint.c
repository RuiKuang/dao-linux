#include <stdio.h>

void foo(unsigned int param) { printf("foo %X\n", param); }

int main()
{
    unsigned char opcode;

    printf("Checking for 0xCC breakpoint at foo()...\n");
    opcode = (*(unsigned char*)((unsigned long)&foo)) & 0xFF;
    if (opcode == 0xCC)
        printf("Breakpoint found - DEBUGGER DETECTED!\n");
    else
        printf("No breakpoint was found (0x%02X), ALL IS GOOD!\n", opcode);

    printf("\nFinishing up, calling foo()...\n");
    foo(0xDEADBEEF);

    printf("\nAll done!\n");
    return 0;
}
