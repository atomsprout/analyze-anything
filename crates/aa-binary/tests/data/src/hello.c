/* Fixture source: uses a stack buffer and libc string functions so that the stack
   protector and _FORTIFY_SOURCE have something to instrument. */
#include <stdio.h>
#include <string.h>

int exported_add(int a, int b) { return a + b; }

int main(int argc, char **argv) {
    char buffer[64];
    if (argc > 1) {
        strcpy(buffer, argv[1]);
        printf("%s %d\n", buffer, exported_add(argc, 2));
    }
    return 0;
}
