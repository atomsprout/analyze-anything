/* Fixture source that needs no C library headers, for cross targets without an SDK. */
int printf(const char *, ...);
char *strcpy(char *, const char *);
int main(int argc, char **argv) {
    char buffer[64];
    if (argc > 1) {
        strcpy(buffer, argv[1]);
        printf("%s\n", buffer);
    }
    return 0;
}
