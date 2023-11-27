#include <stdio.h>
#include <string.h>

void vulnerable_function(char *input) {
    char buffer[100];
    // Use strncpy instead of strcpy to prevent buffer overflow
    strncpy(buffer, input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0'; // Ensure null-termination
}

int main(int argc, char **argv) {
    if (argc > 1) {
        vulnerable_function(argv[1]);
    }
    return 0;
}