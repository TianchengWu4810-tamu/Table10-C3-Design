#include <stdio.h>
#include <string.h>

void vulnerable_function(char *str) {
    char buffer[50];
    strcpy(buffer, str);
}

int main(int argc, char **argv) {
    vulnerable_function(argv[1]);
    return 0;
}
