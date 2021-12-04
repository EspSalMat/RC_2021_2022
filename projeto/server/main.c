#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#define DEFAULT_PORT "58054"

typedef struct {
    char *port;
    bool verbose;
} args_t;

args_t parse_args(int argc, char **argv) {
    args_t args;
    args.port = DEFAULT_PORT;
    args.verbose = false;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-v")) {
            args.verbose = true;
        } else if (!strcmp(argv[i], "-p") && i < argc - 1) {
            args.port = argv[i + 1];
            i++;
        }
    }

    return args;
}

int main(int argc, char **argv) {
    args_t args = parse_args(argc, argv);

    return 0;
}
