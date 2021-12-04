#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#define DEFAULT_PORT "58054"
#define MAX_IP_LEN 128

typedef struct {
    char *port;
    char ip[MAX_IP_LEN];
} args_t;

args_t parse_args(int argc, char **argv) {
    args_t args;
    args.port = DEFAULT_PORT;

    if (gethostname(args.ip, MAX_IP_LEN) < 0)
        fprintf(stderr, "error: %s\n", strerror(errno));

    for (int i = 1; i < argc - 1; i += 2) {
        if (!strcmp(argv[i], "-n")) {
            strncpy(args.ip, argv[i + 1], MAX_IP_LEN);
        } else if (!strcmp(argv[i], "-p")) {
            args.port = argv[i + 1];
        }
    }

    return args;
}

int main(int argc, char **argv) {
    args_t args = parse_args(argc, argv);
    
    return 0;
}
