#ifndef ARGS_H
#define ARGS_H

#define DEFAULT_PORT "58054"

typedef struct {
    char *port;
    char *ip;
} args_t;

args_t parse_args(int argc, char **argv);

#endif /* ARGS_H */