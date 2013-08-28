#ifndef _GETOPT_H_
#define _GETOPT_H_

extern char *optarg;
extern int optind, opterr, optopt;

struct option {
    const char *name;
    int         has_arg;
    int        *flag;
    int         val;
};
int getopt(int argc, char * const argv[], const char *optstring);
int getopt_long(int argc, char * const argv[],
           const char *optstring,
           const struct option *longopts, int *longindex);
           
#endif