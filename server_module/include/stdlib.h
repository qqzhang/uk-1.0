#ifndef _STDLIB_H_
#define _STDLIB_H_

#include <linux/types.h>

void           _exit(int);
void           abort(void);
int            atexit(void (*)(void));
double         atof(const char*);
int            atoi(const char*);
long           atol(const char*);
void*          calloc(size_t,size_t);

void           exit(int);
void           free(void*);
char*          getenv(const char*);
void*          malloc(size_t);
void           perror(const char*);
void*          realloc(void*,size_t);
double         strtod(const char*,char**);
long           strtol(const char*,char**,int);
unsigned long  strtoul(const char*,char**,int);

#endif