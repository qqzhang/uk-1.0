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
void           perror(const char*);
double         strtod(const char*,char**);
long           strtol(const char*,char**,int);
unsigned long  strtoul(const char*,char**,int);

#ifdef MEM_LEAK_CHECK
void *_malloc_atomic(size_t size, const char *func, const char *filename, int lineno);
void *_malloc(size_t size, const char *func, const char *filename, int lineno);
void *_calloc(size_t nmemb, size_t size, const char *func, const char *filename, int lineno);
void _free(void *objp);
void *_realloc_atomic(void *ptr, size_t new_size, const char *func, const char* filename, int lineno);
void *_realloc(void *ptr, size_t new_size, const char *func, const char* filename, int lineno);

#define malloc(size) _malloc((size), __func__, __FILE__, __LINE__ )
#define calloc(nmemb, size) _calloc((nmemb), (size), __func__, __FILE__, __LINE__ )
#define malloc_atomic(size) _malloc_atomic((size), __func__, __FILE__, __LINE__ )
#define realloc(ptr, new_size) _realloc((ptr), (new_size), __func__, __FILE__, __LINE__ )
#define realloc_atomic(ptr, new_size) _realloc_atomic((ptr), (new_size), __func__, __FILE__, __LINE__ )
#define free(ptr) _free((ptr))

#else

void*          malloc(size_t);
void*          malloc_atomic(size_t size);
void*          realloc(void*,size_t);
void*          realloc_atomic(void*,size_t);

#endif

#endif
