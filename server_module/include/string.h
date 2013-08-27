#ifndef _STRING_H_
#define _STRING_H_

#include <linux/types.h>

void*    memchr(const void*,int,size_t);
int      memcmp(const void*,const void*,size_t);
void*    memcpy(void*,const void*,size_t);
int  memcpy_s(void*,size_t,const void*,size_t);
void*    memset(void*,int,size_t);

void*    memmove(void*,const void*,size_t);
int  memmove_s(void*,size_t,const void*,size_t);
char*    strcat(char*,const char*);
int  strcat_s(char*,size_t,const char*);
char*    strchr(const char*,int);
int      strcmp(const char*,const char*);
int      strcoll(const char*,const char*);
char*    strcpy(char*,const char*);
int  strcpy_s(char*,size_t,const char*);
size_t   strcspn(const char*,const char*);
char*    strerror(int);
size_t   strlen(const char*);
char*    strncat(char*,const char*,size_t);
int  strncat_s(char*,size_t,const char*,size_t);
int      strncmp(const char*,const char*,size_t);
char*    strncpy(char*,const char*,size_t);
int  strncpy_s(char*,size_t,const char*,size_t);
size_t   strnlen(const char*,size_t);
char*    strpbrk(const char*,const char*);
char*    strrchr(const char*,int);
size_t   strspn(const char*,const char*);
char*    strstr(const char*,const char*);
char*    strtok(char*,const char*);
char*    strtok_s(char*,const char*,char**);
size_t   strxfrm(char*,const char*,size_t);

int strcasecmp(const char* s1, const char* s2);
int strcmpi(const char* s1, const char* s2);
char* strdup(const char* buf);
int stricmp(const char* s1, const char* s2);
int stricoll(const char* s1, const char* s2) ;
char* strlwr(char* str) ;
int strncasecmp(const char *str1, const char *str2, size_t n);
int strnicmp(const char* s1, const char* s2, size_t n);
char* strnset(char* str, int value, unsigned int len);
char* strrev(char* str);
char* strset(char* str, int value);
char* strupr(char* str);

#endif