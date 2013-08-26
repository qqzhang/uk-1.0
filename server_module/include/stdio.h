#ifndef _STDIO_H_
#define _STDIO_H_

#include <linux/types.h>
#include "stdarg.h"

#define _IOREAD          0x0001
#define _IOWRT           0x0002
#define _IOMYBUF         0x0008
#define _IOEOF           0x0010
#define _IOERR           0x0020
#define _IOSTRG          0x0040
#define _IORW            0x0080

#define STDIN_FILENO  0
#define STDOUT_FILENO 1
#define STDERR_FILENO 2

#define _IOFBF    0x0000
#define _IONBF    0x0004
#define _IOLBF    0x0040

#define EOF       (-1)
#define FILENAME_MAX 260
#define TMP_MAX   0x7fff
#define FOPEN_MAX 20
#define L_tmpnam  260

#define BUFSIZ    512

#ifndef SEEK_SET
#define SEEK_SET  0
#define SEEK_CUR  1
#define SEEK_END  2
#endif

typedef struct _iobuf
{
  char* _ptr;
  int   _cnt;
  char* _base;
  int   _flag;
  int   _file;
  int   _charbuf;
  int   _bufsiz;
  char* _tmpfname;
} FILE;


FILE*  __p__iob(void);
#define _iob (__p__iob())

#define stdin              (_iob+STDIN_FILENO)
#define stdout             (_iob+STDOUT_FILENO)
#define stderr             (_iob+STDERR_FILENO)


void    clearerr(FILE*);
int     fclose(FILE*);
int     feof(FILE*);
int     ferror(FILE*);
int     fflush(FILE*);
int     fgetc(FILE*);
char*   fgets(char*,int,FILE*);
FILE*   fopen(const char*,const char*);
FILE *  fopen(const char *path, const char *mode);
FILE *  fdopen(int fd, const char *mode);

int     fprintf(FILE*,const char*,...);
int     fputc(int,FILE*);
int     fputs(const char*,FILE*);
size_t  fread(void*,size_t,size_t,FILE*);
FILE*   freopen(const char*,const char*,FILE*);
int     fscanf(FILE*,const char*,...);
int     fscanf_s(FILE*,const char*,...);
int     fseek(FILE*,long,int);
long    ftell(FILE*);
size_t  fwrite(const void*,size_t,size_t,FILE*);
int     getc(FILE*);
int     getchar(void);
char*   gets(char*);
void    perror(const char*);
int     printf(const char*,...);
int     putc(int,FILE*);
int     putchar(int);
int     puts(const char*);
int     rename(const char*,const char*);
int     scanf(const char*,...);
void    setbuf(FILE*,char*);
int     setvbuf(FILE*,char*,int,size_t);
int     sprintf(char*,const char*,...);
int     sscanf(const char*,const char*,...);
int     vfprintf(FILE*,const char*,va_list);
int     vprintf(const char*,va_list);
int     vsprintf(char*,const char*,va_list);

#endif