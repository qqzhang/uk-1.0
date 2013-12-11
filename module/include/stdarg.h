#ifndef UK_STDARG_H
#define UK_STDARG_H

#define _WIN32_WINNT 0x0501

#ifndef WINE_STRICT_PROTOTYPES
#define WINE_STRICT_PROTOTYPES
#endif

typedef char*  va_list;

#define _INTSIZEOF(n)   ( (sizeof(n) + sizeof(int) - 1) & ~(sizeof(int) - 1) )
#define va_start(ap,v)  ( ap = (va_list)&v + _INTSIZEOF(v) )
#define va_arg(ap,t)    ( *(t *)((ap += _INTSIZEOF(t)) - _INTSIZEOF(t)) )
#define va_end(ap)      ( ap = (va_list)0 )

#endif
