#ifndef _UK_ASSERT_H_
#define _UK_ASSERT_H_

#define NDEBUG

#undef assert

#ifdef NDEBUG
#define assert(_expr) ((void)0)
#else
extern void _assert(const char *, const char *, unsigned int);
#define assert(_expr) (void)((!!(_expr)) || (_assert(#_expr, __FILE__, __LINE__), 0))
#endif

#endif
