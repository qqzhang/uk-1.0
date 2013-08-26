#ifndef _ASSERT_H_
#define _ASSERT_H_

#undef assert
#define assert(_expr) ((void)0)

extern int*  _errno(void);
#define errno        (*_errno())

#endif
