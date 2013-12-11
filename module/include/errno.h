#ifndef _UK_ERRNO_H_
#define _UK_ERRNO_H_

#include <linux/err.h>

extern int *_errno(void);
#define errno (*_errno())

#endif

