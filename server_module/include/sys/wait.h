#ifndef _WAIT_H_
#define _WAIT_H_

#define WNOHANG		0x00000001
#define WUNTRACED	0x00000002
#define WSTOPPED	WUNTRACED
#define WEXITED		0x00000004
#define WCONTINUED	0x00000008
#define WNOWAIT		0x01000000	/* Don't reap, just poll status.  */

#define	WEXITSTATUS(status)	(((status) & 0xff00) >> 8)

/* If WIFSIGNALED(STATUS), the terminating signal.  */
#define	WTERMSIG(status)	((status) & 0x7f)

/* If WIFSTOPPED(STATUS), the signal that stopped the child.  */
#define	WSTOPSIG(status)	WEXITSTATUS(status)

/* Nonzero if STATUS indicates normal termination.  */
#define	WIFEXITED(status)	(WTERMSIG(status) == 0)

/* Nonzero if STATUS indicates termination by a signal.  */
#define WIFSIGNALED(status) \
  (((signed char) (((status) & 0x7f) + 1) >> 1) > 0)

/* Nonzero if STATUS indicates the child is stopped.  */
#define	WIFSTOPPED(status)	(((status) & 0xff) == 0x7f)

#endif