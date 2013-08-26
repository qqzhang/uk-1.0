#ifndef _UK_LIB_H
#define _UK_LIB_H

#include <linux/types.h>
#include <linux/major.h>
#include "stdarg.h"
#include "sys/poll.h"
#include "sys/epoll.h"
#include "sys/socket.h"
#include "sys/ptrace.h"
#include "sys/time.h"
#include "sys/sysctl.h"


/*typedef*/
typedef void __signalfn_t(int);
typedef __signalfn_t* __sighandler_t;

/*for major*/
unsigned int gnu_dev_major (unsigned long long int dev);
unsigned int gnu_dev_minor (unsigned long long int dev);
unsigned long long int gnu_dev_makedev (unsigned int major, unsigned int minor);

#define major(dev) gnu_dev_major (dev)
#define minor(dev) gnu_dev_minor (dev)
#define makedev(maj, min) gnu_dev_makedev (maj, min)

/*struct define*/

typedef unsigned long sigset_t;
typedef unsigned int socklen_t;

#define __fsid_t		struct { int __val[2]; }
typedef unsigned long int __fsblkcnt_t;
struct statfs
  {
    unsigned int f_type;
    unsigned int f_bsize;
    __fsblkcnt_t f_blocks;
    __fsblkcnt_t f_bfree;
    __fsblkcnt_t f_bavail;
    __fsblkcnt_t f_files;
    __fsblkcnt_t f_ffree;
    __fsid_t f_fsid;
    unsigned int f_namelen;
    unsigned int f_spare[6];
  };
  
  struct flock
  {
    short int l_type;	/* Type of lock: F_RDLCK, F_WRLCK, or F_UNLCK.  */
    short int l_whence;	/* Where `l_start' is relative to (like `lseek').  */
    off_t l_start;	/* Offset where the lock begins.  */
    off_t l_len;	/* Size of the locked area; zero means until EOF.  */
    pid_t l_pid;	/* Process holding the lock.  */
  };

typedef union sigval
  {
    int sival_int;
    void *sival_ptr;
  } sigval_t;

#define __SI_MAX_SIZE     128
#define __SI_PAD_SIZE     ((__SI_MAX_SIZE / sizeof (int)) - 3)

#define __pid_t int 
#define __uid_t int 
#define __clock_t int 

typedef struct siginfo
  {
    int si_signo;		/* Signal number.  */
    int si_errno;		/* If non-zero, an errno value associated with
				   this signal, as defined in <errno.h>.  */
    int si_code;		/* Signal code.  */

    union
      {
	int _pad[__SI_PAD_SIZE];

	 /* kill().  */
	struct
	  {
	    __pid_t si_pid;	/* Sending process ID.  */
	    __uid_t si_uid;	/* Real user ID of sending process.  */
	  } _kill;

	/* POSIX.1b timers.  */
	struct
	  {
	    int si_tid;		/* Timer ID.  */
	    int si_overrun;	/* Overrun count.  */
	    sigval_t si_sigval;	/* Signal value.  */
	  } _timer;

	/* POSIX.1b signals.  */
	struct
	  {
	    __pid_t si_pid;	/* Sending process ID.  */
	    __uid_t si_uid;	/* Real user ID of sending process.  */
	    sigval_t si_sigval;	/* Signal value.  */
	  } _rt;

	/* SIGCHLD.  */
	struct
	  {
	    __pid_t si_pid;	/* Which child.  */
	    __uid_t si_uid;	/* Real user ID of sending process.  */
	    int si_status;	/* Exit value or signal.  */
	    __clock_t si_utime;
	    __clock_t si_stime;
	  } _sigchld;

	/* SIGILL, SIGFPE, SIGSEGV, SIGBUS.  */
	struct
	  {
	    void *si_addr;	/* Faulting insn/memory ref.  */
	  } _sigfault;

	/* SIGPOLL.  */
	struct
	  {
	    long int si_band;	/* Band event for SIGPOLL.  */
	    int si_fd;
	  } _sigpoll;
      } _sifields;
  } siginfo_t;


/* X/Open requires some more fields with fixed names.  */
# define si_pid		_sifields._kill.si_pid
# define si_uid		_sifields._kill.si_uid
# define si_timerid	_sifields._timer.si_tid
# define si_overrun	_sifields._timer.si_overrun
# define si_status	_sifields._sigchld.si_status
# define si_utime	_sifields._sigchld.si_utime
# define si_stime	_sifields._sigchld.si_stime
# define si_value	_sifields._rt.si_sigval
# define si_int		_sifields._rt.si_sigval.sival_int
# define si_ptr		_sifields._rt.si_sigval.sival_ptr
# define si_addr	_sifields._sigfault.si_addr
# define si_band	_sifields._sigpoll.si_band
# define si_fd		_sifields._sigpoll.si_fd
  
struct sigaction {
    void     (*sa_handler)(int);
    void     (*sa_sigaction)(int, siginfo_t *, void *);
    sigset_t   sa_mask;
    int        sa_flags;
    void     (*sa_restorer)(void);
};

#define SIG_DFL	((__force __sighandler_t)0)	/* default signal handling */
#define SIG_IGN	((__force __sighandler_t)1)	/* ignore signal */
#define SIG_ERR	((__force __sighandler_t)-1)	/* error return from signal */

/*unistd*/

pid_t fork(void);
pid_t setsid(void);


time_t time(time_t *t);
//int gettimeofday(struct timeval *tv, struct timezone *tz);
//int settimeofday(const struct timeval *tv, const struct timezone *tz);
int gettimeofday(void *tv, void *tz);
int settimeofday(const void *tv, const void *tz);
int usleep(unsigned int usec);
//int clock_getres(clockid_t clk_id, struct timespec *res);
//int clock_getres(clockid_t clk_id, struct timespec *res);
//int clock_gettime(clockid_t clk_id, struct timespec *tp);
int clock_settime(clockid_t clk_id, const void *tp);
int clock_gettime(clockid_t clk_id, void *tp);
int clock_settime(clockid_t clk_id, const void *tp);

__sighandler_t  signal(int sig, __sighandler_t func);
int  raise(int sig);
int kill(pid_t pid, int sig);
unsigned int alarm(unsigned int seconds);
int sigaction(int signum, const struct sigaction *act,
              struct sigaction *oldact);
              
int sigemptyset(sigset_t *set);
int sigfillset(sigset_t *set);
int sigaddset(sigset_t *set, int signum);
int sigdelset(sigset_t *set, int signum);
int sigismember(const sigset_t *set, int signum);
int sigprocmask(int how, const sigset_t *set, sigset_t *oldset);


int inotify_init(void);
int inotify_add_watch(int fd, const char *pathname, uint32_t mask);
int inotify_rm_watch(int fd, int wd);

pid_t getpid(void);
pid_t getppid(void);
uid_t getuid(void);
uid_t geteuid(void);
int setuid(uid_t uid);

int open(const char *pathname, int flags, ...);
int close(int fd);

ssize_t read(int fd, void *buf, size_t count);
ssize_t write(int fd, const void *buf, size_t count);
ssize_t pread(int fd, void *buf, size_t count, off_t offset);
ssize_t pwrite(int fd, const void *buf, size_t count, off_t offset);

ssize_t readv(int fd, const struct iovec *iov, int iovcnt);

ssize_t writev(int fd, const struct iovec *iov, int iovcnt);

ssize_t preadv(int fd, const struct iovec *iov, int iovcnt,
               off_t offset);

ssize_t pwritev(int fd, const struct iovec *iov, int iovcnt,
off_t offset);
                
ssize_t readlink(const char *path, char *buf, size_t bufsiz);

int chmod(const char *path, mode_t mode);
int fchmod(int fildes, mode_t mode);
int fcntl(int fd, int cmd, ... /* arg */ );
int dup(int oldfd);
int dup2(int oldfd, int newfd);
//int stat(const char *path, struct stat *buf);
//int fstat(int fd, struct stat *buf);
//int lstat(const char *path, struct stat *buf);
int stat(const char *path, void *buf);
int fstat(int fd, void *buf);
int lstat(const char *path, void *buf);
int symlink(const char *oldpath, const char *newpath);
int rename(const char *oldpath, const char *newpath);
int unlink(const char *pathname);
int truncate(const char *path, off_t length);
int ftruncate(int fd, off_t length);
int statfs(const char *path, struct statfs *buf);
int fstatfs(int fd, struct statfs *buf);
int rmdir(const char *pathname);
int mkdir(const char *pathname, mode_t mode);
int chdir(const char *path);
int fchdir(int fd);
int fsync(int fd);

int socket(int socket_family, int socket_type, int protocol);
int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int listen(int sockfd, int backlog);
int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int shutdown(int sockfd, int how);    

ssize_t recv(int sockfd, void *buf, size_t len, int flags);

ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
                 struct sockaddr *src_addr, socklen_t *addrlen);

ssize_t recvmsg(int sockfd, struct msghdr *msg, int flags);

ssize_t send(int sockfd, const void *buf, size_t len, int flags);

ssize_t sendto(int sockfd, const void *buf, size_t len, int flags,
               const struct sockaddr *dest_addr, socklen_t addrlen);

ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags);


int socketpair (int domain, int type, int protocol, int fds[2]);
		       
int getsockopt(int sockfd, int level, int optname, void *optval,socklen_t *optlen);
int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen);
int getsockname(int sockfd, struct sockaddr *addr, socklen_t * addrlen );
int getpeername(int sockfd, struct sockaddr *addr, socklen_t * addrlen );

int epoll_create(int size);
int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);
int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout);

int poll(struct pollfd *fds, unsigned long int nfds, int timeout);

//int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout);
int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, void *timeout);
void FD_CLR(int fd, fd_set *set);
int  FD_ISSET(int fd, fd_set *set);
void FD_SET(int fd, fd_set *set);
void FD_ZERO(fd_set *set);

void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
int munmap(void *addr, size_t length);

int pipe(int pipefd[2]);

pid_t wait(int *status);
pid_t waitpid(pid_t pid, int *status, int options);


long ptrace(enum __ptrace_request request, ...);
long sysconf(int name);

#define __NR_tkill 131
#define __NR_tgkill 131
int syscall(int number, ...);

#endif
