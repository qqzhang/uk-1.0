/*
 * lib.c
 *
 * Copyright (C) 2006  Insigma Co., Ltd
 *
 * This software has been developed while working on the Linux Unified Kernel
 * project (http://www.longene.org) in the Insigma Research Institute,  
 * which is a subdivision of Insigma Co., Ltd (http://www.insigma.com.cn).
 * 
 * The project is sponsored by Insigma Co., Ltd.
 *
 * The authors can be reached at linux@insigma.com.cn.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of  the GNU General  Public License as published by the
 * Free Software Foundation; either version 2 of the  License, or (at your
 * option) any later version.
 *
 * Revision History:
 *   Dec 2008 - Created.
 */
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/file.h>
#include <linux/vmalloc.h>
#include <linux/ctype.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <linux/statfs.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <asm/byteorder.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "winternl.h"

#ifdef KDEBUG
#define kdebug(FMT...) \
	do { \
		printk("UK: pid %x tid %x %s ", current->tgid, current->pid, __FUNCTION__); \
		printk(FMT); \
	} while (0)
#else
#define kdebug(FMT...) do { } while (0)
#endif

#ifdef KTRACE
#define ktrace(FMT...) \
	do { \
		printk("UK: pid %x tid %x %s ", current->tgid, current->pid, __FUNCTION__); \
		printk(FMT); \
	} while (0)
#else
#define ktrace(FMT...) do { } while (0)
#endif

#define PREPARE_KERNEL_CALL	\
	mm_segment_t oldfs; \
oldfs = get_fs(); \
set_fs(KERNEL_DS);
#define END_KERNEL_CALL	set_fs(oldfs);

#define MAXSIZE_ALLOC (128*1024) //128K

#define TICKSPERSEC        10000000
#define SECSPERDAY         86400
/* 1601 to 1970 is 369 years plus 89 leap days */
#define SECS_1601_TO_1970  ((369 * 365 + 89) * (ULONGLONG)SECSPERDAY)
#define TICKS_1601_TO_1970 (SECS_1601_TO_1970 * TICKSPERSEC)

char *optarg = NULL;
int optind, opterr, optopt;
__int64 start_time;

static inline unsigned int get_error(void)       { return 0; }
static inline void set_error( unsigned int err ) { }
static inline void clear_error(void)             { set_error(0); }
static inline void set_win32_error( unsigned int err ) { set_error( 0xc0010000 | err ); }
static NTSTATUS errno2ntstatus( int error)  { return STATUS_SUCCESS; }

struct LIBC_FILE
{
	struct file *filp;
	loff_t pos;
	char *buf;
	long buflen;
	long bufpos;
	ssize_t validlen;
};


time_t time(void* v)
{
	struct timeval now;
	LARGE_INTEGER time;
	ULONGLONG t;

	PREPARE_KERNEL_CALL;
	do_gettimeofday(&now);
	END_KERNEL_CALL;


	time.QuadPart = now.tv_sec * (ULONGLONG)TICKSPERSEC  + TICKS_1601_TO_1970 + now.tv_usec * 10;
	t = ((ULONGLONG)time.u.HighPart << 32) | time.u.LowPart;
	t = do_div(t,TICKSPERSEC) - TICKS_1601_TO_1970;

	return t;
}

__int64 get_current_time(void)
{
	struct timespec ts;

	getnstimeofday(&ts);
	return (__int64)ts.tv_sec * TICKSPERSEC + ts.tv_nsec / 100 + TICKS_1601_TO_1970;
}


#undef TICKSPERSEC
#undef SECSPERDAY
#undef SECS_1601_TO_1970
#undef TICKS_1601_TO_1970


/* for major() */
unsigned int gnu_dev_major (unsigned long long int dev)
{
	return ((dev >> 8) & 0xfff) | ((unsigned int) (dev >> 32) & ~0xfff);
}

unsigned int gnu_dev_minor (unsigned long long int dev)
{
	return (dev & 0xff) | ((unsigned int) (dev >> 12) & ~0xff);
}

unsigned long long int gnu_dev_makedev (unsigned int major, unsigned int minor)
{
	return ((minor & 0xff) | ((major & 0xfff) << 8)
			| (((unsigned long long int) (minor & ~0xff)) << 12)
			| (((unsigned long long int) (major & ~0xfff)) << 32));
}



typedef unsigned long (*FUNCTION_POINTER)(const char *name);
static FUNCTION_POINTER kallsyms_lookup_name_ptr = NULL;
unsigned long read_kallsyms(char *symbol_name);

#define MAX_BUF_LEN 100
#define PROC_HOME    "/proc/kallsyms"

int kgetline(struct file *file, char *buf)
{
	int i = 0;
	char c = 0;
	int nbytes = 0;
	char temp[MAX_BUF_LEN] = {0};

	for(i=0; i<MAX_BUF_LEN && c!='\n'; i++)
	{
		nbytes = file->f_op->read(file, &c, 1,&file->f_pos);
		if(nbytes==0)
			break;
		temp[i] = c;
		buf[i] = c;
	}
	//printk("Line(%d): %s", i, temp);
	return i;
}

unsigned long read_kallsyms(char *symbol_name)
{
	mm_segment_t old_fs;
	ssize_t bytes;
	struct file *file = NULL;
	char *p;
	int i = 0, len;
	unsigned long addr = 0;

	char line[MAX_BUF_LEN] = {0};
	char new_symbol_name[MAX_BUF_LEN] = "T ";
	strcat(new_symbol_name, symbol_name);
	printk("new_symbol_name: %s\n", new_symbol_name);
	len = strlen(new_symbol_name);

	file = filp_open(PROC_HOME,O_RDONLY,0);
	if (!file)
		return -1;

	if (!file->f_op->read)
		return -1;

	old_fs = get_fs();
	set_fs(get_ds());

	for(;;)
	{
		bytes = kgetline(file,line);
		if(bytes==0)
			break;
		if (( p = strstr(line, new_symbol_name)) != NULL)
		{
			/*
NOTES: ' ' & '\t'
c0123456 T sys_read
e0654321 T cdrom_open    [cdrom]
*/
			if( (*(p+len) != '\n') && (*(p+len) != '\t') )
				continue;

			//			printk("line:%s\n", line);

			for(i=0; i<MAX_BUF_LEN; i++)
			{
				if(line[i] == ' ')
					break;
			}
			line[i] = '\0';

			addr = simple_strtoul(line,NULL,16);

			//			printk("addr(%s): %x\n", symbol_name, addr);

			break;
		}
		memset(line, 0, MAX_BUF_LEN);
	}

	filp_close(file,NULL);

	set_fs(old_fs);
	return addr;
}

void get_kallsyms_lookup_name(void)
{
	kallsyms_lookup_name_ptr = (FUNCTION_POINTER)read_kallsyms("kallsyms_lookup_name");

	if (!kallsyms_lookup_name_ptr) 
	{
		printk("Couldn't find kallsyms_lookup_name()\n");
	} 
	else 
	{
		printk("kallsyms_lookup_name=%08x \n",(unsigned int)kallsyms_lookup_name_ptr);
	}
}

void* get_kernel_proc_address(char *funcname)
{
	void * addr = (void*)kallsyms_lookup_name_ptr(funcname); 
	if (!addr) 
	{
		printk("%s=NULL\n",funcname);
		dump_stack();
	}
	else
	{
		//		printk("%s=%08x\n",funcname,addr);
	}

	return addr;
}


void perror(const char *s)
{
	kdebug("%s\n", s);
	/* FIXME */
	kdebug(": %d\n", errno);
}


void *malloc(size_t size)
{
	void	*addr;

	if (size > MAXSIZE_ALLOC || !(addr = kmalloc(size, GFP_KERNEL))) 
	{
		kdebug("kmalloc size %x err, too large\n", size);
		set_error(STATUS_NO_MEMORY);
		return NULL;
	}

	return addr;
}

void *calloc(size_t nmemb, size_t size)
{
	void	*addr;
	size_t	total = nmemb * size;

	if (total > MAXSIZE_ALLOC || !(addr = kmalloc(total, GFP_KERNEL))) {
		kdebug("kmalloc size %x err, too large\n", total);
		set_error(STATUS_NO_MEMORY);
		return NULL;
	}

	memset(addr, 0, total);

	return addr;
}

void free(void *p)
{
	if (p)
		kfree(p);
}

void *realloc(void *ptr, size_t new_size, size_t old_size)
{
	void	*new_ptr;

	if (!new_size) {
		free(ptr);
		return ptr;
	}

	if (!ptr)
		return malloc(new_size);

	new_ptr = malloc(new_size);
	if (new_ptr) {
		memcpy(new_ptr, ptr, new_size > old_size ? old_size : new_size);
		free(ptr);
	}

	return new_ptr;
}


/* need PREPARE_KERNEL_CALL ? */
long close(unsigned int fd)
{
	long ret;
	asmlinkage	long (*sys_close)(unsigned int fd) = get_kernel_proc_address("sys_close");

	PREPARE_KERNEL_CALL;
	if (!current->files) /* in this case, close is called after do_exit */
		ret = 0;
	else
		ret = sys_close(fd);
	END_KERNEL_CALL;

	return ret;
}

ssize_t filp_write(struct file *filp, void *buf, size_t size)
{
	ssize_t ret;
	loff_t pos;

	PREPARE_KERNEL_CALL;
	pos = filp->f_pos;
	ret = vfs_write(filp, buf, size, &pos);
	filp->f_pos = pos;
	END_KERNEL_CALL;

	return ret;
}

long fclose(struct LIBC_FILE *fp)
{
	int ret;
	if (fp)
	{
		if (fp->buf)
		{
			ret = filp_write(fp->filp, (fp->buf + fp->bufpos-fp->validlen), fp->validlen);
			free_pages((unsigned long)fp->buf, 1);
			fp->buf = NULL;
			fp->validlen = 0;
		}
		fput(fp->filp);

		kfree(fp);
		return 0;
	}

	return -1;
}

ssize_t read(unsigned int fd, void *buf, size_t size)
{
	ssize_t ret;
	asmlinkage	long (*sys_read)(unsigned int, char*, size_t) = get_kernel_proc_address("sys_read");

	PREPARE_KERNEL_CALL;
	ret = sys_read(fd, buf, size);
	END_KERNEL_CALL;

	return ret;
}

ssize_t fwrite(struct LIBC_FILE *fp, void *buf, size_t size)
{
	unsigned int ret=0;
	size_t len = size;
	int pos;

	if(fp->buf == NULL){
		fp->buf = (char *)__get_free_pages(GFP_KERNEL, 1);
		fp->buflen = PAGE_SIZE * 2;
		fp->validlen = 0;
		fp->bufpos = 0;
		if (!fp->buf) {
			set_error(STATUS_NO_MEMORY);
			perror("no memory");
			return 0;
		}
	}
	if(len < 0)
		return 0;
	pos = 0;
	while (len > 0) {
		if (fp->bufpos + len < PAGE_SIZE) {
			memcpy(fp->buf + fp->bufpos, buf + pos, len);
			fp->bufpos += len;
			fp->validlen +=len ;
			break;
		}

		if (!fp->bufpos) {
			ret = filp_write(fp->filp, buf + pos, PAGE_SIZE);
			if (ret != PAGE_SIZE) {
				set_error(errno2ntstatus(-ret));
				return ret;
			}
			pos += PAGE_SIZE;
			len -= PAGE_SIZE;
		} else {
			memcpy(fp->buf + fp->bufpos, buf + pos, PAGE_SIZE - fp->bufpos);
			ret = filp_write(fp->filp, fp->buf, PAGE_SIZE);
			if (ret != PAGE_SIZE) {
				set_error(errno2ntstatus(-ret));
				return ret;
			}
			pos += PAGE_SIZE - fp->bufpos;
			len -= PAGE_SIZE - fp->bufpos;
			fp->bufpos = 0;
			fp->validlen = 0;
		}
	}	

	return ret;
}

long dup(unsigned int fd)
{
	long ret;
	asmlinkage	long (*sys_dup)(unsigned int) = get_kernel_proc_address("sys_dup");

	PREPARE_KERNEL_CALL;
	ret = sys_dup(fd);
	END_KERNEL_CALL;

	return ret;
}

long dup2(unsigned int oldfd, unsigned int newfd)
{
	long ret;
	asmlinkage	long (*sys_dup2)(unsigned int, unsigned int) = get_kernel_proc_address("sys_dup2");

	PREPARE_KERNEL_CALL;
	ret = sys_dup2(oldfd, newfd);
	END_KERNEL_CALL;

	return ret;
}

long kill(int pid, int sig)
{
	long ret;
	asmlinkage long (*sys_kill)(int, int) = get_kernel_proc_address("sys_kill");

	PREPARE_KERNEL_CALL;
	ret = sys_kill(pid, sig);
	END_KERNEL_CALL;

	return ret;
}


int fprintf(struct LIBC_FILE *fp , char *fmt, ...)
{
	int ret;
	va_list args;
	if(fp->buf==NULL)
	{
		fp->buf = (char *)__get_free_pages(GFP_KERNEL, 1);
		fp->buflen = PAGE_SIZE * 2;
		fp->validlen = 0;
		fp->bufpos = 0;
		if (!fp->buf) 
		{
			set_error(STATUS_NO_MEMORY);
			perror("no memory");
			return 0;
		}
	}

	va_start(args, fmt);
	ret = vsnprintf(fp->buf+fp->bufpos, 2 * PAGE_SIZE-fp->bufpos, fmt, args);
	va_end(args);

	if (ret <= 0)
	{
		set_error(STATUS_INVALID_PARAMETER);
		perror("vsnprintf error");
		return ret;
	}
	fp->validlen += (long)ret;
	fp->bufpos += (long)ret;
	if(fp->validlen >= PAGE_SIZE)
	{
		ret = filp_write(fp->filp, fp->buf, PAGE_SIZE);
		if (ret < 0)
		{
			set_error(ret);
			return ret;
		}
		fp->validlen -= ret;
		memcpy(fp->buf, fp->buf + ret, fp->validlen);
		fp->bufpos = fp->validlen;
	}

	return ret;
}

long fstat(unsigned int fd, struct stat *st)
{
	long ret;
	asmlinkage	long (*sys_newfstat)(unsigned int, struct stat*) = get_kernel_proc_address("sys_newfstat");

	PREPARE_KERNEL_CALL;
	ret = sys_newfstat(fd, st);
	END_KERNEL_CALL;

	return ret;
}

void unlink(const char *filename)
{
	asmlinkage	long (*sys_unlink)(const char*) = get_kernel_proc_address("sys_unlink");

	PREPARE_KERNEL_CALL;
	sys_unlink(filename);
	END_KERNEL_CALL;
}

int rename(const char *oldpath, const char *newpath)
{
	int ret;
	asmlinkage	long (*sys_rename)(const char*, const char*) = get_kernel_proc_address("sys_rename");

	PREPARE_KERNEL_CALL;
	ret = sys_rename(oldpath, newpath);
	END_KERNEL_CALL;

	return ret;
}

struct LIBC_FILE *libc_file_open(struct file *filp, char *readwrite)
{
	struct LIBC_FILE *ret;

	ret = (struct LIBC_FILE *)malloc(sizeof(struct LIBC_FILE));
	if (!ret) {
		perror("no memory!\n");
		return NULL;
	}

	memset(ret, 0, sizeof(struct LIBC_FILE));
	ret->filp = filp;
	ret->buf=NULL;
	ret->bufpos=0;

	return ret;
}

void *fgets(void *buf, int len, struct LIBC_FILE *fp)
{
	char *p;
	ssize_t nread;
	struct file *file;

	if (!len)
		return NULL;

	file = fp->filp;
	nread = kernel_read(file, file->f_pos, buf, (size_t)len - 1);

	if (nread <= 0)
		return NULL;

	p = memchr(buf, '\n', nread);
	if (!p) {
		*((char *)buf + nread) = 0;
		file->f_pos += nread;
	}
	else {
		*++p = 0;
		file->f_pos += ((void *)p - buf);
	}

	return buf;
}

ssize_t filp_pread(struct file *filp, char *buf, size_t count, off_t pos)
{
	ssize_t ret;
	loff_t lpos = (loff_t)pos;

	PREPARE_KERNEL_CALL;
	ret = vfs_read(filp, buf, count, &lpos);
	END_KERNEL_CALL;

	return ret;
}

ssize_t filp_pwrite(struct file *filp, const char *buf, size_t count, off_t pos)
{
	ssize_t ret;
	loff_t lpos = (loff_t)pos;

	PREPARE_KERNEL_CALL;
	ret = vfs_write(filp, buf, count, &lpos);
	END_KERNEL_CALL;

	return ret;
}

long readlink(const char *path, char *buf, size_t bufsiz)
{
	long ret;
	asmlinkage	long (*sys_readlink)(const char*, char*, int) = get_kernel_proc_address("sys_readlink");

	PREPARE_KERNEL_CALL;
	ret = sys_readlink(path, buf, bufsiz);
	END_KERNEL_CALL;

	return ret;
}

long fcntl(unsigned int fd, int cmd, unsigned long arg)
{
	long ret;
	asmlinkage	long (*sys_fcntl)(unsigned int, unsigned int, unsigned long) = get_kernel_proc_address("sys_fcntl");

	PREPARE_KERNEL_CALL;
	ret = sys_fcntl(fd, cmd, arg);
	END_KERNEL_CALL;

	return ret;
}

long stat(char *filename, struct stat *st)
{
	long ret;
	asmlinkage	long (*sys_newstat)(char*, struct stat*) 
		= get_kernel_proc_address("sys_newstat");

	PREPARE_KERNEL_CALL;
	ret = sys_newstat(filename, st);
	END_KERNEL_CALL;

	return ret;
}

long poll(struct pollfd *pfds, unsigned int nfds, long timeout_msecs)
{
	long ret;
	asmlinkage	long (*sys_poll)(struct pollfd*, unsigned int, long) 
		= get_kernel_proc_address("sys_poll");

	PREPARE_KERNEL_CALL;
	ret = sys_poll(pfds, nfds, timeout_msecs);
	END_KERNEL_CALL;

	return ret;
}

long socket(int family, int type, int protocol)
{
	asmlinkage	long (*sys_socket)(int, int, int) 
		= get_kernel_proc_address("sys_socket");
	return sys_socket(family, type, protocol);
}

long socketpair(int family, int type, int protocol, int *sockvec)
{
	long ret;
	asmlinkage	long (*sys_socketpair)(int, int, int, int*) 
		= get_kernel_proc_address("sys_socketpair");

	PREPARE_KERNEL_CALL;
	ret = sys_socketpair(family, type, protocol, sockvec);
	END_KERNEL_CALL;

	return ret;
}

long accept(int fd, struct sockaddr *peer_sockaddr, int *peer_addrlen)
{
	long ret;
	asmlinkage	long (*sys_accept)(int, struct sockaddr*, int*) 
		= get_kernel_proc_address("sys_accept");

	PREPARE_KERNEL_CALL;
	ret = sys_accept(fd, peer_sockaddr, peer_addrlen);
	END_KERNEL_CALL;

	return ret;
}

long recv(int fd, void *buf, size_t size, unsigned flags)
{
	long ret;
	asmlinkage	long (*sys_recvfrom)(int, void*, size_t, unsigned, struct sockaddr*, int*) 
		= get_kernel_proc_address("sys_recvfrom");

	PREPARE_KERNEL_CALL;
	ret = sys_recvfrom(fd, buf, size, flags, NULL, NULL);
	END_KERNEL_CALL;

	return ret;
}

long getsockopt(int fd, int level, int optname, void *optval, unsigned int *optlen)
{
	long ret;
	asmlinkage	long (*sys_getsockopt)(int fd, int level, int optname,
			char * optval, int * optlen) = get_kernel_proc_address("sys_getsockopt");

	PREPARE_KERNEL_CALL;
	ret = sys_getsockopt(fd, level, optname, optval, optlen);
	END_KERNEL_CALL;

	return ret;
}

int setsockopt(int fd, int level, int optname, const void *optval, int optlen)
{
	long ret;
	asmlinkage	long (*sys_setsockopt)(int fd, int level, int optname,
			char * optval, int optlen) = get_kernel_proc_address("sys_setsockopt");

	PREPARE_KERNEL_CALL;
	ret = sys_setsockopt(fd, level, optname, (char *)optval, optlen);
	END_KERNEL_CALL;

	return ret;
}

long mkdir(const char *name, int mode)
{
	long ret;
	asmlinkage	long (*sys_mkdir)(const char *pathname, int mode) = get_kernel_proc_address("sys_mkdir");

	PREPARE_KERNEL_CALL;
	ret = sys_mkdir(name, mode);
	END_KERNEL_CALL;

	return ret;
}

/*
 * placeholder
 */
long fchdir(unsigned int fd)
{
	long ret;

	ret = 0	;

	return ret;
}

/*
 * placeholder
 */
long fchmod(int fd, mode_t mode)
{
	long ret;

	ret = 0	;

	return ret;
}

long shutdown(int fd, int how)
{
	long ret;
	asmlinkage	long (*sys_shutdown)(int, int) = get_kernel_proc_address("sys_shutdown");

	PREPARE_KERNEL_CALL;
	ret = sys_shutdown(fd, how);
	END_KERNEL_CALL;

	return ret;
}

/* 
 * below is 3 function.
 * inotify_init,
 * inotify_add_watch,
 * inotify_rm_watch
 */
int inotify_init(void)
{
	int ret;
	asmlinkage long (*sys_inotify_init)(void) = get_kernel_proc_address("sys_inotify_init");

	PREPARE_KERNEL_CALL;
	ret = sys_inotify_init();
	END_KERNEL_CALL;

	return ret;
}

int inotify_add_watch(int fd,const char *pathname,unsigned int mask)
{
	int ret;
	asmlinkage long (*sys_inotify_add_watch)(int, const char __user*, u32)
		= get_kernel_proc_address("sys_inotify_add_watch");

	PREPARE_KERNEL_CALL;
	ret = sys_inotify_add_watch(fd,pathname,mask);
	END_KERNEL_CALL;

	return ret;
}

int inotify_rm_watch(int fd,int wd)
{
	int ret;
	asmlinkage long (*sys_inotify_rm_watch)(int, __s32) = get_kernel_proc_address("sys_inotify_rm_watch");

	PREPARE_KERNEL_CALL;
	ret = sys_inotify_rm_watch(fd,wd);
	END_KERNEL_CALL;

	return ret;
}


int getsockname(int sockfd, void *addr, int *addrlen)
{
	int ret;
	asmlinkage long (*sys_getsockname)(int, struct sockaddr __user*, int __user*)
		= get_kernel_proc_address("sys_getsockname");

	PREPARE_KERNEL_CALL;
	ret = sys_getsockname(sockfd,addr,addrlen);
	END_KERNEL_CALL;

	return ret;
}

int getpeername(int sockfd, void *addr, int *addrlen)
{
	int ret;
	asmlinkage long (*sys_getpeername)(int, struct sockaddr __user*, int __user*)
		= get_kernel_proc_address("sys_getpeername");

	PREPARE_KERNEL_CALL;
	ret = sys_getpeername(sockfd,addr,addrlen);
	END_KERNEL_CALL;

	return ret;
}

int recvmsg(int sockfd, void *msg, int flags)
{
	int ret;
	asmlinkage long (*sys_recvmsg)(int, struct msghdr __user*, unsigned)
		= get_kernel_proc_address("sys_recvmsg");

	PREPARE_KERNEL_CALL;
	ret = sys_recvmsg(sockfd,msg,flags);
	END_KERNEL_CALL;

	return ret;	
}

int sendmsg(int sockfd, void *msg, int flags)
{
	int ret;
	asmlinkage long (*sys_sendmsg)(int, struct msghdr __user*, unsigned)
		= get_kernel_proc_address("sys_sendmsg");

	PREPARE_KERNEL_CALL;
	ret = sys_sendmsg(sockfd,msg,flags);
	END_KERNEL_CALL;

	return ret;	
}

//long filp_truncate(struct file *file, loff_t length, int small)
long filp_truncate(struct file *file, long length, int small)
{
	struct inode * inode;
	struct dentry *dentry;
	int error;
	loff_t len = length;
	int (*do_truncate)(struct dentry*, loff_t, unsigned int, struct file*)
		= get_kernel_proc_address("do_truncate");

	error = -EINVAL;
	if (length < 0)
		goto out;
	if (!file)
		goto out;

	/* explicitly opened as large or we are on 64-bit box */
	if (file->f_flags & O_LARGEFILE)
		small = 0;

	dentry = file->f_path.dentry;
	inode = dentry->d_inode;
	error = -EINVAL;
	if (!S_ISREG(inode->i_mode) || !(file->f_mode & FMODE_WRITE))
		goto out;

	error = -EINVAL;
	/* Cannot ftruncate over 2^31 bytes without large file support */
	if (small && length > MAX_NON_LFS)
		goto out;

	error = -EPERM;
	if (IS_APPEND(inode))
		goto out;

	error = locks_verify_truncate(inode, file, length);
	if (!error)
		error = do_truncate(dentry, len, ATTR_MTIME | ATTR_CTIME, file);

out:
	return error;
}


