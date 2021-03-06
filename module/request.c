/*
 * Server-side request handling
 *
 * Copyright (C) 1998 Alexandre Julliard
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 */

/*
 * Copyright (C) 2006  Insigma Co., Ltd
 *
 * This software has been developed while working on the Linux Unified Kernel
 * Project (http://www.longene.org) in the Insigma Research Institute,  
 * which is a subdivision of Insigma Co., Ltd (http://www.insigma.com.cn).
 * 
 * The project is sponsored by Insigma Co., Ltd.
 *
 * The authors can be reached at linux@insigma.com.cn.
 */

#include "config.h"
#include "wine/port.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#ifdef HAVE_PWD_H
#include <pwd.h>
#endif
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
#ifdef HAVE_SYS_WAIT_H
# include <sys/wait.h>
#endif
#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif
#ifdef HAVE_SYS_UN_H
#include <sys/un.h>
#endif
#include <unistd.h>
#ifdef HAVE_POLL_H
#include <poll.h>
#endif
#ifdef __APPLE__
# include <mach/mach_time.h>
#endif

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "wincon.h"
#include "winternl.h"
#include "wine/library.h"

#include "file.h"
#include "process.h"
#define WANT_REQUEST_HANDLERS
#include "request.h"

#ifdef CONFIG_UNIFIED_KERNEL
#include "wine/server.h" /* for struct __server_request_info */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/cdev.h>
#include <linux/slab.h>
#include <linux/device.h>
#endif

/* Some versions of glibc don't define this */
#ifndef SCM_RIGHTS
#define SCM_RIGHTS 1
#endif

/* path names for server master Unix socket */
static const char * const server_socket_name = "socket";   /* name of the socket file */
static const char * const server_lock_name = "lock";       /* name of the server lock file */

struct master_socket
{
    struct object        obj;        /* object header */
    struct uk_fd           *fd;         /* file descriptor of the master socket */
};

static void master_socket_dump( struct object *obj, int verbose );
static void master_socket_destroy( struct object *obj );
static void master_socket_poll_event( struct uk_fd *fd, int event );

static const struct object_ops master_socket_ops =
{
    sizeof(struct master_socket),  /* size */
    master_socket_dump,            /* dump */
    no_get_type,                   /* get_type */
    no_add_queue,                  /* add_queue */
    NULL,                          /* remove_queue */
    NULL,                          /* signaled */
    NULL,                          /* satisfied */
    no_signal,                     /* signal */
    no_get_fd,                     /* get_fd */
    no_map_access,                 /* map_access */
    default_get_sd,                /* get_sd */
    default_set_sd,                /* set_sd */
    no_lookup_name,                /* lookup_name */
    no_open_file,                  /* open_file */
    no_close_handle,               /* close_handle */
    master_socket_destroy          /* destroy */
};

static const struct fd_ops master_socket_fd_ops =
{
    NULL,                          /* get_poll_events */
    master_socket_poll_event,      /* poll_event */
    NULL,                          /* flush */
    NULL,                          /* get_fd_type */
    NULL,                          /* ioctl */
    NULL,                          /* queue_async */
    NULL,                          /* reselect_async */
    NULL                           /* cancel_async */
};


#ifndef CONFIG_UNIFIED_KERNEL
struct thread *current_thread = NULL;  /* thread handling the current_thread request */
#endif
unsigned int global_error = 0;  /* global error code for when no thread is current_thread */
timeout_t server_start_time = 0;  /* server startup time */
int server_dir_fd = -1;    /* file descriptor for the server dir */
int config_dir_fd = -1;    /* file descriptor for the config dir */

static struct master_socket *master_socket;  /* the master socket object */
static struct timeout_user *master_timeout;

/* complain about a protocol error and terminate the client connection */
void fatal_protocol_error( struct thread *thread, const char *err, ... )
{
    va_list args;

    va_start( args, err );
    fprintf( stderr, "Protocol error:%04x: ", thread->id );
    vfprintf( stderr, err, args );
    va_end( args );
    thread->exit_code = 1;
    kill_thread( thread, 1 );
}

/* die on a fatal error */
void fatal_error( const char *err, ... )
{
    va_list args;

    va_start( args, err );
    fprintf( stderr, "wineserver: " );
    vfprintf( stderr, err, args );
    va_end( args );
    exit(1);
}

/* allocate the reply data */
void *set_reply_data_size( data_size_t size )
{
    assert( size <= get_reply_max_size() );
    if (size && !(current_thread->reply_data = mem_alloc( size ))) size = 0;
    current_thread->reply_size = size;
    return current_thread->reply_data;
}

/* write the remaining part of the reply */
void write_reply( struct thread *thread )
{
    int ret;

    if ((ret = write( get_unix_fd( thread->reply_fd ),
                      (char *)thread->reply_data + thread->reply_size - thread->reply_towrite,
                      thread->reply_towrite )) >= 0)
    {
        if (!(thread->reply_towrite -= ret))
        {
            free( thread->reply_data );
            thread->reply_data = NULL;
            /* sent everything, can go back to waiting for requests */
            set_fd_events( thread->request_fd, POLLIN );
            set_fd_events( thread->reply_fd, 0 );
        }
        return;
    }
    if (errno == EPIPE)
        kill_thread( thread, 0 );  /* normal death */
    else if (errno != EWOULDBLOCK && errno != EAGAIN)
        fatal_protocol_error( thread, "reply write: %s\n", strerror( errno ));
}

/* send a reply to the current_thread thread */
static void send_reply( union generic_reply *reply )
{
    int ret;

    if (!current_thread->reply_size)
    {
        if ((ret = write( get_unix_fd( current_thread->reply_fd ),
                          reply, sizeof(*reply) )) != sizeof(*reply)) goto error;
    }
    else
    {
        struct iovec vec[2];

        vec[0].iov_base = (void *)reply;
        vec[0].iov_len  = sizeof(*reply);
        vec[1].iov_base = current_thread->reply_data;
        vec[1].iov_len  = current_thread->reply_size;

        if ((ret = writev( get_unix_fd( current_thread->reply_fd ), vec, 2 )) < sizeof(*reply)) goto error;

        if ((current_thread->reply_towrite = current_thread->reply_size - (ret - sizeof(*reply))))
        {
            /* couldn't write it all, wait for POLLOUT */
            set_fd_events( current_thread->reply_fd, POLLOUT );
            set_fd_events( current_thread->request_fd, 0 );
            return;
        }
    }
    free( current_thread->reply_data );
    current_thread->reply_data = NULL;
    return;

 error:
    if (ret >= 0)
        fatal_protocol_error( current_thread, "partial write %d\n", ret );
    else if (errno == EPIPE)
        kill_thread( current_thread, 0 );  /* normal death */
    else
        fatal_protocol_error( current_thread, "reply write: %s\n", strerror( errno ));
}

/* call a request handler */
static void call_req_handler( struct thread *thread )
{
    union generic_reply reply;
    enum request req = thread->req.request_header.req;

#ifndef CONFIG_UNIFIED_KERNEL
    current_thread = thread;
#endif
    current_thread->reply_size = 0;
    clear_error();
    memset( &reply, 0, sizeof(reply) );

    if (debug_level) trace_request();

    if (req < REQ_NB_REQUESTS)
        req_handlers[req]( &current_thread->req, &reply );
    else
        set_error( STATUS_NOT_IMPLEMENTED );

    if (current_thread)
    {
        if (current_thread->reply_fd)
        {
            reply.reply_header.error = current_thread->error;
            reply.reply_header.reply_size = current_thread->reply_size;
            if (debug_level) trace_reply( req, &reply );
            send_reply( &reply );
        }
        else
        {
            current_thread->exit_code = 1;
            kill_thread( current_thread, 1 );  /* no way to continue without reply fd */
        }
    }
#ifndef CONFIG_UNIFIED_KERNEL
    current_thread = NULL;
#endif
}

/* read a request from a thread */
void read_request( struct thread *thread )
{
    int ret;

    if (!thread->req_toread)  /* no pending request */
    {
        if ((ret = read( get_unix_fd( thread->request_fd ), &thread->req,
                         sizeof(thread->req) )) != sizeof(thread->req)) goto error;
        if (!(thread->req_toread = thread->req.request_header.request_size))
        {
            /* no data, handle request at once */
            call_req_handler( thread );
            return;
        }
        if (!(thread->req_data = malloc( thread->req_toread )))
        {
            fatal_protocol_error( thread, "no memory for %u bytes request %d\n",
                                  thread->req_toread, thread->req.request_header.req );
            return;
        }
    }

    /* read the variable sized data */
    for (;;)
    {
        ret = read( get_unix_fd( thread->request_fd ),
                    (char *)thread->req_data + thread->req.request_header.request_size
                      - thread->req_toread,
                    thread->req_toread );
        if (ret <= 0) break;
        if (!(thread->req_toread -= ret))
        {
            call_req_handler( thread );
            free( thread->req_data );
            thread->req_data = NULL;
            return;
        }
    }

error:
    if (!ret)  /* closed pipe */
        kill_thread( thread, 0 );
    else if (ret > 0)
        fatal_protocol_error( thread, "partial read %d\n", ret );
    else if (errno != EWOULDBLOCK && errno != EAGAIN)
        fatal_protocol_error( thread, "read: %s\n", strerror( errno ));
}

#ifdef CONFIG_UNIFIED_KERNEL
int receive_fd( struct process *process )
{
	klog(0,"don't need \n");
	return -1;
}
#else
/* receive a file descriptor on the process socket */
int receive_fd( struct process *process )
{
    struct iovec vec;
    struct send_fd data;
    struct msghdr msghdr;
    int fd = -1, ret;

#ifdef HAVE_STRUCT_MSGHDR_MSG_ACCRIGHTS
    msghdr.msg_accrightslen = sizeof(int);
    msghdr.msg_accrights = (void *)&fd;
#else  /* HAVE_STRUCT_MSGHDR_MSG_ACCRIGHTS */
    char cmsg_buffer[256];
    msghdr.msg_control    = cmsg_buffer;
    msghdr.msg_controllen = sizeof(cmsg_buffer);
    msghdr.msg_flags      = 0;
#endif  /* HAVE_STRUCT_MSGHDR_MSG_ACCRIGHTS */

    msghdr.msg_name    = NULL;
    msghdr.msg_namelen = 0;
    msghdr.msg_iov     = &vec;
    msghdr.msg_iovlen  = 1;
    vec.iov_base = (void *)&data;
    vec.iov_len  = sizeof(data);

    ret = recvmsg( get_unix_fd( process->msg_fd ), &msghdr, 0 );

#ifndef HAVE_STRUCT_MSGHDR_MSG_ACCRIGHTS
    if (ret > 0)
    {
        struct cmsghdr *cmsg;
        for (cmsg = CMSG_FIRSTHDR( &msghdr ); cmsg; cmsg = CMSG_NXTHDR( &msghdr, cmsg ))
        {
            if (cmsg->cmsg_level != SOL_SOCKET) continue;
            if (cmsg->cmsg_type == SCM_RIGHTS) fd = *(int *)CMSG_DATA(cmsg);
        }
    }
#endif  /* HAVE_STRUCT_MSGHDR_MSG_ACCRIGHTS */

    if (ret == sizeof(data))
    {
        struct thread *thread;

        if (data.tid) thread = get_thread_from_id( data.tid );
        else thread = (struct thread *)grab_object( get_process_first_thread( process ));

        if (!thread || thread->process != process || thread->state == TERMINATED)
        {
            if (debug_level)
                fprintf( stderr, "%04x: *fd* %d <- %d bad thread id\n",
                         data.tid, data.fd, fd );
            close( fd );
        }
        else
        {
            if (debug_level)
                fprintf( stderr, "%04x: *fd* %d <- %d\n",
                         thread->id, data.fd, fd );
            thread_add_inflight_fd( thread, data.fd, fd );
        }
        if (thread) release_object( thread );
        return 0;
    }

    if (!ret)
    {
        kill_process( process, 0 );
    }
    else if (ret > 0)
    {
        fprintf( stderr, "Protocol error: process %04x: partial recvmsg %d for fd\n",
                 process->id, ret );
        if (fd != -1) close( fd );
        kill_process( process, 1 );
    }
    else
    {
        if (errno != EWOULDBLOCK && errno != EAGAIN)
        {
            fprintf( stderr, "Protocol error: process %04x: ", process->id );
            perror( "recvmsg" );
            kill_process( process, 1 );
        }
    }
    return -1;
}
#endif

#ifdef CONFIG_UNIFIED_KERNEL
int send_client_fd( struct process *process, int fd, obj_handle_t handle )
{
	return 0;
}
#else
/* send an fd to a client */
int send_client_fd( struct process *process, int fd, obj_handle_t handle )
{
    struct iovec vec;
    struct msghdr msghdr;
    int ret;

#ifdef HAVE_STRUCT_MSGHDR_MSG_ACCRIGHTS
    msghdr.msg_accrightslen = sizeof(fd);
    msghdr.msg_accrights = (void *)&fd;
#else  /* HAVE_STRUCT_MSGHDR_MSG_ACCRIGHTS */
    char cmsg_buffer[256];
    struct cmsghdr *cmsg;
    msghdr.msg_control    = cmsg_buffer;
    msghdr.msg_controllen = sizeof(cmsg_buffer);
    msghdr.msg_flags      = 0;
    cmsg = CMSG_FIRSTHDR( &msghdr );
    cmsg->cmsg_len   = CMSG_LEN( sizeof(fd) );
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type  = SCM_RIGHTS;
    *(int *)CMSG_DATA(cmsg) = fd;
    msghdr.msg_controllen = cmsg->cmsg_len;
#endif  /* HAVE_STRUCT_MSGHDR_MSG_ACCRIGHTS */

    msghdr.msg_name    = NULL;
    msghdr.msg_namelen = 0;
    msghdr.msg_iov     = &vec;
    msghdr.msg_iovlen  = 1;

    vec.iov_base = (void *)&handle;
    vec.iov_len  = sizeof(handle);

    if (debug_level)
        fprintf( stderr, "%04x: *fd* %04x -> %d\n", current_thread ? current_thread->id : process->id, handle, fd );

    ret = sendmsg( get_unix_fd( process->msg_fd ), &msghdr, 0 );

    if (ret == sizeof(handle)) return 0;

    if (ret >= 0)
    {
        fprintf( stderr, "Protocol error: process %04x: partial sendmsg %d\n", process->id, ret );
        kill_process( process, 1 );
    }
    else if (errno == EPIPE)
    {
        kill_process( process, 0 );
    }
    else
    {
        fprintf( stderr, "Protocol error: process %04x: ", process->id );
        perror( "sendmsg" );
        kill_process( process, 1 );
    }
    return -1;
}
#endif

/* get current_thread tick count to return to client */
unsigned int get_tick_count(void)
{
#ifndef CONFIG_UNIFIED_KERNEL
#ifdef HAVE_CLOCK_GETTIME
    struct timespec ts;
#ifdef CLOCK_MONOTONIC_RAW
    if (!clock_gettime( CLOCK_MONOTONIC_RAW, &ts ))
        return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
#endif
    if (!clock_gettime( CLOCK_MONOTONIC, &ts ))
        return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
#elif defined(__APPLE__)
    static mach_timebase_info_data_t timebase;

    if (!timebase.denom) mach_timebase_info( &timebase );
    return mach_absolute_time() * timebase.numer / timebase.denom / 1000000;
#endif
    return (current_time - server_start_time) / 10000;
#else
    {
	    u64 tmp = (current_time - server_start_time);
	    do_div(tmp, 10000);
	    return (unsigned int)tmp;
    }
#endif
}

static void master_socket_dump( struct object *obj, int verbose )
{
    struct master_socket *sock = (struct master_socket *)obj;
    assert( obj->ops == &master_socket_ops );
    fprintf( stderr, "Master socket fd=%p\n", sock->fd );
}

static void master_socket_destroy( struct object *obj )
{
    struct master_socket *sock = (struct master_socket *)obj;
    assert( obj->ops == &master_socket_ops );
    release_object( sock->fd );
}

/* handle a socket event */
static void master_socket_poll_event( struct uk_fd *fd, int event )
{
    struct master_socket *sock = get_fd_user( fd );
    assert( master_socket->obj.ops == &master_socket_ops );

    assert( sock == master_socket );  /* there is only one master socket */

    if (event & (POLLERR | POLLHUP))
    {
        /* this is not supposed to happen */
        fprintf( stderr, "wineserver: Error on master socket\n" );
        set_fd_events( sock->fd, -1 );
    }
    else if (event & POLLIN)
    {
        struct sockaddr_un dummy;
        socklen_t len = sizeof(dummy);
        int client = accept( get_unix_fd( master_socket->fd ), (struct sockaddr *) &dummy, &len );
        if (client == -1) return;
        fcntl( client, F_SETFL, O_NONBLOCK );
        create_process( client, NULL, 0 );
    }
}

/* remove the socket upon exit */
static void socket_cleanup(void)
{
    static int do_it_once;
    if (!do_it_once++) unlink( server_socket_name );
}

/* create a directory and check its permissions */
static void create_dir( const char *name, struct stat *st )
{
    if (lstat( name, st ) == -1)
    {
        if (errno != ENOENT)
            fatal_error( "lstat %s: %s", name, strerror( errno ));
        if (mkdir( name, 0700 ) == -1 && errno != EEXIST)
            fatal_error( "mkdir %s: %s\n", name, strerror( errno ));
        if (lstat( name, st ) == -1)
            fatal_error( "lstat %s: %s\n", name, strerror( errno ));
    }
    if (!S_ISDIR(st->st_mode)) fatal_error( "%s is not a directory\n", name );
    if (st->st_uid != getuid()) fatal_error( "%s is not owned by you\n", name );
    if (st->st_mode & 077) fatal_error( "%s must not be accessible by other users\n", name );
}

/* create the server directory and chdir to it */
static void create_server_dir( const char *dir )
{
    char *p, *server_dir;
    struct stat st, st2;

    if (!(server_dir = strdup( dir ))) fatal_error( "out of memory\n" );

    /* first create the base directory if needed */

    p = strrchr( server_dir, '/' );
    *p = 0;
    create_dir( server_dir, &st );

    /* now create the server directory */

    *p = '/';
    create_dir( server_dir, &st );

    if (chdir( server_dir ) == -1)
        fatal_error( "chdir %s: %s\n", server_dir, strerror( errno ));
    if ((server_dir_fd = open( ".", O_RDONLY )) == -1)
        fatal_error( "open %s: %s\n", server_dir, strerror( errno ));
    if (fstat( server_dir_fd, &st2 ) == -1)
        fatal_error( "stat %s: %s\n", server_dir, strerror( errno ));
    if (st.st_dev != st2.st_dev || st.st_ino != st2.st_ino)
        fatal_error( "chdir did not end up in %s\n", server_dir );

    free( server_dir );
}

/* create the lock file and return its file descriptor */
static int create_server_lock(void)
{
    struct stat st;
    int fd;

    if (lstat( server_lock_name, &st ) == -1)
    {
        if (errno != ENOENT)
            fatal_error( "lstat %s/%s: %s", wine_get_server_dir(), server_lock_name, strerror( errno ));
    }
    else
    {
        if (!S_ISREG(st.st_mode))
            fatal_error( "%s/%s is not a regular file\n", wine_get_server_dir(), server_lock_name );
    }

    if ((fd = open( server_lock_name, O_CREAT|O_TRUNC|O_WRONLY, 0600 )) == -1)
        fatal_error( "error creating %s/%s: %s", wine_get_server_dir(), server_lock_name, strerror( errno ));
    return fd;
}

/* wait for the server lock */
int wait_for_lock(void)
{
    const char *server_dir = wine_get_server_dir();
    int fd, r;
    struct flock fl;

    if (!server_dir) return 0;  /* no server dir, so no lock to wait on */

    create_server_dir( server_dir );
    fd = create_server_lock();

    fl.l_type   = F_WRLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start  = 0;
    fl.l_len    = 1;
    r = fcntl( fd, F_SETLKW, &fl );
    close(fd);

    return r;
}

/* kill the wine server holding the lock */
int kill_lock_owner( int sig )
{
    const char *server_dir = wine_get_server_dir();
    int fd, i, ret = 0;
    pid_t pid = 0;
    struct flock fl;

    if (!server_dir) return 0;  /* no server dir, nothing to do */

    create_server_dir( server_dir );
    fd = create_server_lock();

    for (i = 1; i <= 20; i++)
    {
        fl.l_type   = F_WRLCK;
        fl.l_whence = SEEK_SET;
        fl.l_start  = 0;
        fl.l_len    = 1;
        if (fcntl( fd, F_GETLK, &fl ) == -1) goto done;
        if (fl.l_type != F_WRLCK) goto done;  /* the file is not locked */
        if (!pid)  /* first time around */
        {
            if (!(pid = fl.l_pid)) goto done;  /* shouldn't happen */
            if (sig == -1)
            {
                if (kill( pid, SIGINT ) == -1) goto done;
                kill( pid, SIGCONT );
                ret = 1;
            }
            else  /* just send the specified signal and return */
            {
                ret = (kill( pid, sig ) != -1);
                goto done;
            }
        }
        else if (fl.l_pid != pid) goto done;  /* no longer the same process */
        usleep( 50000 * i );
    }
    /* waited long enough, now kill it */
    kill( pid, SIGKILL );

 done:
    close( fd );
    return ret;
}

/* acquire the main server lock */
static void acquire_lock(void)
{
    struct sockaddr_un addr;
    struct stat st;
    struct flock fl;
    int fd, slen, got_lock = 0;

    fd = create_server_lock();

    fl.l_type   = F_WRLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start  = 0;
    fl.l_len    = 1;
    if (fcntl( fd, F_SETLK, &fl ) != -1)
    {
        /* check for crashed server */
        if (stat( server_socket_name, &st ) != -1 &&   /* there is a leftover socket */
            stat( "core", &st ) != -1 && st.st_size)   /* and there is a non-empty core file */
        {
            fprintf( stderr,
                     "Warning: a previous instance of the wine server seems to have crashed.\n"
                     "Please run 'gdb %s %s/core',\n"
                     "type 'backtrace' at the gdb prompt and report the results. Thanks.\n\n",
                     server_argv0, wine_get_server_dir() );
        }
        unlink( server_socket_name ); /* we got the lock, we can safely remove the socket */
        got_lock = 1;
        /* in that case we reuse fd without closing it, this ensures
         * that we hold the lock until the process exits */
    }
    else
    {
        switch(errno)
        {
        case ENOLCK:
            break;
        case EACCES:
            /* check whether locks work at all on this file system */
            if (fcntl( fd, F_GETLK, &fl ) == -1) break;
            /* fall through */
        case EAGAIN:
            exit(2); /* we didn't get the lock, exit with special status */
        default:
            fatal_error( "fcntl %s/%s: %s", wine_get_server_dir(), server_lock_name, strerror( errno ));
        }
        /* it seems we can't use locks on this fs, so we will use the socket existence as lock */
        close( fd );
    }

    if ((fd = socket( AF_UNIX, SOCK_STREAM, 0 )) == -1) fatal_error( "socket: %s\n", strerror( errno ));
    addr.sun_family = AF_UNIX;
    strcpy( addr.sun_path, server_socket_name );
    slen = sizeof(addr) - sizeof(addr.sun_path) + strlen(addr.sun_path) + 1;
#ifdef HAVE_STRUCT_SOCKADDR_UN_SUN_LEN
    addr.sun_len = slen;
#endif
    if (bind( fd, (struct sockaddr *)&addr, slen ) == -1)
    {
        if ((errno == EEXIST) || (errno == EADDRINUSE))
        {
            if (got_lock)
                fatal_error( "couldn't bind to the socket even though we hold the lock\n" );
            exit(2); /* we didn't get the lock, exit with special status */
        }
        fatal_error( "bind: %s\n", strerror( errno ));
    }
    atexit( socket_cleanup );
    chmod( server_socket_name, 0600 );  /* make sure no other user can connect */
    if (listen( fd, 5 ) == -1) fatal_error( "listen: %s\n", strerror( errno ));

    if (!(master_socket = alloc_object( &master_socket_ops )) ||
        !(master_socket->fd = create_anonymous_fd( &master_socket_fd_ops, fd, &master_socket->obj, 0 )))
        fatal_error( "out of memory\n" );
    set_fd_events( master_socket->fd, POLLIN );
    make_object_static( &master_socket->obj );
}

/* open the master server socket and start waiting for new clients */
void open_master_socket(void)
{
    const char *server_dir = wine_get_server_dir();
    const char *config_dir = wine_get_config_dir();
    int fd, pid, status, sync_pipe[2];
    char dummy;

    /* make sure no request is larger than the maximum size */
    assert( sizeof(union generic_request) == sizeof(struct request_max_size) );
    assert( sizeof(union generic_reply) == sizeof(struct request_max_size) );

    /* make sure the stdio fds are open */
    fd = open( "/dev/null", O_RDWR );
    while (fd >= 0 && fd <= 2) fd = dup( fd );

    if (!server_dir)
        fatal_error( "directory %s cannot be accessed\n", config_dir );
    if (chdir( config_dir ) == -1)
        fatal_error( "chdir to %s: %s\n", config_dir, strerror( errno ));
    if ((config_dir_fd = open( ".", O_RDONLY )) == -1)
        fatal_error( "open %s: %s\n", config_dir, strerror( errno ));

    create_server_dir( server_dir );

    if (!foreground)
    {
        if (pipe( sync_pipe ) == -1) fatal_error( "pipe: %s\n", strerror( errno ));
        pid = fork();
        switch( pid )
        {
        case 0:  /* child */
            setsid();
            close( sync_pipe[0] );

            acquire_lock();

            /* close stdin and stdout */
            dup2( fd, 0 );
            dup2( fd, 1 );

            /* signal parent */
            dummy = 0;
            write( sync_pipe[1], &dummy, 1 );
            close( sync_pipe[1] );
            break;

        case -1:
            fatal_error( "fork: %s\n", strerror( errno ));
            break;

        default:  /* parent */
            close( sync_pipe[1] );

            /* wait for child to signal us and then exit */
            if (read( sync_pipe[0], &dummy, 1 ) == 1) _exit(0);

            /* child terminated, propagate exit status */
            waitpid( pid, &status, 0 );
            if (WIFEXITED(status)) _exit( WEXITSTATUS(status) );
            _exit(1);
        }
    }
    else  /* remain in the foreground */
    {
        acquire_lock();
    }

    /* init the process tracing mechanism */
    init_tracing_mechanism();
    close( fd );
}

/* master socket timer expiration handler */
static void close_socket_timeout( void *arg )
{
    master_timeout = NULL;
    flush_registry();
    if (debug_level) fprintf( stderr, "wineserver: exiting (pid=%ld)\n", (long) getpid() );

#ifdef DEBUG_OBJECTS
    close_objects();  /* shut down everything properly */
#endif
    exit( 0 );
}

#ifdef CONFIG_UNIFIED_KERNEL
/* close the master socket and stop waiting for new clients */
void close_master_socket( timeout_t timeout )
{
}
#else
/* close the master socket and stop waiting for new clients */
void close_master_socket( timeout_t timeout )
{
    if (master_socket)
    {
        release_object( master_socket );
        master_socket = NULL;
    }
    if (master_timeout)  /* cancel previous timeout */
        remove_timeout_user( master_timeout );

    master_timeout = add_timeout_user( timeout, close_socket_timeout, NULL );
}
#endif

#ifdef CONFIG_UNIFIED_KERNEL

const char __user *current_config_dir;
extern void uk_init_registry(const char __user* config_dir, int len);
extern ssize_t uk_thread_wait(char __user *buf, size_t len);

NTSTATUS NtEarlyInit(int __user* init_data_ptr)
{
    struct init_data init_data;
    struct thread *new_thread;
    int thread_id;
    char type;

    memset(&init_data, 0, sizeof(struct init_data));
    if (copy_from_user(&init_data, init_data_ptr, sizeof(struct init_data)))
    {
        klog(0,"error: copy_from_user\n");
        return STATUS_NO_MEMORY;
    }

    type = init_data.init_type;
    thread_id = init_data.thread_id;
    switch( type )
    {
        case FIRST_PROCESS:
            create_process( init_data.socketfd, NULL, 0 );
            if (!current_config_dir)
            {
                current_config_dir = init_data.config_dir;
                uk_init_registry(init_data.config_dir, init_data.config_dir_len);
            }
            /* TODO */
            //else if (!strcmp(current_config_dir, init_data.config_dir))

            return STATUS_SUCCESS;

        case NEW_PROCESS:
        case NEW_THREAD:
            if (thread_id)
            {
                if ((new_thread = get_thread_from_id(thread_id)) != NULL)
                {
                    add_thread_by_pid( new_thread, current->pid );
                }
                else
                {
                    klog(0,"error: get_thread_from_id. type %d thread_id=%d \n", type, thread_id);
                    return STATUS_UNSUCCESSFUL;
                }
            }
            return STATUS_SUCCESS;

        default:
            klog(0,"error : Unkown type \n");
            return STATUS_NOT_IMPLEMENTED;
    }
}

NTSTATUS NtWineService(int __user *user_req_info)
{
    struct thread *thread;
    struct __server_request_info req_msg;
    union generic_reply reply;
    enum request req = -1;
    NTSTATUS status = STATUS_SUCCESS;
    int i;

    thread = get_current_thread();

    if(!user_req_info || !thread)
    {
        return STATUS_INVALID_PARAMETER;
    }

    if (copy_from_user(&req_msg, user_req_info, sizeof(req_msg)))
    {
        return STATUS_NO_MEMORY;
    }

    memcpy(&thread->req, &req_msg, sizeof(thread->req));
    req = thread->req.request_header.req;
    thread->req_toread = thread->req.request_header.request_size; 

    if (thread->req_toread )
    {
        if (!(thread->req_data = malloc(thread->req_toread)))
        {
            return STATUS_NO_MEMORY;
        }

        for (i=0; i<req_msg.data_count; ++i)
        {
            if(copy_from_user(
                        (char *)thread->req_data + thread->req.request_header.request_size - thread->req_toread, 
                        req_msg.data[i].ptr, 
                        req_msg.data[i].size))
            { 
                status = STATUS_NO_MEMORY;
                goto out;
            }

            thread->req_toread -= req_msg.data[i].size;
        }
    }

    thread->reply_size = 0;
    clear_error();
    memset( &reply, 0, sizeof(reply) );

    if (debug_level) trace_request();

    if (req < REQ_NB_REQUESTS)
    {
        req_handlers[req]( &thread->req, &reply ); /* call handle */
    }
    else
    {
        set_error( STATUS_NOT_IMPLEMENTED );
    }

    status = get_error();

    //if (thread->reply_fd)
    if (thread)
    {
        reply.reply_header.error = thread->error;
        reply.reply_header.reply_size = thread->reply_size;
        if (debug_level) trace_reply( req, &reply );
    }
    else
    {
        thread->exit_code = 1;
        kill_thread( thread, 1 );  /* no way to continue without reply fd */
    }

    /* make sure : &user_req_info == &user_req_info.u.reply */
    if (copy_to_user(user_req_info, &reply, sizeof(reply))) 
    {
        status = STATUS_NO_MEMORY;
        goto out;
    }

    if (thread->reply_size)
    {
        if (copy_to_user(req_msg.reply_data, thread->reply_data, thread->reply_size))
        {
            status = STATUS_NO_MEMORY;
            goto out;
        }
    }

out:
    if (thread->req_data)
    {
        free(thread->req_data);
        thread->req_data = NULL;
    }

    if (thread->reply_data)
    {
        free(thread->reply_data);
        thread->reply_data = NULL;
    }

    return status;
}

NTSTATUS NtKillThread(int __user* exit_code)
{
    kill_thread(current_thread, 0);
    return STATUS_SUCCESS;
}

NTSTATUS NtKillProcess(int __user* exit_code)
{
    struct process * process = current_thread->process;
    kill_thread(current_thread, 0);
    kill_process(process, 0);
    return STATUS_SUCCESS;
}

/* for syscall_chardev_fops */
static struct class *class;
static struct device *dev;
static struct cdev *chardev;
static dev_t devno;

static int syscall_chardev_open(struct inode *inode, struct file *file)
{
    return 0;
}

static int syscall_chardev_release(struct inode *inode, struct file *file)
{
    return 0;
}

static ssize_t syscall_chardev_read(struct file *filp, char __user *buf, size_t len, loff_t *ppos)
{
    return uk_thread_wait(buf, len);
}

static ssize_t syscall_chardev_write(struct file *filp, const char __user *buf, size_t len, loff_t *ppos)
{
    ssize_t ret;
    struct thread *thread = current_thread ?: get_thread_from_tid(current->pid);

    if(copy_from_user( &thread->wake_info, buf, sizeof(struct wake_up_reply)))
    {
        klog(0,"error:cpoy_from_user \n");
        ret = -EFAULT;
    }
    else
    {
        ret = sizeof(struct wake_up_reply);
    }

    return ret;
}


static long syscall_chardev_unlocked_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
    int err = 0;
    int __user* argp = (int __user*)arg;

    if ( (cmd > Nt_MaxNum) || (cmd < Nt_None) )
    {
        klog(0,"error : bad syscall num\n");
        return STATUS_INVALID_PARAMETER;
    }

    uk_lock();
    switch (cmd) 
    {
        case Nt_None:
            break;
        case Nt_EarlyInit:
            err = NtEarlyInit(argp);
            break;
        case Nt_WineService:
            err = NtWineService(argp);
            break;
        case Nt_KillThread:
            err = NtKillThread(argp);
            break;
        case Nt_KillProcess:
            err = NtKillProcess(argp);
            break;
        default:
            break;
    }
    uk_unlock();

    return err;
}

static const struct file_operations syscall_chardev_fops =
{
    .open		= syscall_chardev_open,
    .release 	= syscall_chardev_release,
    .read       = syscall_chardev_read,
    .write      = syscall_chardev_write,
    .unlocked_ioctl = syscall_chardev_unlocked_ioctl,
};

static char *chardev_devnode(struct device *dev, umode_t *mode)
{
    if (mode)
        *mode = 0666;

    return NULL;
}

int create_syscall_chardev(void)
{
    const char filename[]="syscall";
    int ret;

    chardev = cdev_alloc();
    if(chardev == NULL)
    {
        klog(0,"cdev_alloc error: no memory \n");
        return -ENOMEM;
    }

    ret = alloc_chrdev_region(&devno, 0, 1, filename);
    if(ret < 0)
    {
        klog(0,"alloc_chrdev_region error %d\n",ret);
        goto bad_alloc_chrdev_region;
    }

    class = class_create(NULL, filename);
    if(IS_ERR(class))
    {
        ret = PTR_ERR(class);
        klog(0,"class_create error %d\n",ret);
        goto bad_class_create;
    }

    class->devnode = chardev_devnode;
    dev = device_create(class, NULL, devno, NULL, filename);/*create /dev/syscall*/
    if (IS_ERR(dev))
    {
        ret = PTR_ERR(dev);
        klog(0,"device_create error %d\n",ret);
        goto bad_device_create;
    }

    cdev_init(chardev, &syscall_chardev_fops);
    ret = cdev_add(chardev, devno, 1);
    if(ret < 0)
    {
        klog(0,"cdev_add error %d\n",ret);
        goto bad_cdev_add;
    }

    return 0;

bad_cdev_add:
    device_destroy(class, devno);
bad_device_create:
    class_destroy(class);
bad_class_create:
    unregister_chrdev_region(devno, 1);
bad_alloc_chrdev_region:
    kfree(chardev);
    return ret;
}

void destroy_syscall_chardev(void)
{
    device_destroy(class, devno); /* destroy device first */
    class_destroy(class);
    unregister_chrdev_region(devno, 1);
    kfree(chardev);
}
#endif
