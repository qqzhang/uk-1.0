/*
 * Server-side mutex management
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
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winternl.h"

#include "handle.h"
#include "thread.h"
#include "request.h"
#include "security.h"

struct uk_mutex
{
    struct object  obj;             /* object header */
    struct thread *owner;           /* mutex owner */
    unsigned int   count;           /* recursion count */
    int            abandoned;       /* has it been abandoned? */
    struct list_head    entry;           /* entry in owner thread mutex list */
};

static void mutex_dump( struct object *obj, int verbose );
static struct object_type *mutex_get_type( struct object *obj );
static int mutex_signaled( struct object *obj, struct wait_queue_entry *entry );
static void mutex_satisfied( struct object *obj, struct wait_queue_entry *entry );
static unsigned int mutex_map_access( struct object *obj, unsigned int access );
static void uk_mutex_destroy( struct object *obj );
static int mutex_signal( struct object *obj, unsigned int access );

static const struct object_ops mutex_ops =
{
    sizeof(struct uk_mutex),      /* size */
    mutex_dump,                /* dump */
    mutex_get_type,            /* get_type */
    add_queue,                 /* add_queue */
    remove_queue,              /* remove_queue */
    mutex_signaled,            /* signaled */
    mutex_satisfied,           /* satisfied */
    mutex_signal,              /* signal */
    no_get_fd,                 /* get_fd */
    mutex_map_access,          /* map_access */
    default_get_sd,            /* get_sd */
    default_set_sd,            /* set_sd */
    no_lookup_name,            /* lookup_name */
    no_open_file,              /* open_file */
    no_close_handle,           /* close_handle */
    uk_mutex_destroy              /* destroy */
};


/* grab a mutex for a given thread */
static void do_grab( struct uk_mutex *mutex, struct thread *thread )
{
    assert( !mutex->count || (mutex->owner == thread) );

    if (!mutex->count++)  /* FIXME: avoid wrap-around */
    {
        assert( !mutex->owner );
        mutex->owner = thread;
        wine_list_add_head( &thread->mutex_list, &mutex->entry );
    }
}

/* release a mutex once the recursion count is 0 */
static void do_release( struct uk_mutex *mutex )
{
    assert( !mutex->count );
    /* remove the mutex from the thread list of owned mutexes */
    list_remove( &mutex->entry );
    mutex->owner = NULL;
    uk_wake_up( &mutex->obj, 0 );
}

static struct uk_mutex *create_mutex( struct directory *root, const struct unicode_str *name,
                                   unsigned int attr, int owned, const struct security_descriptor *sd )
{
    struct uk_mutex *mutex;

    if ((mutex = create_named_object_dir( root, name, attr, &mutex_ops )))
    {
        if (get_error() != STATUS_OBJECT_NAME_EXISTS)
        {
            /* initialize it if it didn't already exist */
            mutex->count = 0;
            mutex->owner = NULL;
            mutex->abandoned = 0;
            if (owned) do_grab( mutex, current_thread );
            if (sd) default_set_sd( &mutex->obj, sd, OWNER_SECURITY_INFORMATION|
                                                     GROUP_SECURITY_INFORMATION|
                                                     DACL_SECURITY_INFORMATION|
                                                     SACL_SECURITY_INFORMATION );
        }
    }
    return mutex;
}

void abandon_mutexes( struct thread *thread )
{
    struct list_head *ptr;

    while ((ptr = list_head( &thread->mutex_list )) != NULL)
    {
        struct uk_mutex *mutex = LIST_ENTRY( ptr, struct uk_mutex, entry );
        assert( mutex->owner == thread );
        mutex->count = 0;
        mutex->abandoned = 1;
        do_release( mutex );
    }
}

static void mutex_dump( struct object *obj, int verbose )
{
    struct uk_mutex *mutex = (struct uk_mutex *)obj;
    assert( obj->ops == &mutex_ops );
    fprintf( stderr, "Mutex count=%u owner=%p ", mutex->count, mutex->owner );
    dump_object_name( &mutex->obj );
    fputc( '\n', stderr );
}

static struct object_type *mutex_get_type( struct object *obj )
{
    static const WCHAR name[] = {'M','u','t','a','n','t'};
    static const struct unicode_str str = { name, sizeof(name) };
    return get_object_type( &str );
}

static int mutex_signaled( struct object *obj, struct wait_queue_entry *entry )
{
    struct uk_mutex *mutex = (struct uk_mutex *)obj;
    assert( obj->ops == &mutex_ops );
    return (!mutex->count || (mutex->owner == get_wait_queue_thread( entry )));
}

static void mutex_satisfied( struct object *obj, struct wait_queue_entry *entry )
{
    struct uk_mutex *mutex = (struct uk_mutex *)obj;
    assert( obj->ops == &mutex_ops );

    do_grab( mutex, get_wait_queue_thread( entry ));
    if (mutex->abandoned) make_wait_abandoned( entry );
    mutex->abandoned = 0;
}

static unsigned int mutex_map_access( struct object *obj, unsigned int access )
{
    if (access & GENERIC_READ)    access |= STANDARD_RIGHTS_READ;
    if (access & GENERIC_WRITE)   access |= STANDARD_RIGHTS_WRITE;
    if (access & GENERIC_EXECUTE) access |= STANDARD_RIGHTS_EXECUTE | SYNCHRONIZE;
    if (access & GENERIC_ALL)     access |= STANDARD_RIGHTS_ALL | MUTEX_ALL_ACCESS;
    return access & ~(GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL);
}

static int mutex_signal( struct object *obj, unsigned int access )
{
    struct uk_mutex *mutex = (struct uk_mutex *)obj;
    assert( obj->ops == &mutex_ops );

    if (!(access & SYNCHRONIZE))
    {
        set_error( STATUS_ACCESS_DENIED );
        return 0;
    }
    if (!mutex->count || (mutex->owner != current_thread))
    {
        set_error( STATUS_MUTANT_NOT_OWNED );
        return 0;
    }
    if (!--mutex->count) do_release( mutex );
    return 1;
}

static void uk_mutex_destroy( struct object *obj )
{
    struct uk_mutex *mutex = (struct uk_mutex *)obj;
    assert( obj->ops == &mutex_ops );

    if (!mutex->count) return;
    mutex->count = 0;
    do_release( mutex );
}

/* create a mutex */
DECL_HANDLER(create_mutex)
{
    struct uk_mutex *mutex;
    struct unicode_str name;
    struct directory *root = NULL;
    const struct object_attributes *objattr = get_req_data();
    const struct security_descriptor *sd;

    reply->handle = 0;

    if (!objattr_is_valid( objattr, get_req_data_size() ))
        return;

    sd = objattr->sd_len ? (const struct security_descriptor *)(objattr + 1) : NULL;
    objattr_get_name( objattr, &name );

    if (objattr->rootdir && !(root = get_directory_obj( current_thread->process, objattr->rootdir, 0 )))
        return;

    if ((mutex = create_mutex( root, &name, req->attributes, req->owned, sd )))
    {
        if (get_error() == STATUS_OBJECT_NAME_EXISTS)
            reply->handle = alloc_handle( current_thread->process, mutex, req->access, req->attributes );
        else
            reply->handle = alloc_handle_no_access_check( current_thread->process, mutex, req->access, req->attributes );
        release_object( mutex );
    }

    if (root) release_object( root );
}

/* open a handle to a mutex */
DECL_HANDLER(open_mutex)
{
    struct unicode_str name;
    struct directory *root = NULL;
    struct uk_mutex *mutex;

    get_req_unicode_str( &name );
    if (req->rootdir && !(root = get_directory_obj( current_thread->process, req->rootdir, 0 )))
        return;

    if ((mutex = open_object_dir( root, &name, req->attributes, &mutex_ops )))
    {
        reply->handle = alloc_handle( current_thread->process, &mutex->obj, req->access, req->attributes );
        release_object( mutex );
    }

    if (root) release_object( root );
}

/* release a mutex */
DECL_HANDLER(release_mutex)
{
    struct uk_mutex *mutex;

    if ((mutex = (struct uk_mutex *)get_handle_obj( current_thread->process, req->handle,
                                                 0, &mutex_ops )))
    {
        if (!mutex->count || (mutex->owner != current_thread)) set_error( STATUS_MUTANT_NOT_OWNED );
        else
        {
            reply->prev_count = mutex->count;
            if (!--mutex->count) do_release( mutex );
        }
        release_object( mutex );
    }
}
