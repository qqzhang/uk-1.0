/*
 * Server-side semaphore management
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

struct uk_semaphore
{
    struct object  obj;    /* object header */
    unsigned int   count;  /* current_thread count */
    unsigned int   max;    /* maximum possible count */
};

static void semaphore_dump( struct object *obj, int verbose );
static struct object_type *semaphore_get_type( struct object *obj );
static int semaphore_signaled( struct object *obj, struct wait_queue_entry *entry );
static void semaphore_satisfied( struct object *obj, struct wait_queue_entry *entry );
static unsigned int semaphore_map_access( struct object *obj, unsigned int access );
static int semaphore_signal( struct object *obj, unsigned int access );

static const struct object_ops semaphore_ops =
{
    sizeof(struct uk_semaphore),      /* size */
    semaphore_dump,                /* dump */
    semaphore_get_type,            /* get_type */
    add_queue,                     /* add_queue */
    remove_queue,                  /* remove_queue */
    semaphore_signaled,            /* signaled */
    semaphore_satisfied,           /* satisfied */
    semaphore_signal,              /* signal */
    no_get_fd,                     /* get_fd */
    semaphore_map_access,          /* map_access */
    default_get_sd,                /* get_sd */
    default_set_sd,                /* set_sd */
    no_lookup_name,                /* lookup_name */
    no_open_file,                  /* open_file */
    no_close_handle,               /* close_handle */
    no_destroy                     /* destroy */
};


static struct uk_semaphore *create_semaphore( struct directory *root, const struct unicode_str *name,
                                           unsigned int attr, unsigned int initial, unsigned int max,
                                           const struct security_descriptor *sd )
{
    struct uk_semaphore *sem;

    if (!max || (initial > max))
    {
        set_error( STATUS_INVALID_PARAMETER );
        return NULL;
    }
    if ((sem = create_named_object_dir( root, name, attr, &semaphore_ops )))
    {
        if (get_error() != STATUS_OBJECT_NAME_EXISTS)
        {
            /* initialize it if it didn't already exist */
            sem->count = initial;
            sem->max   = max;
            if (sd) default_set_sd( &sem->obj, sd, OWNER_SECURITY_INFORMATION|
                                                   GROUP_SECURITY_INFORMATION|
                                                   DACL_SECURITY_INFORMATION|
                                                   SACL_SECURITY_INFORMATION );
        }
    }
    return sem;
}

static int release_semaphore( struct uk_semaphore *sem, unsigned int count,
                              unsigned int *prev )
{
    if (prev) *prev = sem->count;
    if (sem->count + count < sem->count || sem->count + count > sem->max)
    {
        set_error( STATUS_SEMAPHORE_LIMIT_EXCEEDED );
        return 0;
    }
    else if (sem->count)
    {
        /* there cannot be any thread to wake up if the count is != 0 */
        sem->count += count;
    }
    else
    {
        sem->count = count;
        uk_wake_up( &sem->obj, count );
    }
    return 1;
}

static void semaphore_dump( struct object *obj, int verbose )
{
    struct uk_semaphore *sem = (struct uk_semaphore *)obj;
    assert( obj->ops == &semaphore_ops );
    fprintf( stderr, "Semaphore count=%d max=%d ", sem->count, sem->max );
    dump_object_name( &sem->obj );
    fputc( '\n', stderr );
}

static struct object_type *semaphore_get_type( struct object *obj )
{
    static const WCHAR name[] = {'S','e','m','a','p','h','o','r','e'};
    static const struct unicode_str str = { name, sizeof(name) };
    return get_object_type( &str );
}

static int semaphore_signaled( struct object *obj, struct wait_queue_entry *entry )
{
    struct uk_semaphore *sem = (struct uk_semaphore *)obj;
    assert( obj->ops == &semaphore_ops );
    return (sem->count > 0);
}

static void semaphore_satisfied( struct object *obj, struct wait_queue_entry *entry )
{
    struct uk_semaphore *sem = (struct uk_semaphore *)obj;
    assert( obj->ops == &semaphore_ops );
    assert( sem->count );
    sem->count--;
}

static unsigned int semaphore_map_access( struct object *obj, unsigned int access )
{
    if (access & GENERIC_READ)    access |= STANDARD_RIGHTS_READ | SYNCHRONIZE;
    if (access & GENERIC_WRITE)   access |= STANDARD_RIGHTS_WRITE | SEMAPHORE_MODIFY_STATE;
    if (access & GENERIC_EXECUTE) access |= STANDARD_RIGHTS_EXECUTE;
    if (access & GENERIC_ALL)     access |= STANDARD_RIGHTS_ALL | SEMAPHORE_ALL_ACCESS;
    return access & ~(GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL);
}

static int semaphore_signal( struct object *obj, unsigned int access )
{
    struct uk_semaphore *sem = (struct uk_semaphore *)obj;
    assert( obj->ops == &semaphore_ops );

    if (!(access & SEMAPHORE_MODIFY_STATE))
    {
        set_error( STATUS_ACCESS_DENIED );
        return 0;
    }
    return release_semaphore( sem, 1, NULL );
}

/* create a semaphore */
DECL_HANDLER(create_semaphore)
{
    struct uk_semaphore *sem;
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

    if ((sem = create_semaphore( root, &name, req->attributes, req->initial, req->max, sd )))
    {
        if (get_error() == STATUS_OBJECT_NAME_EXISTS)
            reply->handle = alloc_handle( current_thread->process, sem, req->access, req->attributes );
        else
            reply->handle = alloc_handle_no_access_check( current_thread->process, sem, req->access, req->attributes );
        release_object( sem );
    }

    if (root) release_object( root );
}

/* open a handle to a semaphore */
DECL_HANDLER(open_semaphore)
{
    struct unicode_str name;
    struct directory *root = NULL;
    struct uk_semaphore *sem;

    get_req_unicode_str( &name );
    if (req->rootdir && !(root = get_directory_obj( current_thread->process, req->rootdir, 0 )))
        return;

    if ((sem = open_object_dir( root, &name, req->attributes, &semaphore_ops )))
    {
        reply->handle = alloc_handle( current_thread->process, &sem->obj, req->access, req->attributes );
        release_object( sem );
    }

    if (root) release_object( root );
}

/* release a semaphore */
DECL_HANDLER(release_semaphore)
{
    struct uk_semaphore *sem;

    if ((sem = (struct uk_semaphore *)get_handle_obj( current_thread->process, req->handle,
                                                   SEMAPHORE_MODIFY_STATE, &semaphore_ops )))
    {
        release_semaphore( sem, req->count, &reply->prev_count );
        release_object( sem );
    }
}

/* query details about the semaphore */
DECL_HANDLER(query_semaphore)
{
    struct uk_semaphore *sem;

    if ((sem = (struct uk_semaphore *)get_handle_obj( current_thread->process, req->handle,
                                                   SEMAPHORE_QUERY_STATE, &semaphore_ops )))
    {
        reply->current_count = sem->count;
        reply->max = sem->max;
        release_object( sem );
    }
}
