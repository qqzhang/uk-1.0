/*
 * Unicode routines for use inside the server
 *
 * Copyright (C) 1999 Alexandre Julliard
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

#ifndef __WINE_SERVER_UNICODE_H
#define __WINE_SERVER_UNICODE_H

#include <stdio.h>

#include "windef.h"
#include "wine/unicode.h"
#include "object.h"

static inline WCHAR *strdupW( const WCHAR *str )
{
    size_t len = (strlenW(str) + 1) * sizeof(WCHAR);
    return memdup( str, len );
}

extern int parse_strW( WCHAR *buffer, data_size_t *len, const char *src, char endchar );
extern int dump_strW( const WCHAR *str, data_size_t len, FILE *f, const char escape[2] );

#endif  /* __WINE_SERVER_UNICODE_H */
