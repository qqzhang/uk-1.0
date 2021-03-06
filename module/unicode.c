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

#include "config.h"
#include "wine/port.h"

#include <ctype.h>
#include <stdio.h>

#include "unicode.h"

/* number of following bytes in sequence based on first byte value (for bytes above 0x7f) */
static const char utf8_length[128] =
{
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, /* 0x80-0x8f */
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, /* 0x90-0x9f */
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, /* 0xa0-0xaf */
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, /* 0xb0-0xbf */
    0,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1, /* 0xc0-0xcf */
    1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1, /* 0xd0-0xdf */
    2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2, /* 0xe0-0xef */
    3,3,3,3,3,0,0,0,0,0,0,0,0,0,0,0  /* 0xf0-0xff */
};

/* first byte mask depending on UTF-8 sequence length */
static const unsigned char utf8_mask[4] = { 0x7f, 0x1f, 0x0f, 0x07 };

/* minimum Unicode value depending on UTF-8 sequence length */
static const unsigned int utf8_minval[4] = { 0x0, 0x80, 0x800, 0x10000 };

static inline char to_hex( char ch )
{
    if (isdigit(ch)) return ch - '0';
    return tolower(ch) - 'a' + 10;
}

/* parse an escaped string back into Unicode */
/* return the number of chars read from the input, or -1 on output overflow */
int parse_strW( WCHAR *buffer, data_size_t *len, const char *src, char endchar )
{
    WCHAR *dest = buffer;
    WCHAR *end = buffer + *len / sizeof(WCHAR);
    const char *p = src;
    unsigned char ch;

    while (*p && *p != endchar && dest < end)
    {
        if (*p == '\\')
        {
            p++;
            if (!*p) break;
            switch(*p)
            {
            case 'a': *dest++ = '\a'; p++; continue;
            case 'b': *dest++ = '\b'; p++; continue;
            case 'e': *dest++ = '\e'; p++; continue;
            case 'f': *dest++ = '\f'; p++; continue;
            case 'n': *dest++ = '\n'; p++; continue;
            case 'r': *dest++ = '\r'; p++; continue;
            case 't': *dest++ = '\t'; p++; continue;
            case 'v': *dest++ = '\v'; p++; continue;
            case 'x':  /* hex escape */
                p++;
                if (!isxdigit(*p)) *dest = 'x';
                else
                {
                    *dest = to_hex(*p++);
                    if (isxdigit(*p)) *dest = (*dest * 16) + to_hex(*p++);
                    if (isxdigit(*p)) *dest = (*dest * 16) + to_hex(*p++);
                    if (isxdigit(*p)) *dest = (*dest * 16) + to_hex(*p++);
                }
                dest++;
                continue;
            case '0':
            case '1':
            case '2':
            case '3':
            case '4':
            case '5':
            case '6':
            case '7':  /* octal escape */
                *dest = *p++ - '0';
                if (*p >= '0' && *p <= '7') *dest = (*dest * 8) + (*p++ - '0');
                if (*p >= '0' && *p <= '7') *dest = (*dest * 8) + (*p++ - '0');
                dest++;
                continue;
            }
            /* unrecognized escape: fall through to normal char handling */
        }


        ch = *p++;
        if (ch < 0x80) *dest++ = ch;
        else  /* parse utf8 char */
        {
            int charlen = utf8_length[ch-0x80];
            unsigned int res = ch & utf8_mask[charlen];

            switch(charlen)
            {
            case 3:
                if ((ch = *p ^ 0x80) >= 0x40) break;
                res = (res << 6) | ch;
                p++;
            case 2:
                if ((ch = *p ^ 0x80) >= 0x40) break;
                res = (res << 6) | ch;
                p++;
            case 1:
                if ((ch = *p ^ 0x80) >= 0x40) break;
                res = (res << 6) | ch;
                p++;
                if (res < utf8_minval[charlen]) break;
                if (res > 0x10ffff) break;
                if (res <= 0xffff) *dest++ = res;
                else /* we need surrogates */
                {
                    res -= 0x10000;
                    *dest++ = 0xd800 | (res >> 10);
                    if (dest < end) *dest++ = 0xdc00 | (res & 0x3ff);
                }
                continue;
            }
            /* ignore invalid char */
        }
    }
    if (dest >= end) return -1;  /* overflow */
    *dest++ = 0;
    if (!*p) return -1;  /* delimiter not found */
    *len = (dest - buffer) * sizeof(WCHAR);
    return p + 1 - src;
}

/* dump a Unicode string with proper escaping */
int dump_strW( const WCHAR *str, data_size_t len, FILE *f, const char escape[2] )
{
    static const char escapes[32] = ".......abtnvfr.............e....";
    char buffer[256];
    char *pos = buffer;
    int count = 0;

    for (; len; str++, len--)
    {
        if (pos > buffer + sizeof(buffer) - 8)
        {
            fwrite( buffer, pos - buffer, 1, f );
            count += pos - buffer;
            pos = buffer;
        }
        if (*str > 127)  /* hex escape */
        {
            if (len > 1 && str[1] < 128 && isxdigit((char)str[1]))
                pos += sprintf( pos, "\\x%04x", *str );
            else
                pos += sprintf( pos, "\\x%x", *str );
            continue;
        }
        if (*str < 32)  /* octal or C escape */
        {
            if (!*str && len == 1) continue;  /* do not output terminating NULL */
            if (escapes[*str] != '.')
                pos += sprintf( pos, "\\%c", escapes[*str] );
            else if (len > 1 && str[1] >= '0' && str[1] <= '7')
                pos += sprintf( pos, "\\%03o", *str );
            else
                pos += sprintf( pos, "\\%o", *str );
            continue;
        }
        if (*str == '\\' || *str == escape[0] || *str == escape[1]) *pos++ = '\\';
        *pos++ = *str;
    }
    fwrite( buffer, pos - buffer, 1, f );
    count += pos - buffer;
    return count;
}
