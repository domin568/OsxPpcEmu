/*-
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 1990, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * Copyright (c) 2011 The FreeBSD Foundation
 *
 * Copyright (c) 2023 Dag-Erling Smørgrav
 *
 * Portions of this software were developed by David Chisnall
 * under sponsorship from the FreeBSD Foundation.
 *
 * This code is derived from software contributed to Berkeley by
 * Chris Torek.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * Origin: FreeBSD src, lib/libc/stdio/vfscanf.c @ 8e6843db9bc
 */
// Modified by domin568:

#include "scanf.h"
#include <ctype.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h> // EOF
#include <stdlib.h>
#include <string.h>

#define BUF 513 /* Maximum length of numeric string. */

/* Flags used during conversion. */
#define LONG 0x01      /* l: long or double */
#define LONGDBL 0x02   /* L: long double */
#define SHORT 0x04     /* h: short */
#define SUPPRESS 0x08  /* *: suppress assignment */
#define POINTER 0x10   /* p: void * (as hex) */
#define NOSKIP 0x20    /* [ or c: do not skip blanks */
#define LONGLONG 0x400 /* ll: long long (+ deprecated q: quad) */
#define INTMAXT 0x800  /* j: intmax_t */
#define PTRDIFFT 0x1000
#define SIZET 0x2000
#define SHORTSHORT 0x4000
#define UNSIGNED 0x8000 /* %[oupxX] conversions */

/* Conversion types. */
#define CT_CHAR 0
#define CT_CCL 1
#define CT_STRING 2
#define CT_INT 3
#define CT_FLOAT 4

static const int suppress;
#define SUPPRESS_PTR ( (void *)&suppress )

/* Cursor over the string being scanned; replaces FILE. */
typedef struct
{
    const unsigned char *p;
    size_t r; // characters remaining
} instr_t;

static inline int s_getc( instr_t *s )
{
    return s->r ? ( s->r--, *s->p++ ) : EOF;
}

static inline void s_ungetc( int c, instr_t *s )
{
    if (c != EOF)
    {
        s->p--;
        s->r++;
    }
}

/*
 * The following conversion functions return the number of characters consumed,
 * or -1 on input failure. Character class conversion returns 0 on match failure.
 */

static int convert_char( instr_t *s, char *p, int width )
{
    if (p == SUPPRESS_PTR)
    {
        size_t sum = 0;
        while (width-- && s->r)
        {
            s->p++;
            s->r--;
            sum++;
        }
        return sum ? (int)sum : -1;
    }
    else
    {
        if (s->r == 0)
            return -1;
        size_t n = width < (int)s->r ? (size_t)width : s->r;
        memcpy( p, s->p, n );
        s->p += n;
        s->r -= n;
        return (int)n;
    }
}

static int convert_ccl( instr_t *s, char *p, int width, const char *ccltab )
{
    char *p0 = p;
    int n = 0;

    if (p == SUPPRESS_PTR)
    {
        while (s->r && ccltab[*s->p])
        {
            n++;
            s->p++;
            s->r--;
            if (--width == 0)
                break;
        }
    }
    else
    {
        while (s->r && ccltab[*s->p])
        {
            *p++ = *s->p++;
            s->r--;
            if (--width == 0)
                break;
        }
        n = (int)( p - p0 );
        if (n == 0)
            return 0;
        *p = 0;
    }
    return n;
}

static int convert_string( instr_t *s, char *p, int width )
{
    char *p0 = p;
    int n;

    if (p == SUPPRESS_PTR)
    {
        n = 0;
        while (s->r && !isspace( *s->p ))
        {
            n++;
            s->p++;
            s->r--;
            if (--width == 0)
                break;
        }
    }
    else
    {
        while (s->r && !isspace( *s->p ))
        {
            *p++ = *s->p++;
            s->r--;
            if (--width == 0)
                break;
        }
        *p = 0;
        n = (int)( p - p0 );
    }
    return n;
}

enum parseint_state
{
    begin,
    havesign,
    havezero,
    haveprefix,
    any,
};

static int parseint_fsm( int c, enum parseint_state *state, int *base )
{
    switch (c)
    {
    case '+':
    case '-':
        if (*state == begin)
        {
            *state = havesign;
            return 1;
        }
        break;
    case '0':
        if (*state == begin || *state == havesign)
        {
            *state = havezero;
            return 1;
        }
        /* FALLTHROUGH */
    case '1':
    case '2':
    case '3':
    case '4':
    case '5':
    case '6':
    case '7':
        if (*state == havezero && *base == 0)
            *base = 8;
        /* FALLTHROUGH */
    case '8':
    case '9':
        if (*state == begin || *state == havesign)
        {
            if (*base == 0)
                *base = 10;
        }
        if (*state == begin || *state == havesign || *state == havezero || *state == haveprefix || *state == any)
        {
            if (*base > c - '0')
            {
                *state = any;
                return 1;
            }
        }
        break;
    case 'b':
        if (*state == havezero && ( *base == 0 || *base == 2 ))
        {
            *state = haveprefix;
            *base = 2;
            return 1;
        }
        /* FALLTHROUGH */
    case 'a':
    case 'c':
    case 'd':
    case 'e':
    case 'f':
        if (*state == begin || *state == havesign || *state == havezero || *state == haveprefix || *state == any)
        {
            if (*base > c - 'a' + 10)
            {
                *state = any;
                return 1;
            }
        }
        break;
    case 'B':
        if (*state == havezero && ( *base == 0 || *base == 2 ))
        {
            *state = haveprefix;
            *base = 2;
            return 1;
        }
        /* FALLTHROUGH */
    case 'A':
    case 'C':
    case 'D':
    case 'E':
    case 'F':
        if (*state == begin || *state == havesign || *state == havezero || *state == haveprefix || *state == any)
        {
            if (*base > c - 'A' + 10)
            {
                *state = any;
                return 1;
            }
        }
        break;
    case 'x':
    case 'X':
        if (*state == havezero && ( *base == 0 || *base == 16 ))
        {
            *state = haveprefix;
            *base = 16;
            return 1;
        }
        break;
    }
    return 0;
}

/* Read an integer into buf. Returns 0 on match failure, chars read otherwise. */
static int parseint( instr_t *s, char *buf, int width, int base )
{
    enum parseint_state state = begin;
    char *p;
    int c = EOF;

    for (p = buf; width; width--)
    {
        c = s_getc( s );
        if (c == EOF)
            break;
        if (!parseint_fsm( c, &state, &base ))
            break;
        *p++ = (char)c;
    }
    /*
     * If we only had a sign, or only had a 0b/0x prefix, push back the
     * offending character(s); same for a trailing non-number character.
     */
    if (state == havesign)
    {
        p--;
        s_ungetc( (unsigned char)*p, s );
    }
    else if (state == haveprefix)
    {
        p--;
        s_ungetc( c, s );
    }
    else if (width && c != EOF)
    {
        s_ungetc( c, s );
    }
    return (int)( p - buf );
}

/*
 * Fill in the given table from the scanset at the given format (just after
 * `['). Return a pointer to the character past the closing `]'.
 */
static const unsigned char *sccl( char *tab, const unsigned char *fmt )
{
    int c, n, v;

    c = *fmt++;
    int negate = 0;
    if (c == '^')
    {
        negate = 1;
        c = *fmt++;
    }

    memset( tab, negate, 256 );

    if (c == 0)
        return fmt - 1;

    v = 1 - negate;
    for (;;)
    {
        tab[c] = (char)v;
    doswitch:
        n = *fmt++;
        switch (n)
        {
        case 0:
            return fmt - 1;

        case '-':
            n = *fmt;
            if (n == ']' || n < c)
            {
                c = '-';
                break;
            }
            fmt++;
            do
            {
                tab[++c] = (char)v;
            } while (c < n);
            c = n;
            goto doswitch;

        case ']':
            return fmt;

        default:
            c = n;
            break;
        }
    }
}

static int parsefloat( instr_t *s, char *buf, char *end )
{
    char *commit, *p;
    int infnanpos = 0;
    enum
    {
        S_START,
        S_GOTSIGN,
        S_INF,
        S_NAN,
        S_DONE,
        S_MAYBEHEX,
        S_DIGITS,
        S_DECPT,
        S_FRAC,
        S_EXP,
        S_EXPDIGITS
    } state = S_START;
    unsigned char c;
    int gotmantdig = 0, ishex = 0;

    commit = buf - 1;
    for (p = buf; p < end && s->r;)
    {
        c = *s->p;
    reswitch:
        switch (state)
        {
        case S_START:
            state = S_GOTSIGN;
            if (c == '-' || c == '+')
                break;
            else
                goto reswitch;
        case S_GOTSIGN:
            switch (c)
            {
            case '0':
                state = S_MAYBEHEX;
                commit = p;
                break;
            case 'I':
            case 'i':
                state = S_INF;
                break;
            case 'N':
            case 'n':
                state = S_NAN;
                break;
            default:
                state = S_DIGITS;
                goto reswitch;
            }
            break;
        case S_INF:
            if (infnanpos > 6 || ( c != "nfinity"[infnanpos] && c != "NFINITY"[infnanpos] ))
                goto parsedone;
            if (infnanpos == 1 || infnanpos == 6)
                commit = p;
            infnanpos++;
            break;
        case S_NAN:
            switch (infnanpos)
            {
            case 0:
                if (c != 'A' && c != 'a')
                    goto parsedone;
                break;
            case 1:
                if (c != 'N' && c != 'n')
                    goto parsedone;
                else
                    commit = p;
                break;
            case 2:
                if (c != '(')
                    goto parsedone;
                break;
            default:
                if (c == ')')
                {
                    commit = p;
                    state = S_DONE;
                }
                else if (!isalnum( c ) && c != '_')
                    goto parsedone;
                break;
            }
            infnanpos++;
            break;
        case S_DONE:
            goto parsedone;
        case S_MAYBEHEX:
            state = S_DIGITS;
            if (c == 'X' || c == 'x')
            {
                ishex = 1;
                break;
            }
            else
            {
                gotmantdig = 1;
                goto reswitch;
            }
        case S_DIGITS:
            if (( ishex && isxdigit( c ) ) || isdigit( c ))
            {
                gotmantdig = 1;
                commit = p;
                break;
            }
            else
            {
                state = S_DECPT;
                goto reswitch;
            }
        case S_DECPT:
            if (c == '.')
            {
                state = S_FRAC;
                if (gotmantdig)
                    commit = p;
                break;
            }
            else
            {
                state = S_FRAC;
                goto reswitch;
            }
        case S_FRAC:
            if (( ( c == 'E' || c == 'e' ) && !ishex ) || ( ( c == 'P' || c == 'p' ) && ishex ))
            {
                if (!gotmantdig)
                    goto parsedone;
                else
                    state = S_EXP;
            }
            else if (( ishex && isxdigit( c ) ) || isdigit( c ))
            {
                commit = p;
                gotmantdig = 1;
            }
            else
                goto parsedone;
            break;
        case S_EXP:
            state = S_EXPDIGITS;
            if (c == '-' || c == '+')
                break;
            else
                goto reswitch;
        case S_EXPDIGITS:
            if (isdigit( c ))
                commit = p;
            else
                goto parsedone;
            break;
        default:
            abort();
        }
        *p++ = (char)c;
        s->p++;
        s->r--;
    }

parsedone:
    while (commit < --p)
        s_ungetc( (unsigned char)*p, s );
    *++commit = '\0';
    return (int)( commit - buf );
}

static int svfscanf( instr_t *s, const char *fmt0, const uint64_t *args )
{
#define GETARG( type ) ( ( flags & SUPPRESS ) ? SUPPRESS_PTR : (type)(uintptr_t)args[argIdx++] )
#define NEXTARG( type ) ( (type)(uintptr_t)args[argIdx++] )
    const unsigned char *fmt = (const unsigned char *)fmt0;
    int c;
    size_t width;
    int flags;
    int nassigned = 0;
    int nconversions = 0;
    int nread = 0;
    int base = 0;
    size_t argIdx = 0;
    char ccltab[256];
    char buf[BUF];

    for (;;)
    {
        c = *fmt++;
        if (c == 0)
            return nassigned;
        if (isspace( c ))
        {
            while (s->r && isspace( *s->p ))
                nread++, s->r--, s->p++;
            continue;
        }
        if (c != '%')
            goto literal;
        width = 0;
        flags = 0;
    again:
        c = *fmt++;
        switch (c)
        {
        case '%':
        literal:
            if (s->r == 0)
                goto input_failure;
            if (*s->p != c)
                goto match_failure;
            s->r--, s->p++;
            nread++;
            continue;

        case '*':
            flags |= SUPPRESS;
            goto again;
        case 'j':
            flags |= INTMAXT;
            goto again;
        case 'l':
            if (flags & LONG)
            {
                flags &= ~LONG;
                flags |= LONGLONG;
            }
            else
                flags |= LONG;
            goto again;
        case 'q':
            flags |= LONGLONG;
            goto again;
        case 't':
            flags |= PTRDIFFT;
            goto again;
        case 'z':
            flags |= SIZET;
            goto again;
        case 'L':
            flags |= LONGDBL;
            goto again;
        case 'h':
            if (flags & SHORT)
            {
                flags &= ~SHORT;
                flags |= SHORTSHORT;
            }
            else
                flags |= SHORT;
            goto again;

        case '0':
        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7':
        case '8':
        case '9':
            width = width * 10 + c - '0';
            goto again;

        /* Conversions. */
        case 'B':
        case 'b':
            c = CT_INT;
            flags |= UNSIGNED;
            base = 2;
            break;
        case 'd':
            c = CT_INT;
            base = 10;
            break;
        case 'i':
            c = CT_INT;
            base = 0;
            break;
        case 'o':
            c = CT_INT;
            flags |= UNSIGNED;
            base = 8;
            break;
        case 'u':
            c = CT_INT;
            flags |= UNSIGNED;
            base = 10;
            break;
        case 'X':
        case 'x':
            c = CT_INT;
            flags |= UNSIGNED;
            base = 16;
            break;
        case 'A':
        case 'E':
        case 'F':
        case 'G':
        case 'a':
        case 'e':
        case 'f':
        case 'g':
            c = CT_FLOAT;
            break;
        case 's':
        case 'S': // treated as narrow, guest MSL runtime has no wide chars
            c = CT_STRING;
            break;
        case '[':
            fmt = sccl( ccltab, fmt );
            flags |= NOSKIP;
            c = CT_CCL;
            break;
        case 'c':
        case 'C':
            flags |= NOSKIP;
            c = CT_CHAR;
            break;
        case 'p': /* pointer format is like hex */
            flags |= POINTER;
            c = CT_INT;
            flags |= UNSIGNED;
            base = 16;
            break;
        case 'n':
            if (flags & SUPPRESS)
                continue;
            if (flags & SHORTSHORT)
                *NEXTARG( char * ) = (char)nread;
            else if (flags & SHORT)
                *NEXTARG( short * ) = (short)nread;
            else if (flags & LONG)
                *NEXTARG( long * ) = nread;
            else if (flags & LONGLONG)
                *NEXTARG( long long * ) = nread;
            else if (flags & INTMAXT)
                *NEXTARG( intmax_t * ) = nread;
            else if (flags & SIZET)
                *NEXTARG( size_t * ) = nread;
            else if (flags & PTRDIFFT)
                *NEXTARG( ptrdiff_t * ) = nread;
            else
                *NEXTARG( int * ) = nread;
            continue;

        default:
            goto match_failure;

        case '\0': /* compat */
            return EOF;
        }

        /* We have a conversion that requires input. */
        if (s->r == 0)
            goto input_failure;

        if (( flags & NOSKIP ) == 0)
        {
            while (s->r && isspace( *s->p ))
            {
                nread++;
                s->r--;
                s->p++;
            }
            if (s->r == 0)
                goto input_failure;
        }

        int nr;
        switch (c)
        {
        case CT_CHAR:
            if (width == 0)
                width = 1;
            nr = convert_char( s, GETARG( char * ), (int)width );
            if (nr < 0)
                goto input_failure;
            break;

        case CT_CCL:
            if (width == 0)
                width = (size_t)~0;
            nr = convert_ccl( s, GETARG( char * ), (int)width, ccltab );
            if (nr <= 0)
            {
                if (nr < 0)
                    goto input_failure;
                else
                    goto match_failure;
            }
            break;

        case CT_STRING:
            if (width == 0)
                width = (size_t)~0;
            nr = convert_string( s, GETARG( char * ), (int)width );
            if (nr < 0)
                goto input_failure;
            break;

        case CT_INT:
            if (--width > sizeof( buf ) - 2)
                width = sizeof( buf ) - 2;
            width++;
            nr = parseint( s, buf, (int)width, base );
            if (nr == 0)
                goto match_failure;
            if (( flags & SUPPRESS ) == 0)
            {
                uintmax_t res;
                buf[nr] = '\0';
                if (( flags & UNSIGNED ) == 0)
                    res = (uintmax_t)strtoimax( buf, NULL, base );
                else
                    res = strtoumax( buf, NULL, base );
                if (flags & POINTER)
                    *NEXTARG( void ** ) = (void *)(uintptr_t)res;
                else if (flags & SHORTSHORT)
                    *NEXTARG( char * ) = (char)res;
                else if (flags & SHORT)
                    *NEXTARG( short * ) = (short)res;
                else if (flags & LONG)
                    *NEXTARG( long * ) = (long)res;
                else if (flags & LONGLONG)
                    *NEXTARG( long long * ) = (long long)res;
                else if (flags & INTMAXT)
                    *NEXTARG( intmax_t * ) = res;
                else if (flags & PTRDIFFT)
                    *NEXTARG( ptrdiff_t * ) = (ptrdiff_t)res;
                else if (flags & SIZET)
                    *NEXTARG( size_t * ) = (size_t)res;
                else
                    *NEXTARG( int * ) = (int)res;
            }
            break;

        case CT_FLOAT:
            if (width == 0 || width > sizeof( buf ) - 1)
                width = sizeof( buf ) - 1;
            nr = parsefloat( s, buf, buf + width );
            if (nr == 0)
                goto match_failure;
            if (( flags & SUPPRESS ) == 0)
            {
                if (flags & LONGDBL)
                    *NEXTARG( long double * ) = strtold( buf, NULL );
                else if (flags & LONG)
                    *NEXTARG( double * ) = strtod( buf, NULL );
                else
                    *NEXTARG( float * ) = strtof( buf, NULL );
            }
            break;
        default:
            nr = 0;
            break;
        }
        if (!( flags & SUPPRESS ))
            nassigned++;
        nread += nr;
        nconversions++;
    }
input_failure:
    return nconversions != 0 ? nassigned : EOF;
match_failure:
    return nassigned;
#undef GETARG
#undef NEXTARG
}

int vsscanf_( const char *str, const char *format, const uint64_t *args )
{
    instr_t s = { (const unsigned char *)str, strlen( str ) };
    return svfscanf( &s, format, args );
}

