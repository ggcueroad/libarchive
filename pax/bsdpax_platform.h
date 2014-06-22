/*-
 * Copyright (c) 2003-2007 Tim Kientzle
 * Copyright (c) 2011-2012 Michihiro NAKAJIMA
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR(S) ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR(S) BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $FreeBSD$
 */

/*
 * This header is the first thing included in any of the bsdpax
 * source files.  As far as possible, platform-specific issues should
 * be dealt with here and not within individual source files.
 */

#ifndef BSDPAX_PLATFORM_H_INCLUDED
#define	BSDPAX_PLATFORM_H_INCLUDED

#if defined(PLATFORM_CONFIG_H)
/* Use hand-built config.h in environments that need it. */
#include PLATFORM_CONFIG_H
#else
/* Not having a config.h of some sort is a serious problem. */
#include "config.h"
#endif

#if defined(_WIN32) && !defined(__CYGWIN__)
#include "bsdpax_windows.h"
#endif

/* Get a real definition for __FBSDID if we can */
#if HAVE_SYS_CDEFS_H
#include <sys/cdefs.h>
#endif

/* If not, define it so as to avoid dangling semicolons. */
#ifndef __FBSDID
#define	__FBSDID(a)     struct _undefined_hack
#endif

#ifdef HAVE_LIBARCHIVE
/* If we're using the platform libarchive, include system headers. */
#include <archive.h>
#include <archive_entry.h>
#else
/* Otherwise, include user headers. */
#include "archive.h"
#include "archive_entry.h"
#endif

/* How to mark functions that don't return. */
/* This facilitates use of some newer static code analysis tools. */
#undef __LA_DEAD
#if defined(__GNUC__) && (__GNUC__ > 2 || \
			  (__GNUC__ == 2 && __GNUC_MINOR__ >= 5))
#define	__LA_DEAD	__attribute__((__noreturn__))
#else
#define	__LA_DEAD
#endif

/* Borland warns about its own constants!  */
#if defined(__BORLANDC__)
# if HAVE_DECL_UINT64_MIN
#  undef	UINT64_MIN
#  undef	HAVE_DECL_UINT64_MIN
# endif
# if HAVE_DECL_INT64_MAX
#  undef	INT64_MAX
#  undef	HAVE_DECL_INT64_MAX
# endif
#endif

/* Some platforms lack the standard *_MAX definitions. */
#if !HAVE_DECL_UINT64_MAX
#define	UINT64_MAX (~(uint64_t)0)
#endif
#if !HAVE_DECL_INT64_MAX
#define	INT64_MAX ((int64_t)(UINT64_MAX >> 1))
#endif

#endif /* !BSDPAX_PLATFORM_H_INCLUDED */
