/*-
 * Copyright (c) 2003-2007 Tim Kientzle
 * Copyright (c) 2011 Michihiro NAKAJIMA
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
 */

#include "bsdpax_platform.h"
__FBSDID("$FreeBSD$");

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>  /* Linux doesn't define mode_t, etc. in sys/stat.h. */
#endif
#include <ctype.h>
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#ifdef HAVE_IO_H
#include <io.h>
#endif
#ifdef HAVE_STDARG_H
#include <stdarg.h>
#endif
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_WCTYPE_H
#include <wctype.h>
#else
/* If we don't have wctype, we need to hack up some version of iswprint(). */
#define	iswprint isprint
#endif

#include "bsdpax.h"
#include "err.h"

static size_t	bsdpax_expand_char(char *, size_t, char);
static const char *strip_components(const char *path, int elements);

#if defined(_WIN32) && !defined(__CYGWIN__)
#define	read _read
#endif

/* TODO:  Hack up a version of mbtowc for platforms with no wide
 * character support at all.  I think the following might suffice,
 * but it needs careful testing.
 * #if !HAVE_MBTOWC
 * #define	mbtowc(wcp, p, n) ((*wcp = *p), 1)
 * #endif
 */

/*
 * Print a string, taking care with any non-printable characters.
 *
 * Note that we use a stack-allocated buffer to receive the formatted
 * string if we can.  This is partly performance (avoiding a call to
 * malloc()), partly out of expedience (we have to call vsnprintf()
 * before malloc() anyway to find out how big a buffer we need; we may
 * as well point that first call at a small local buffer in case it
 * works), but mostly for safety (so we can use this to print messages
 * about out-of-memory conditions).
 */

void
safe_fprintf(FILE *f, const char *fmt, ...)
{
	char fmtbuff_stack[256]; /* Place to format the printf() string. */
	char outbuff[256]; /* Buffer for outgoing characters. */
	char *fmtbuff_heap; /* If fmtbuff_stack is too small, we use malloc */
	char *fmtbuff;  /* Pointer to fmtbuff_stack or fmtbuff_heap. */
	int fmtbuff_length;
	int length, n;
	va_list ap;
	const char *p;
	unsigned i;
	wchar_t wc;
	char try_wc;

	/* Use a stack-allocated buffer if we can, for speed and safety. */
	fmtbuff_heap = NULL;
	fmtbuff_length = sizeof(fmtbuff_stack);
	fmtbuff = fmtbuff_stack;

	/* Try formatting into the stack buffer. */
	va_start(ap, fmt);
	length = vsnprintf(fmtbuff, fmtbuff_length, fmt, ap);
	va_end(ap);

	/* If the result was too large, allocate a buffer on the heap. */
	while (length < 0 || length >= fmtbuff_length) {
		if (length >= fmtbuff_length)
			fmtbuff_length = length+1;
		else if (fmtbuff_length < 8192)
			fmtbuff_length *= 2;
		else {
			int old_length = fmtbuff_length;
			fmtbuff_length += fmtbuff_length / 4;
			if (old_length > fmtbuff_length) {
				length = old_length;
				fmtbuff_heap[length-1] = '\0';
				break;
			}
		}
		free(fmtbuff_heap);
		fmtbuff_heap = malloc(fmtbuff_length);

		/* Reformat the result into the heap buffer if we can. */
		if (fmtbuff_heap != NULL) {
			fmtbuff = fmtbuff_heap;
			va_start(ap, fmt);
			length = vsnprintf(fmtbuff, fmtbuff_length, fmt, ap);
			va_end(ap);
		} else {
			/* Leave fmtbuff pointing to the truncated
			 * string in fmtbuff_stack. */
			length = sizeof(fmtbuff_stack) - 1;
			break;
		}
	}

	/* Note: mbrtowc() has a cleaner API, but mbtowc() seems a bit
	 * more portable, so we use that here instead. */
	n = mbtowc(NULL, NULL, 1); /* Reset the shift state. */

	/* Write data, expanding unprintable characters. */
	p = fmtbuff;
	i = 0;
	try_wc = 1;
	while (*p != '\0') {

		/* Convert to wide char, test if the wide
		 * char is printable in the current locale. */
		if (try_wc && (n = mbtowc(&wc, p, length)) != -1) {
			length -= n;
			if (iswprint(wc) && wc != L'\\') {
				/* Printable, copy the bytes through. */
				while (n-- > 0)
					outbuff[i++] = *p++;
			} else {
				/* Not printable, format the bytes. */
				while (n-- > 0)
					i += (unsigned)bsdpax_expand_char(
					    outbuff, i, *p++);
			}
		} else {
			/* After any conversion failure, don't bother
			 * trying to convert the rest. */
			i += (unsigned)bsdpax_expand_char(outbuff, i, *p++);
			try_wc = 0;
		}

		/* If our output buffer is full, dump it and keep going. */
		if (i > (sizeof(outbuff) - 20)) {
			outbuff[i] = '\0';
			fprintf(f, "%s", outbuff);
			i = 0;
		}
	}
	outbuff[i] = '\0';
	fprintf(f, "%s", outbuff);

	/* If we allocated a heap-based formatting buffer, free it now. */
	if (fmtbuff_heap != NULL)
		free(fmtbuff_heap);
}

/*
 * Render an arbitrary sequence of bytes into printable ASCII characters.
 */
static size_t
bsdpax_expand_char(char *buff, size_t offset, char c)
{
	size_t i = offset;

	if (isprint((unsigned char)c) && c != '\\')
		buff[i++] = c;
	else {
		buff[i++] = '\\';
		switch (c) {
		case '\a': buff[i++] = 'a'; break;
		case '\b': buff[i++] = 'b'; break;
		case '\f': buff[i++] = 'f'; break;
		case '\n': buff[i++] = 'n'; break;
#if '\r' != '\n'
		/* On some platforms, \n and \r are the same. */
		case '\r': buff[i++] = 'r'; break;
#endif
		case '\t': buff[i++] = 't'; break;
		case '\v': buff[i++] = 'v'; break;
		case '\\': buff[i++] = '\\'; break;
		default:
			sprintf(buff + i, "%03o", 0xFF & (int)c);
			i += 3;
		}
	}

	return (i - offset);
}

/*
 * Prompt for a new name for this entry.  Returns a pointer to the
 * Returns -1 if exit pax program: we got EOF from /dev/tty.
 * Returns 0 if skipp this entry.
 * Returns 1 if handle this entry.
 */
int
pax_rename(struct bsdpax *bsdpax, struct archive_entry *entry)
{
	static char buff[1024];
	char tmp[128];
	FILE *t;
	char *name, *p;
	const char *fmt;
	time_t tim;
	static time_t now;
	int ret;

	t = fopen("/dev/tty", "r+");
	if (t == NULL)
		lafe_errc(1, errno, "Can't open /dev/tty");

	if (!now)
		time(&now);
	fprintf(t, "\nATTENTION: %s interactive file rename operation.\n",
	    lafe_progname);
	fprintf(t, "%s", archive_entry_strmode(entry));
	/* Format the time using 'ls -l' conventions. */
	tim = archive_entry_mtime(entry);
#define HALF_YEAR (time_t)365 * 86400 / 2
#if defined(_WIN32) && !defined(__CYGWIN__)
#define DAY_FMT  "%d"  /* Windows' strftime function does not support %e format. */
#else
#define DAY_FMT  "%e"  /* Day number without leading zeros */
#endif
	if (tim < now - HALF_YEAR || tim > now + HALF_YEAR)
		fmt = bsdpax->day_first ? DAY_FMT " %b  %Y" : "%b " DAY_FMT "  %Y";
	else
		fmt = bsdpax->day_first ? DAY_FMT " %b %H:%M" : "%b " DAY_FMT " %H:%M";
	strftime(tmp, sizeof(tmp), fmt, localtime(&tim));
	fprintf(t, "%s ", tmp);
	safe_fprintf(t, "%s", archive_entry_pathname(entry));
	fprintf(t,
	    "\nInput new name, or a \".\" to keep the old name, or"
	    " a \"return\" to skip this file.\n");
	fprintf(t, "Input > ");
	fflush(t);

	p = fgets(buff, sizeof(buff), t);
	if (p == NULL) {
		/* End-of-file. */
		ret = -1;
		goto finish_rename;
	}

	while (*p == ' ' || *p == '\t')
		++p;
	if (*p == '\n' || *p == '\0') {
		/* Empty line. */
		fprintf(t, "Skipping file.\n");
		ret = 0;
		goto finish_rename;
	}
	if (*p == '.' && p[1] == '\n') {
		/* Single period preserves original name. */
		fprintf(t, "Processing continues, name unchanged.\n");
		ret = 1;
		goto finish_rename;
	}
	name = p;
	/* Trim the final newline. */
	while (*p != '\0' && *p != '\n')
		++p;
	/* Overwrite the final \n with a null character. */
	*p = '\0';
	archive_entry_copy_pathname(entry, name);
	fprintf(t, "Processing continues, name changed to: %s\n", name);
	ret = 1;
finish_rename:
	fflush(t);
	fclose(t);
	return (ret);
}

static const char *
strip_components(const char *p, int elements)
{
	/* Skip as many elements as necessary. */
	while (elements > 0) {
		switch (*p++) {
		case '/':
#if defined(_WIN32) && !defined(__CYGWIN__)
		case '\\': /* Support \ path sep on Windows ONLY. */
#endif
			elements--;
			break;
		case '\0':
			/* Path is too short, skip it. */
			return (NULL);
		}
	}

	/* Skip any / characters.  This handles short paths that have
	 * additional / termination.  This also handles the case where
	 * the logic above stops in the middle of a duplicate //
	 * sequence (which would otherwise get converted to an
	 * absolute path). */
	for (;;) {
		switch (*p) {
		case '/':
#if defined(_WIN32) && !defined(__CYGWIN__)
		case '\\': /* Support \ path sep on Windows ONLY. */
#endif
			++p;
			break;
		case '\0':
			return (NULL);
		default:
			return (p);
		}
	}
}

/*
 * Handle --strip-components and any future path-rewriting options.
 * Returns non-zero if the pathname should not be extracted.
 *
 * TODO: Support pax-style regex path rewrites.
 */
int
edit_pathname(struct bsdpax *bsdpax, struct archive_entry *entry)
{
	const char *name = archive_entry_pathname(entry);
#if HAVE_REGEX_H
	char *subst_name;
	int r;

	r = apply_substitution(bsdpax, name, &subst_name, 0, 0);
	if (r == -1) {
		lafe_warnc(0, "Invalid substitution, skipping entry");
		return 1;
	}
	if (r == 1) {
		archive_entry_copy_pathname(entry, subst_name);
		if (*subst_name == '\0') {
			free(subst_name);
			return -1;
		} else
			free(subst_name);
		name = archive_entry_pathname(entry);
	}

	if (archive_entry_hardlink(entry)) {
		r = apply_substitution(bsdpax, archive_entry_hardlink(entry),
		    &subst_name, 0, 1);
		if (r == -1) {
			lafe_warnc(0, "Invalid substitution, skipping entry");
			return 1;
		}
		if (r == 1) {
			archive_entry_copy_hardlink(entry, subst_name);
			free(subst_name);
		}
	}
	if (archive_entry_symlink(entry) != NULL) {
		r = apply_substitution(bsdpax, archive_entry_symlink(entry),
		    &subst_name, 1, 0);
		if (r == -1) {
			lafe_warnc(0, "Invalid substitution, skipping entry");
			return 1;
		}
		if (r == 1) {
			archive_entry_copy_symlink(entry, subst_name);
			free(subst_name);
		}
	}
#endif

	/* Strip leading dir names as per --strip-components option. */
	if (bsdpax->strip_components > 0) {
		const char *linkname = archive_entry_hardlink(entry);

		name = strip_components(name, bsdpax->strip_components);
		if (name == NULL)
			return (1);

		if (linkname != NULL) {
			linkname = strip_components(linkname,
			    bsdpax->strip_components);
			if (linkname == NULL)
				return (1);
			archive_entry_copy_hardlink(entry, linkname);
		}
	}

	/* By default, don't write or restore absolute pathnames. */
	if (!bsdpax->option_absolute_paths) {
		const char *rp, *p = name;
		int slashonly = 1;

		/* Remove leading "//./" or "//?/" or "//?/UNC/"
		 * (absolute path prefixes used by Windows API) */
		if ((p[0] == '/' || p[0] == '\\') &&
		    (p[1] == '/' || p[1] == '\\') &&
		    (p[2] == '.' || p[2] == '?') &&
		    (p[3] == '/' || p[3] == '\\'))
		{
			if (p[2] == '?' &&
			    (p[4] == 'U' || p[4] == 'u') &&
			    (p[5] == 'N' || p[5] == 'n') &&
			    (p[6] == 'C' || p[6] == 'c') &&
			    (p[7] == '/' || p[7] == '\\'))
				p += 8;
			else
				p += 4;
			slashonly = 0;
		}
		do {
			rp = p;
			/* Remove leading drive letter from archives created
			 * on Windows. */
			if (((p[0] >= 'a' && p[0] <= 'z') ||
			     (p[0] >= 'A' && p[0] <= 'Z')) &&
				 p[1] == ':') {
				p += 2;
				slashonly = 0;
			}
			/* Remove leading "/../", "//", etc. */
			while (p[0] == '/' || p[0] == '\\') {
				if (p[1] == '.' && p[2] == '.' &&
					(p[3] == '/' || p[3] == '\\')) {
					p += 3; /* Remove "/..", leave "/"
							 * for next pass. */
					slashonly = 0;
				} else
					p += 1; /* Remove "/". */
			}
		} while (rp != p);

		if (p != name && !bsdpax->warned_lead_slash) {
			/* Generate a warning the first time this happens. */
			if (slashonly)
				lafe_warnc(0,
				    "Removing leading '%c' from member names",
				    name[0]);
			else
				lafe_warnc(0,
				    "Removing leading drive letter from "
				    "member names");
			bsdpax->warned_lead_slash = 1;
		}

		/* Special case: Stripping everything yields ".". */
		if (*p == '\0')
			name = ".";
		else
			name = p;
	} else {
		/* Strip redundant leading '/' characters. */
		while (name[0] == '/' && name[1] == '/')
			name++;
	}

	/* Safely replace name in archive_entry. */
	if (name != archive_entry_pathname(entry)) {
		char *q = strdup(name);
		archive_entry_copy_pathname(entry, q);
		free(q);
	}
	return (0);
}

/*
 * It would be nice to just use printf() for formatting large numbers,
 * but the compatibility problems are quite a headache.  Hence the
 * following simple utility function.
 */
const char *
pax_i64toa(int64_t n0)
{
	static char buff[24];
	uint64_t n = n0 < 0 ? -n0 : n0;
	char *p = buff + sizeof(buff);

	*--p = '\0';
	do {
		*--p = '0' + (int)(n % 10);
	} while (n /= 10);
	if (n0 < 0)
		*--p = '-';
	return p;
}

/*
 * Like strcmp(), but try to be a little more aware of the fact that
 * we're comparing two paths.  Right now, it just handles leading
 * "./" and trailing '/' specially, so that "a/b/" == "./a/b"
 *
 * TODO: Make this better, so that "./a//b/./c/" == "a/b/c"
 * TODO: After this works, push it down into libarchive.
 * TODO: Publish the path normalization routines in libarchive so
 * that bsdpax can normalize paths and use fast strcmp() instead
 * of this.
 *
 * Note: This is currently only used within write.c, so should
 * not handle \ path separators.
 */

int
pathcmp(const char *a, const char *b)
{
	/* Skip leading './' */
	if (a[0] == '.' && a[1] == '/' && a[2] != '\0')
		a += 2;
	if (b[0] == '.' && b[1] == '/' && b[2] != '\0')
		b += 2;
	/* Find the first difference, or return (0) if none. */
	while (*a == *b) {
		if (*a == '\0')
			return (0);
		a++;
		b++;
	}
	/*
	 * If one ends in '/' and the other one doesn't,
	 * they're the same.
	 */
	if (a[0] == '/' && a[1] == '\0' && b[0] == '\0')
		return (0);
	if (a[0] == '\0' && b[0] == '/' && b[1] == '\0')
		return (0);
	/* They're really different, return the correct sign. */
	return (*(const unsigned char *)a - *(const unsigned char *)b);
}

int
add_user(struct bsdpax *bsdpax, const char *user)
{
	int id, r;

	if (user[0] == '#') {
		id = atoi(user+1);
		if (id < 0)
			return (-1);
		r = archive_match_include_uid(bsdpax->matching, id);
	} else if (user[0] == '\\' && user[1] == '#')
		r = archive_match_include_uname(bsdpax->matching, user+1);
	else
		r = archive_match_include_uname(bsdpax->matching, user);
	return (r);
}

int
add_group(struct bsdpax *bsdpax, const char *group)
{
	int id, r;

	if (group[0] == '#') {
		id = atoi(group+1);
		if (id < 0)
			return (-1);
		r = archive_match_include_gid(bsdpax->matching, id);
	} else if (group[0] == '\\' && group[1] == '#')
		r = archive_match_include_gname(bsdpax->matching, group+1);
	else
		r = archive_match_include_gname(bsdpax->matching, group);
	return (r);
}

int
disk_new_enough(struct bsdpax *bsdpax, const char *path,
    struct archive_entry *entry, int after)
{
#if !defined(_WIN32) || defined(__CYGWIN__)
	struct stat st;
#endif
	time_t t1, t2;
	long n1, n2;
	int c, m, r, use_diskobj;

	if (after) {
		m = bsdpax->option_keep_newer_mtime_files_ar;
		c = bsdpax->option_keep_newer_ctime_files_ar;
	} else {
		m = bsdpax->option_keep_newer_mtime_files_br;
		c = bsdpax->option_keep_newer_ctime_files_br;
	}
	if (!archive_entry_mtime_is_set(entry))
		m = 0;
	if (!archive_entry_ctime_is_set(entry))
		c = 0;
	if (!m && !c)
		return (1);
		
	if (bsdpax->entryenough == NULL) {
		bsdpax->entryenough = archive_entry_new();
		if (bsdpax->entryenough == NULL)
			lafe_errc(1, ENOMEM, "Can't allocate memory");
	} else
		archive_entry_clear(bsdpax->entryenough);

#if defined(_WIN32) && !defined(__CYGWIN__)
	/* On Windows we always use a disk object to get timestamps of
	 * the path since Win32 version of stat() is insufficient. */
	use_diskobj = 1;
#else
	/*
	 * First, simply use stat() to get the file status.
	 * If it fails becaous of its path length, use
	 * archive_read_disk() object instead.
	 */
#ifdef PATH_MAX
	if (strlen(path) > PATH_MAX)
		use_diskobj = 1;
	else
#endif
	if (stat(path, &st) == 0) {
		archive_entry_copy_stat(bsdpax->entryenough, &st);
		use_diskobj = 0;
	} else if (errno == ENAMETOOLONG) {
		use_diskobj = 1;
	} else
		return (1);
#endif /* _WIN32 && ! __CYGWIN__ */

	if (use_diskobj) {
		archive_entry_set_pathname(bsdpax->entryenough, path);
		archive_entry_copy_sourcepath(bsdpax->entryenough, path);
		r = archive_read_disk_entry_from_file(bsdpax->diskenough,
		    bsdpax->entryenough, -1, NULL);
		if (r != ARCHIVE_OK) {
			/* Do not mind whenever any error happen. */
			archive_clear_error(bsdpax->diskenough);
			return (1);
		}
	}

	if (m) {
		t1 = archive_entry_mtime(bsdpax->entryenough);
		t2 = archive_entry_mtime(entry);
		if (t1 < t2)
			return (1);
		if (t1 > t2)
			return (0);
		/* Win32 stat() does not set nsec. */
		n1 = archive_entry_mtime_nsec(bsdpax->entryenough);
		n2 = archive_entry_mtime_nsec(entry);
		if (n1 >= n2)
			return (0);
	}
	if (c) {
		t1 = archive_entry_ctime(bsdpax->entryenough);
		t2 = archive_entry_ctime(entry);
		if (t1 < t2)
			return (1);
		if (t1 > t2)
			return (0);
		/* Win32 stat() does not set nsec. */
		n1 = archive_entry_ctime_nsec(bsdpax->entryenough);
		n2 = archive_entry_ctime_nsec(entry);
		if (n1 >= n2)
			return (0);
	}
	return (1);
}

