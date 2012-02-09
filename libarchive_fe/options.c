/*-
 * Copyright (c) 2011 Michihiro NAKAJIMA
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer
 *    in this position and unchanged.
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


#include "lafe_platform.h"
__FBSDID("$FreeBSD$");

#include <ctype.h>
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#include <stdio.h>
#ifdef HAVE_STDARG_H
#include <stdarg.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#include <time.h>
#ifdef HAVE_WCTYPE_H
#include <wctype.h>
#else
/* If we don't have wctype, we need to hack up some version of iswprint(). */
#define iswprint isprint
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

#include "err.h"
#include "getdate.h"
#include "options.h"

#if defined(_WIN32) && !defined(__CYGWIN__)
#define strdup(_s)	_strdup(_s)
#endif

struct lafe_options {
	char		*options;
	char		*listopt;

	unsigned	 entry_set;
#define E_UID		1U
#define E_UNAME		(1U<<1)
#define E_GID		(1U<<2)
#define E_GNAME		(1U<<3)
#define E_ATIME		(1U<<4)
#define E_CTIME		(1U<<5)
#define E_MTIME		(1U<<6)
#define E_MODE		(1U<<7)

	int64_t		 uid;
	int64_t		 gid;
	char		*uname;
	char		*gname;
	time_t		 atime;
	time_t		 ctime;
	time_t		 mtime;
	mode_t		 mode;
};

#define	HALF_YEAR (time_t)(365 * 86400 / 2)

static void lafe_safe_fprintf(FILE *f, const char *fmt, ...);
static size_t lafe_expand_char(char *buff, size_t offset, char c);

void
lafe_init_options(struct lafe_options **lafe_opt)
{

	*lafe_opt = calloc(1, sizeof(struct lafe_options));
	if (lafe_opt == NULL)
		lafe_errc(1, errno, "Out of memory");
}

void
lafe_free_options(struct lafe_options *lafe_opt)
{
	free(lafe_opt->options);
	free(lafe_opt->listopt);
	free(lafe_opt->uname);
	free(lafe_opt->gname);
	free(lafe_opt);
}

void
lafe_add_options(struct lafe_options *lafe_opt, const char *opt)
{
	char *np, *p = lafe_opt->options;

	if (p != NULL) {
		np = malloc(strlen(p) + strlen(opt) +1);
		if (np != NULL) {
			strcpy(np, p);
			strcpy(np+strlen(p), opt);
			lafe_opt->options = np;
			free(p);
		}
	 } else
		lafe_opt->options = np = strdup(opt);

	if (np == NULL)
		lafe_errc(1, errno, "Out of memory");
}

int
lafe_has_listopt(struct lafe_options *lafe_opt)
{
	return (lafe_opt->listopt != NULL);
}

/*
 * It would be nice to just use printf() for formatting large numbers,
 * but the compatibility problems are quite a headache.  Hence the
 * following simple utility function.
 */
static const char *
lafe_i64toa(char *buff, size_t buff_size, int64_t n0)
{
	uint64_t n = n0 < 0 ? -n0 : n0;
	char *p = buff + buff_size;

	*--p = '\0';
	do {
		*--p = '0' + (int)(n % 10);
	} while (n /= 10);
	if (n0 < 0)
		*--p = '-';
	return p;
}

int
lafe_entry_fprintf(struct lafe_options *lafe_opt, FILE *f,
    struct archive_entry *entry)
{
	const char *p;
	char buff[24];
	char efmt[64];
	char subfmt[64];
	char tmp[100];
	char *fs, *fe;
	time_t t;

	for (p = lafe_opt->listopt; *p != '\0'; p++) {
		const char *_p, *tfmt, *str;
		unsigned long v = 0;
		enum {
			P_NONE = 0,
			P_PATHNAME,
			P_MODE,
			P_UID,
			P_GID,
			P_UNAME,
			P_GNAME,
			P_SIZE,
			P_NLINK,
			P_ATIME,
			P_MTIME,
			P_CTIME,
			P_LINKPATH,
			P_DEV,
			P_DEVMAJOR,
			P_DEVMINOR,
			P_RDEV,
			P_RDEVMAJOR,
			P_RDEVMINOR,
			P_INO,
		} property = P_NONE;
		int flag = 0;
#define FL_ALTERNATE_FORM	1
#define FL_LEFT_ADJUST	(1<<1)
#define FL_SIGN_PLACED	(1<<2)
#define FL_BLANK		(1<<3)
#define FL_ZERO_PADDING	(1<<4)
#define FL_SET_WIDTH	(1<<5)

		if (*p == '\\') {
			switch (p[1]) {
			case '\\': fputc('\\', f); break;
			case 'a':  fputc('\a', f); break;
			case 'b':  fputc('\b', f); break;
			case 'f':  fputc('\f', f); break;
			case 'n':  fputc('\n', f); break;
			case 'r':  fputc('\r', f); break;
			case 't':  fputc('\t', f); break;
			case 'v':  fputc('\v', f); break;
			default:   fputc(p[1], f); break;
			}
			continue;
		} else if (*p != '%') {
			fputc(*p, f);
			continue;
		}
		p++;

		subfmt[0] = 0;
		fs = efmt;
		fe = fs + sizeof(efmt)-5;
		*fs++ = '%';

		/*
		 * Read flags.
		 */
		do {
			_p = p;
			switch (*p) {
			case '#':
				flag |= FL_ALTERNATE_FORM;
				*fs++ = *p++;
				break;
			case '-':
				flag |= FL_LEFT_ADJUST;
				*fs++ = *p++;
				break;
			case '+':
				flag |= FL_SIGN_PLACED;
				*fs++ = *p++;
				break;
			case ' ':
				flag |= FL_BLANK;
				*fs++ = *p++;
				break;
			case '0':
				flag |= FL_ZERO_PADDING;
				*fs++ = *p++;
				break;
			default:
				break;
			}
			if (fs >= fe)
				return (-1);/* Too many flags. */
		} while (_p != p);

		/*
		 * Read a field width.
		 */
		if (*p >= '0' && *p <= '9') {
			flag |= FL_SET_WIDTH;
			*fs++ = *p++;
			while (*p >= '0' && *p <= '9') {
				if (fs >= fe)
					return (-1);/* Too many params. */
				*fs++ = *p++;
			}
		}

		/*
		 * Read a precision.
		 */
		if (*p == '.') {
			flag |= FL_SET_WIDTH;
			*fs++ = *p++;
			while (*p >= '0' && *p <= '9') {
				if (fs >= fe)
					return (-1);/* Too many params. */
				*fs++ = *p++;
			}
		}

		/*
		 * Read a property name.
		 */
		if (*p == '(') {
			const char *end = strchr(p+1, ')');
			const char *sub = strchr(p+1, '=');
			size_t keylen, skiplen;

			if (end == NULL)
				return (-1);/* Invalid */
			if (sub != NULL && sub > end)
				sub = NULL;

			++p;
			skiplen = end - p + 1;
			if (sub == NULL)
				keylen = end - p;
			else
				keylen = sub - p;

			switch (*p) {
			case 'a':
				if (keylen == 5 && strncmp(p, "atime", 5) == 0) {
					property = P_ATIME;
					p += skiplen;
				}
				break;
			case 'c':
				if (keylen == 5 && strncmp(p, "ctime", 5) == 0) {
					property = P_CTIME;
					p += skiplen;
				}
				break;
			case 'd':
				if (keylen == 3 && strncmp(p, "dev", 3) == 0) {
					property = P_DEV;
					p += skiplen;
				} else if (keylen == 8 &&
				    strncmp(p, "devmajor", 8) == 0) {
					property = P_DEVMAJOR;
					p += skiplen;
				} else if (keylen == 8 &&
				    strncmp(p, "devminor", 8) == 0) {
					property = P_DEVMINOR;
					p += skiplen;
				}
				break;
			case 'f':
				if (keylen == 8 &&
				    strncmp(p, "filesize", 8) == 0) {
					property = P_SIZE;
					p += skiplen;
				}
				break;
			case 'g':
				if (keylen == 3 && strncmp(p, "gid", 3) == 0) {
					property = P_GID;
					p += skiplen;
				} else if (keylen == 5 &&
				    strncmp(p, "gname", 5) == 0) {
					property = P_GNAME;
					p += skiplen;
				}
				break;
			case 'i':
				if (keylen == 3 && strncmp(p, "ino", 3) == 0) {
					property = P_INO;
					p += skiplen;
				}
				break;
			case 'l':
				if (keylen == 8 &&
				    (strncmp(p, "linkname", 8) == 0 ||
				     strncmp(p, "linkpath", 8) == 0)) {
					property = P_LINKPATH;
					p += skiplen;
				}
				break;
			case 'm':
				if (keylen == 4 &&
				    strncmp(p, "mode", 4) == 0) {
					property = P_MODE;
					p += skiplen;
				} else if (keylen == 5 &&
				    strncmp(p, "mtime", 5) == 0) {
					property = P_MTIME;
					p += skiplen;
				}
				break;
			case 'n':
				if (keylen == 4 &&
				    strncmp(p, "name", 4) == 0) {
					property = P_PATHNAME;
					p += skiplen;
				} else if (keylen == 5 &&
				    strncmp(p, "nlink", 5) == 0) {
					property = P_NLINK;
					p += skiplen;
				}
				break;
			case 'p':
				if (keylen == 8 &&
				    strncmp(p, "pathname", 8) == 0) {
					property = P_PATHNAME;
					p += skiplen;
				}
				break;
			case 'r':
				if (keylen == 4 && strncmp(p, "rdev", 4) == 0) {
					property = P_RDEV;
					p += skiplen;
				} else if (keylen == 9 &&
				    strncmp(p, "rdevmajor", 9) == 0) {
					property = P_RDEVMAJOR;
					p += skiplen;
				} else if (keylen == 9 &&
				    strncmp(p, "rdevminor", 9) == 0) {
					property = P_RDEVMINOR;
					p += skiplen;
				}
				break;
			case 's':
				if (keylen == 4 &&
				    strncmp(p, "size", 4) == 0) {
					property = P_SIZE;
					p += skiplen;
				}
				break;
			case 'u':
				if (keylen == 3 && strncmp(p, "uid", 3) == 0) {
					property = P_UID;
					p += skiplen;
				} else if (keylen == 5 &&
				    strncmp(p, "uname", 5) == 0) {
					property = P_UNAME;
					p += skiplen;
				}
				break;
			}

			/* Invalid format. */
			if (property == P_NONE)
				return (-1);/* Invalid */

			/*
			 * Save a subformat used for %T format, so
			 * it is the format string of strftime().
			 */
			if (sub != NULL) {
				++sub;/* skip an '=' character. */
				if (end - sub >= (int)sizeof(subfmt)) {
					strncpy(subfmt, sub, sizeof(subfmt)-1);
					subfmt[sizeof(subfmt)-1] = '\0';
				} else {
					strncpy(subfmt, sub, end - sub);
					subfmt[end-sub] = '\0';
				}
			}
		}

		/*
		 * Read a format type.
		 */
		switch (*p) {
		case '%': /* no argument is converted. */
			fputc('%', f);
			break;
		case 'T': /* Time format. */
			if (property == P_ATIME)
				t = archive_entry_atime(entry);
			else if (property == P_CTIME)
				t = archive_entry_ctime(entry);
			else
				t = archive_entry_mtime(entry);

			if (subfmt[0])
				/* Use a time format specified. */
				tfmt = subfmt;
			else {
				/* Use the default time format. */
#if defined(_WIN32) && !defined(__CYGWIN__)
#define DAY_FMT  "%d"  /* Windows' strftime function does not support %e format. */
#else
#define DAY_FMT  "%e"  /* Day number without leading zeros */
#endif
				tfmt = "%b " DAY_FMT " %H:%M %Y";
			}

			strftime(tmp, sizeof(tmp), tfmt, localtime(&t));
			*fs++ = 's';
			*fs = '\0';
			fprintf(f, efmt, tmp);
			break;
		case 'M': /* Mode format. */
			*fs++ = 's';
			*fs = '\0';
			if (property == P_NONE || property == P_MODE)
				fprintf(f, efmt, archive_entry_strmode(entry));
			else
				fprintf(f, efmt, "---------- ");
			break;
		case 'D': /* Device format. */
		{
			int applicable;

			if (archive_entry_filetype(entry) == AE_IFCHR
			    || archive_entry_filetype(entry) == AE_IFBLK)
				applicable = 1;
			else
				applicable = -1;

			if (property != P_NONE) {
				switch (property) {
				case P_SIZE:
					v = (unsigned long)
					    archive_entry_size(entry);
					applicable = 0;
					break;
				case P_UID:
					v = (unsigned long)
					    archive_entry_uid(entry);
					applicable = 0;
					break;
				case P_GID:
					v = (unsigned long)
					    archive_entry_gid(entry);
					applicable = 0;
					break;
				case P_ATIME:
					v = (unsigned long)
					    archive_entry_atime(entry);
					applicable = 0;
					break;
				case P_CTIME:
					v = (unsigned long)
					    archive_entry_ctime(entry);
					applicable = 0;
					break;
				case P_MTIME:
					v = (unsigned long)
					    archive_entry_mtime(entry);
					applicable = 0;
					break;
				case P_DEV:
					v = (unsigned long)
					    archive_entry_dev(entry);
					if (applicable != 1)
						applicable = 0;
					break;
				case P_DEVMAJOR:
					v = (unsigned long)
					    archive_entry_devmajor(entry);
					applicable = 0;
					break;
				case P_DEVMINOR:
					v = (unsigned long)
					    archive_entry_devminor(entry);
					applicable = 0;
					break;
				case P_RDEV:
					v = (unsigned long)
					    archive_entry_rdev(entry);
					if (applicable != 1)
						applicable = 0;
					break;
				case P_RDEVMAJOR:
					v = (unsigned long)
					    archive_entry_rdevmajor(entry);
					applicable = 0;
					break;
				case P_RDEVMINOR:
					v = (unsigned long)
					    archive_entry_rdevminor(entry);
					applicable = 0;
					break;
				case P_INO:
					v = (unsigned long)
					    archive_entry_ino(entry);
					applicable = 0;
					break;
				case P_GNAME:
				case P_UNAME:
				default:
					break;
				}
			}

			if (applicable == 1) {
				*fs++ = 's';
				*fs = '\0';
				sprintf(tmp, "%lu,%lu",
				    (unsigned long)archive_entry_rdevmajor(entry),
				    (unsigned long)archive_entry_rdevminor(entry));
				fprintf(f, efmt, tmp);
			} else if (applicable == 0) {
				*fs++ = 'l';
				*fs++ = 'u';
				*fs = '\0';
				fprintf(f, efmt, v);
			} else {
				*fs++ = 's';
				*fs = '\0';
				fprintf(f, efmt, " ");
			}
			break;
		}
		case 'F': /* Pathname format. */
			*fs++ = 's';
			*fs = '\0';
			str = NULL;
			switch (property) {
			case P_NONE:
			case P_PATHNAME:
				str = archive_entry_pathname(entry);
				break;
			case P_LINKPATH:
				str = archive_entry_hardlink(entry);
				if (str == NULL)
					str = archive_entry_symlink(entry);
				break;
			default:
				break;
			}
			if (str == NULL)
				str = "";
			lafe_safe_fprintf(f, efmt, str);
			break;
		case 'L': /* Linkname format. */
			*fs++ = 's';
			*fs = '\0';
			lafe_safe_fprintf(f, efmt, archive_entry_pathname(entry));
			if (archive_entry_hardlink(entry))
				lafe_safe_fprintf(f, " link to %s",
				    archive_entry_hardlink(entry));
			else if (archive_entry_symlink(entry))
				lafe_safe_fprintf(f, " -> %s",
				    archive_entry_symlink(entry));
			break;
		case 's':
		case 'c':
			str = tmp;
			switch (property) {
			case P_PATHNAME:
				str = archive_entry_pathname(entry);
				break;
			case P_MODE:
				sprintf(tmp, "%o", archive_entry_mode(entry));
				break;
			case P_SIZE:
				sprintf(tmp, "%s",
				    lafe_i64toa(buff, sizeof(buff),
					archive_entry_size(entry)));
				break;
			case P_UNAME:
				str = archive_entry_uname(entry);
				if (str != NULL)
					break;
				/* FALL THROUGH */
			case P_UID:
				sprintf(tmp, "%s",
				    lafe_i64toa(buff, sizeof(buff),
					archive_entry_uid(entry)));
				break;
			case P_GNAME:
				str = archive_entry_gname(entry);
				if (str != NULL)
					break;
				/* FALL THROUGH */
			case P_GID:
				sprintf(tmp, "%s",
				    lafe_i64toa(buff, sizeof(buff),
					archive_entry_gid(entry)));
				break;
			case P_NLINK:
				sprintf(tmp, "%s",
				    lafe_i64toa(buff, sizeof(buff),
					archive_entry_nlink(entry)));
				break;
			case P_ATIME:
				sprintf(tmp, "%s",
				    lafe_i64toa(buff, sizeof(buff),
					archive_entry_atime(entry)));
				break;
			case P_CTIME:
				sprintf(tmp, "%s",
				    lafe_i64toa(buff, sizeof(buff),
					archive_entry_ctime(entry)));
				break;
			case P_MTIME:
				sprintf(tmp, "%s",
				    lafe_i64toa(buff, sizeof(buff),
					archive_entry_mtime(entry)));
				break;
			case P_INO:
				sprintf(tmp, "%s",
				    lafe_i64toa(buff, sizeof(buff),
					archive_entry_ino(entry)));
				break;
			case P_DEV:
				sprintf(tmp, "%s",
				    lafe_i64toa(buff, sizeof(buff),
					archive_entry_dev(entry)));
				break;
			case P_DEVMAJOR:
				sprintf(tmp, "%s",
				    lafe_i64toa(buff, sizeof(buff),
					archive_entry_devmajor(entry)));
				break;
			case P_DEVMINOR:
				sprintf(tmp, "%s",
				    lafe_i64toa(buff, sizeof(buff),
					archive_entry_devminor(entry)));
				break;
			case P_RDEV:
				sprintf(tmp, "%s",
				    lafe_i64toa(buff, sizeof(buff),
					archive_entry_rdev(entry)));
				break;
			case P_RDEVMAJOR:
				sprintf(tmp, "%s",
				    lafe_i64toa(buff, sizeof(buff),
					archive_entry_rdevmajor(entry)));
				break;
			case P_RDEVMINOR:
				sprintf(tmp, "%s",
				    lafe_i64toa(buff, sizeof(buff),
					archive_entry_rdevminor(entry)));
				break;
			default:
				str = " ";/* Print a blank */
				break;
			}
			if (*p == 's') {
				*fs++ = 's';
				*fs = '\0';
				fprintf(f, efmt, str);
			} else {
				*fs++ = 'c';
				*fs = '\0';
				fprintf(f, efmt, str[0]);
			}
			break;
		case 'd': case 'i': case 'o':
		case 'u': case 'x': case 'X':
			switch (property) {
			case P_SIZE:
				v = (unsigned long) archive_entry_size(entry);
				break;
			case P_UID:
			case P_UNAME:
				v = (unsigned long) archive_entry_uid(entry);
				break;
			case P_GID:
			case P_GNAME:
				v = (unsigned long)archive_entry_gid(entry);
				break;
			case P_NLINK:
				v = (unsigned long)archive_entry_nlink(entry);
				break;
			case P_MODE:
				v = (unsigned long)archive_entry_mode(entry);
				break;
			case P_ATIME:
				v = (unsigned long)archive_entry_atime(entry);
				break;
			case P_CTIME:
				v = (unsigned long)archive_entry_ctime(entry);
				break;
			case P_MTIME:
				v = (unsigned long)archive_entry_mtime(entry);
				break;
			case P_DEV:
				v = (unsigned long)archive_entry_dev(entry);
				break;
			case P_DEVMAJOR:
				v = (unsigned long)
				    archive_entry_devmajor(entry);
				break;
			case P_DEVMINOR:
				v = (unsigned long)
				    archive_entry_devminor(entry);
				break;
			case P_RDEV:
				v = (unsigned long)archive_entry_rdev(entry);
				break;
			case P_RDEVMAJOR:
				v = (unsigned long)
				    archive_entry_rdevmajor(entry);
				break;
			case P_RDEVMINOR:
				v = (unsigned long)
				    archive_entry_rdevminor(entry);
				break;
			case P_INO:
				v = (unsigned long)archive_entry_ino(entry);
				break;
			default:
				v = 0;
				break;
			}
			*fs++ = 'l';
			*fs++ = *p;
			*fs = '\0';
			fprintf(f, efmt, v);
			break;
		default:
			return (-1);/* invalid */
		}
	}
	return (0);
}

/*
 * Note that this implementation does not (and should not!) obey
 * locale settings; you cannot simply substitute strtol here, since
 * it does obey locale.
 */
static int64_t
lafe_atol8(const char *p)
{
	int64_t l;
	int digit;

	l = 0;
	while (*p) {
		if (*p >= '0' && *p <= '7')
			digit = *p - '0';
		else
			return (l);
		p++;
		l <<= 3;
		l |= digit;
	}
	return (l);
}

static int64_t
lafe_atoi(const char *p)
{
	int64_t v = 0, pv;
	int d;

	while (*p) {
		if (*p < '0' || *p > '9')
			break;
		pv = v;
		d = *p - '0';
		if (pv == 0)
			v = d;
		else {
			v = pv * 10 + d;
			if (v < pv) {
				v = INT64_MAX;
				break;
			}
		}
		p++;
	}
	return (v);
}

static const char opt_true[] = "1";
static int
use_option(struct lafe_options *lafe_opt, const char *opt, const char *val)
{
	time_t now;

	switch (*opt) {
	case 'a':
		if (strcmp(opt, "atime") == 0 && val != NULL &&
		    val != opt_true) {
			lafe_opt->entry_set |= E_ATIME;
			time(&now);
			lafe_opt->atime = get_date(now, val);
			if (lafe_opt->atime == (time_t)-1)
				lafe_errc(1, 0, "invalid atime format");
			return (0);
		}
		break;
	case 'c':
		if (strcmp(opt, "ctime") == 0 && val != NULL &&
		    val != opt_true) {
			lafe_opt->entry_set |= E_CTIME;
			time(&now);
			lafe_opt->ctime = get_date(now, val);
			if (lafe_opt->ctime == (time_t)-1)
				lafe_errc(1, 0, "invalid ctime format");
			return (0);
		}
		break;
	case 'g':
		if (strcmp(opt, "gid") == 0 && val != NULL &&
		    val != opt_true) {
			lafe_opt->entry_set |= E_GID;
			lafe_opt->gid = lafe_atoi(val);
			if (lafe_opt->gid < 0)
				lafe_errc(1, 0, "gid must be positive");
			return (0);
		} else if (strcmp(opt, "gname") == 0 &&
		    val != NULL && val != opt_true) {
			lafe_opt->entry_set |= E_GNAME;
			lafe_opt->gname = strdup(val);
			if (lafe_opt->gname == NULL)
				lafe_errc(1, errno, "Out of memory");
			return (0);
		}
		break;
	case 'l':
		if (strcmp(opt, "listopt") == 0 && val != NULL &&
		    val != opt_true) {
			char *np, *p = lafe_opt->listopt;
			if (p != NULL) {
				np = malloc(strlen(p) + strlen(val) +1);
				if (np != NULL) {
					strcpy(np, p);
					strcpy(np+strlen(p), val);
					lafe_opt->listopt = np;
					free(p);
				}
			} else
				lafe_opt->listopt = np = strdup(val);
			if (np == NULL)
				lafe_errc(1, errno, "Out of memory");
			return (0);
		}
		break;
	case 'm':
		if (strcmp(opt, "mode") == 0 && val != NULL &&
		    val != opt_true) {
			lafe_opt->entry_set |= E_MODE;
			lafe_opt->mode = (mode_t)(lafe_atol8(val) & 0777);
			return (0);
		} else if (strcmp(opt, "mtime") == 0 && val != NULL &&
		    val != opt_true) {
			lafe_opt->entry_set |= E_MTIME;
			time(&now);
			lafe_opt->mtime = get_date(now, val);
			if (lafe_opt->mtime == (time_t)-1)
				lafe_errc(1, 0, "invalid mtime format");
			return (0);
		}
		break;
	case 'u':
		if (strcmp(opt, "uid") == 0 && val != NULL &&
		    val != opt_true) {
			lafe_opt->entry_set |= E_UID;
			lafe_opt->uid = lafe_atoi(val);
			if (lafe_opt->uid < 0)
				lafe_errc(1, 0, "uid must be positive");
			return (0);
		} else if (strcmp(opt, "uname") == 0 && val != NULL &&
		    val != opt_true) {
			lafe_opt->entry_set |= E_UNAME;
			lafe_opt->uname = strdup(val);
			if (lafe_opt->uname == NULL)
				lafe_errc(1, errno, "Out of memory");
			return (0);
		}
		break;
	}
	return (-1);
}

static const char *
parse_option(const char **s, const char **m, const char **o, const char **v)
{
	const char *end, *mod, *opt, *val;
	char *p, *p2;

	end = NULL;
	mod = NULL;
	opt = *s;
	val = opt_true;

	p = strchr(opt, ',');

	if (p != NULL) {
		*p = '\0';
		end = ((const char *)p) + 1;
	}

	if (0 == strlen(opt)) {
		*s = end;
		*m = NULL;
		*o = NULL;
		*v = NULL;
		return end;
	}

	p = strchr(opt, ':');
	p2 = strchr(opt, '=');
	if (p != NULL && p < p2) {
		*p = '\0';
		mod = opt;
		opt = ++p;
	}

	p = p2;
	if (p != NULL) {
		*p = '\0';
		val = ++p;
	} else if (opt[0] == '!') {
		++opt;
		val = NULL;
	}

	*s = end;
	*m = mod;
	*o = opt;
	*v = val;

	return end;
}

void
lafe_set_options(struct lafe_options *lafe_opt,
    lafe_options_callback archive_options, struct archive *a)
{
	int r;
	char *data, *ar_data, *ar_s;
	const char *s, *mod, *opt, *val;

	if (lafe_opt->options == NULL || lafe_opt->options[0] == '\0')
		return;

	data = strdup(lafe_opt->options);
	ar_data = strdup(lafe_opt->options);
	if (data == NULL || ar_data == NULL)
		lafe_errc(1, errno, "Out of memory");
	s = (const char *)data;
	ar_s = ar_data;

	/*
	 * Parse options for the front-end side.
	 */
	do {
		const char *bp;
		int used = 0;
		size_t len;

		mod = opt = val = NULL;

		bp = s;
		parse_option(&s, &mod, &opt, &val);

		if (mod == NULL && opt != NULL) {
			r = use_option(lafe_opt, opt, val);
			if (r == 0)
				used = 1;
		}
		if (s)
			len = s - bp;
		else
			len = strlen(bp);

		/* Omit the option string which the front-end side used,
		 * from the option string the library side is parsing
		 * next step. */ 
		if (used)
			memmove(ar_s, ar_s + len, strlen(ar_s + len));
		else
			ar_s += len;
	} while (s != NULL);

	*ar_s = '\0';
	free(data);

	/*
	 * Parse options for the library side.
	 */
	r = archive_options(a, ar_data);
	free(ar_data);
	if (r != ARCHIVE_OK) {
		s = archive_error_string(a);
		if (s == NULL)
			lafe_errc(1, 0, "No one accepted the options: %s",
			    lafe_opt->options);
		else
			lafe_errc(1, 0, "%s", s);
	}
}


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

static void
lafe_safe_fprintf(FILE *f, const char *fmt, ...)
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
	if (length >= fmtbuff_length) {
		fmtbuff_length = length+1;
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
					i += (unsigned)lafe_expand_char(
					    outbuff, i, *p++);
			}
		} else {
			/* After any conversion failure, don't bother
			 * trying to convert the rest. */
			i += (unsigned)lafe_expand_char(outbuff, i, *p++);
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
lafe_expand_char(char *buff, size_t offset, char c)
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

void
lafe_edit_entry(struct lafe_options *lafe_opt, struct archive_entry *e)
{
	if (lafe_opt->entry_set == 0)
		return;

	if (lafe_opt->entry_set & E_UID) {
		archive_entry_set_uid(e, lafe_opt->uid);
		if ((lafe_opt->entry_set & E_UNAME) == 0)
			archive_entry_set_uname(e, NULL);
	}
	if (lafe_opt->entry_set & E_UNAME)
		archive_entry_set_uname(e, lafe_opt->uname);
	if (lafe_opt->entry_set & E_GID) {
		archive_entry_set_gid(e, lafe_opt->gid);
		if ((lafe_opt->entry_set & E_GNAME) == 0)
			archive_entry_set_gname(e, NULL);
	}
	if (lafe_opt->entry_set & E_GNAME)
		archive_entry_set_gname(e, lafe_opt->gname);
	if (lafe_opt->entry_set & E_ATIME)
		archive_entry_set_atime(e, lafe_opt->atime, 0);
	if (lafe_opt->entry_set & E_CTIME)
		archive_entry_set_ctime(e, lafe_opt->ctime, 0);
	if (lafe_opt->entry_set & E_MTIME)
		archive_entry_set_mtime(e, lafe_opt->mtime, 0);
	if (lafe_opt->entry_set & E_MODE) {
		mode_t ft = archive_entry_filetype(e);
		archive_entry_set_mode(e, ft | (lafe_opt->mode & ~AE_IFMT));
	}
}
