/*-
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
 */

#include "bsdpax_platform.h"
__FBSDID("$FreeBSD$");

#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_COPYFILE_H
#include <copyfile.h>
#endif
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_LANGINFO_H
#include <langinfo.h>
#endif
#ifdef HAVE_LOCALE_H
#include <locale.h>
#endif
#ifdef HAVE_PATHS_H
#include <paths.h>
#endif
#ifdef HAVE_SIGNAL_H
#include <signal.h>
#endif
#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "bsdpax.h"
#include "err.h"
#include "getdate.h"

#ifdef __MINGW32__
int _CRT_glob = 0; /* Disable broken CRT globbing. */
#endif

#if defined(HAVE_SIGACTION) && (defined(SIGINFO) || defined(SIGUSR1))
static volatile int siginfo_occurred;

static void
siginfo_handler(int sig)
{
	(void)sig; /* UNUSED */
	siginfo_occurred = 1;
}

int
need_report(void)
{
	int r = siginfo_occurred;
	siginfo_occurred = 0;
	return (r);
}
#else
int
need_report(void)
{
	return (0);
}
#endif

static void	 compression_conflict_error(struct bsdpax *, int compression);
static void	 long_help(void);
static void	 only_mode(struct bsdpax *, const char *opt, char valid);
static void	 version(void);
static void	 parse_option_T(struct bsdpax *bsdpax, time_t now,
		    const char *opt);

/* A basic set of security flags to request from libarchive. */
#define	SECURITY					\
	(ARCHIVE_EXTRACT_SECURE_SYMLINKS		\
	 | ARCHIVE_EXTRACT_SECURE_NODOTDOT)

int
main(int argc, char **argv)
{
	struct bsdpax		*bsdpax, bsdpax_storage;
	const char		*arg;
	int			 opt, t;
	char			 option_a;
	char			 buff[16];
	time_t			 now;
	struct stat		 st;

	/*
	 * Use a pointer for consistency, but stack-allocated storage
	 * for ease of cleanup.
	 */
	bsdpax = &bsdpax_storage;
	memset(bsdpax, 0, sizeof(*bsdpax));
	bsdpax->mode = PAXMODE_LIST;
	bsdpax->fd = -1; /* Mark as "unused" */
	option_a = 0;
	lafe_init_options(&(bsdpax->options));

#if defined(HAVE_SIGACTION)
	{ /* Set up signal handling. */
		struct sigaction sa;
		sa.sa_handler = siginfo_handler;
		sigemptyset(&sa.sa_mask);
		sa.sa_flags = 0;
#ifdef SIGINFO
		if (sigaction(SIGINFO, &sa, NULL))
			lafe_errc(1, errno, "sigaction(SIGINFO) failed");
#endif
#ifdef SIGUSR1
		/* ... and treat SIGUSR1 the same way as SIGINFO. */
		if (sigaction(SIGUSR1, &sa, NULL))
			lafe_errc(1, errno, "sigaction(SIGUSR1) failed");
#endif
#ifdef SIGPIPE
		/* Ignore SIGPIPE signals. */
		sa.sa_handler = SIG_IGN;
		sigaction(SIGPIPE, &sa, NULL);
#endif
	}
#endif


	/* Need lafe_progname before calling lafe_warnc. */
	if (*argv == NULL)
		lafe_progname = "bsdpax";
	else {
#if defined(_WIN32) && !defined(__CYGWIN__)
		lafe_progname = strrchr(*argv, '\\');
#else
		lafe_progname = strrchr(*argv, '/');
#endif
		if (lafe_progname != NULL)
			lafe_progname++;
		else
			lafe_progname = *argv;
	}

	time(&now);

#if HAVE_SETLOCALE
	if (setlocale(LC_ALL, "") == NULL)
		lafe_warnc(0, "Failed to set default locale");
#endif
#if defined(HAVE_NL_LANGINFO) && defined(HAVE_D_MD_ORDER)
	bsdpax->day_first = (*nl_langinfo(D_MD_ORDER) == 'd');
#endif

	/* Look up uid of current user for future reference */
	bsdpax->user_uid = geteuid();

	/* Default block size settings. */
	bsdpax->bytes_per_block = DEFAULT_BYTES_PER_BLOCK;
	/* Allow library to default this unless user specifies -b. */
	bsdpax->bytes_in_last_block = -1;

	/* Default: preserve mod time on extract */
	bsdpax->extract_flags = ARCHIVE_EXTRACT_TIME;

	/* Default: Perform basic security checks. */
	bsdpax->extract_flags |= SECURITY;

	/* Default: Do not follow symbolic links. */
	bsdpax->symlink_mode = 'P';

	/* Default: Write to stdout; Read from stdin. */
	bsdpax->filename = NULL;

#ifndef _WIN32
	/* On POSIX systems, assume --same-owner and -p when run by
	 * the root user.  This doesn't make any sense on Windows. */
	if (bsdpax->user_uid == 0) {
		/* --same-owner */
		bsdpax->extract_flags |= ARCHIVE_EXTRACT_OWNER;
		/* -p */
		bsdpax->extract_flags |= ARCHIVE_EXTRACT_PERM;
		bsdpax->extract_flags |= ARCHIVE_EXTRACT_ACL;
		bsdpax->extract_flags |= ARCHIVE_EXTRACT_XATTR;
		bsdpax->extract_flags |= ARCHIVE_EXTRACT_FFLAGS;
	}
#endif

	/*
	 * Enable Mac OS "copyfile()" extension by default.
	 * This has no effect on other platforms.
	 */
	bsdpax->readdisk_flags |= ARCHIVE_READDISK_MAC_COPYFILE;
#ifdef COPYFILE_DISABLE_VAR
	if (getenv(COPYFILE_DISABLE_VAR))
		bsdpax->readdisk_flags &= ~ARCHIVE_READDISK_MAC_COPYFILE;
#endif
	bsdpax->matching = archive_matching_new();
	if (bsdpax->matching == NULL)
		lafe_errc(1, 0, "Out of memory");

	bsdpax->argv = argv;
	bsdpax->argc = argc;

	/*
	 * Comments following each option indicate where that option
	 * originated:  SUSv2, POSIX, GNU tar, star, etc.  If there's
	 * no such comment, then I don't know of anyone else who
	 * implements that option.
	 */
	while ((opt = bsdpax_getopt(bsdpax)) != -1) {
		switch (opt) {
		case 'a':
			option_a = 1;
			break;
		case 'b':
			t = atoi(bsdpax->argument);
			if (t <= 0 || t > 8192)
				lafe_errc(1, 0,
				    "Argument to -b is out of range (1..8192)");
			bsdpax->bytes_per_block = 512 * t;
			/* Explicit -b forces last block size. */
			bsdpax->bytes_in_last_block = bsdpax->bytes_per_block;
			break;
		case OPTION_COMPRESS:
			if (bsdpax->create_compression != '\0')
				compression_conflict_error(bsdpax, opt);
			bsdpax->create_compression = opt;
			break;
		case 'c':
			bsdpax->option_exclude = 1;
			break;
		case 'D':
			bsdpax->option_keep_newer_ctime_files_br = 1;
			break;
		case 'd':
			bsdpax->option_no_subdirs = 1;
			break;
		case OPTION_DISABLE_COPYFILE: /* Mac OS X */
			bsdpax->readdisk_flags &= ~ARCHIVE_READDISK_MAC_COPYFILE;
			break;
		case 'f':
			bsdpax->filename = bsdpax->argument;
			break;
		case 'G':
			if (add_group(bsdpax, bsdpax->argument) < 0) 
				lafe_errc(1, 0,
				    "Argument to -G # must be positive");
			break;
		case 'H':
			bsdpax->symlink_mode = opt;
			break;
		case OPTION_HELP:
			long_help();
			exit(0);
			break;
		case 'i':
			bsdpax->option_interactive = 1;
			break;
		case OPTION_INSECURE:
			bsdpax->extract_flags &= ~SECURITY;
			bsdpax->option_absolute_paths = 1;
			break;
		case 'j':
		case 'J':
		case OPTION_LZIP:
		case OPTION_LZMA:
			if (bsdpax->create_compression != '\0')
				compression_conflict_error(bsdpax, opt);
			bsdpax->create_compression = opt;
			break;
		case 'k':
			bsdpax->extract_flags |= ARCHIVE_EXTRACT_NO_OVERWRITE;
			break;
		case 'L':
			bsdpax->symlink_mode = opt;
			break;
		case 'l':
			bsdpax->option_link = 1;
			break;
		case OPTION_NODUMP:
			bsdpax->readdisk_flags |= ARCHIVE_READDISK_HONOR_NODUMP;
			break;
		case OPTION_NULL:
			bsdpax->option_null = 1;
			break;
		case 'n':
			bsdpax->option_fast_read = 1;
			break;
		case 'o':
			lafe_add_options(bsdpax->options, bsdpax->argument);
			break;
		case 'P':
			bsdpax->symlink_mode = opt;
			break;
		case 'p':
			for (arg = bsdpax->argument; *arg; arg++) {
				switch (*arg) {
				case 'a':
					/* Do not preserve the atime. */
					bsdpax->option_no_atime = 1;
					break;
				case 'e':
					/* Preserve evertything. */
					bsdpax->extract_flags |=
					    ARCHIVE_EXTRACT_TIME;
					bsdpax->extract_flags |=
					    ARCHIVE_EXTRACT_PERM;
					bsdpax->extract_flags |=
					    ARCHIVE_EXTRACT_ACL;
					bsdpax->extract_flags |=
					    ARCHIVE_EXTRACT_XATTR;
					bsdpax->extract_flags |=
					    ARCHIVE_EXTRACT_FFLAGS;
					bsdpax->extract_flags |=
					    ARCHIVE_EXTRACT_MAC_METADATA;
					bsdpax->option_no_atime = 0;
					bsdpax->option_no_mtime = 0;
					break;
				case 'm':
					/* Do not preserve the mtime. */
					bsdpax->option_no_mtime = 1;
					break;
				case 'o':
					/* Preserve the user id and group id. */
					bsdpax->extract_flags |=
					    ARCHIVE_EXTRACT_OWNER;
					break;
				case 'p':
					/* Preserve the file mode. */
					bsdpax->extract_flags |=
					    ARCHIVE_EXTRACT_PERM;
					break;
				default:
					lafe_errc(1, 0,
					    "'%c' is an invalid sub-option for -p",
					    *arg);
					break;
				}
			}
			break;
		case 'r':
			if (bsdpax->mode == PAXMODE_WRITE)
				bsdpax->mode = PAXMODE_COPY;
			else if (bsdpax->mode != PAXMODE_COPY)
				bsdpax->mode = PAXMODE_READ;
			break;
		case 's':
#if HAVE_REGEX_H
			add_substitution(bsdpax, bsdpax->argument);
#else
			lafe_warnc(0,
			    "-s is not supported by this version of bsdpax");
			usage();
#endif
			break;
		case OPTION_STRIP_COMPONENTS:
			errno = 0;
			bsdpax->strip_components = strtol(bsdpax->argument,
			    NULL, 0);
			if (errno)
				lafe_errc(1, 0,
				    "Invalid --strip-components argument: %s",
				    bsdpax->argument);
			break;
		case 'T':
			parse_option_T(bsdpax, now, bsdpax->argument);
			break;
		case 't':
			bsdpax->readdisk_flags |= ARCHIVE_READDISK_RESTORE_ATIME;
			break;
		case 'u':
			bsdpax->option_keep_newer_mtime_files_br = 1;
			break;
		case 'U':
			if (add_user(bsdpax, bsdpax->argument) < 0)
				lafe_errc(1, 0,
				    "Argument to -U # must be positive");
			break;
		case 'v':
			bsdpax->verbose++;
			break;
		case OPTION_VERSION:
			version();
			break;
		case 'w':
			if (bsdpax->mode == PAXMODE_READ)
				bsdpax->mode = PAXMODE_COPY;
			else if (bsdpax->mode != PAXMODE_COPY)
				bsdpax->mode = PAXMODE_WRITE;
			break;
		case 'X':
			bsdpax->option_dont_traverse_mounts = 1;
			break;
		case 'x':
			bsdpax->create_format = bsdpax->argument;
			break;
		case 'Y':
			bsdpax->option_keep_newer_ctime_files_ar = 1;
			break;
		case 'Z':
			bsdpax->option_keep_newer_mtime_files_ar = 1;
			break;
		case 'z':
			if (bsdpax->create_compression != '\0')
				compression_conflict_error(bsdpax, opt);
			bsdpax->create_compression = opt;
			break;
		case OPTION_USE_COMPRESS_PROGRAM:
			bsdpax->compress_program = bsdpax->argument;
			break;
		default:
			usage();
		}
	}

	/*
	 * Sanity-check options.
	 */

	/* Check boolean options only permitted in certain modes. */
	if (option_a)
		only_mode(bsdpax, "-a", PAXMODE_WRITE);
	if (bsdpax->option_keep_newer_mtime_files_br)
		only_mode(bsdpax, "-u",
		    PAXMODE_READ | PAXMODE_WRITE | PAXMODE_COPY);
	if (bsdpax->option_keep_newer_mtime_files_ar)
		only_mode(bsdpax, "-Z",
		    PAXMODE_READ | PAXMODE_WRITE | PAXMODE_COPY);
	if (bsdpax->option_keep_newer_ctime_files_br)
		only_mode(bsdpax, "-D", PAXMODE_READ | PAXMODE_COPY);
	if (bsdpax->option_keep_newer_ctime_files_ar)
		only_mode(bsdpax, "-Y", PAXMODE_READ | PAXMODE_COPY);
	if (bsdpax->option_no_subdirs)
		only_mode(bsdpax, "-d", PAXMODE_WRITE | PAXMODE_COPY);
	if (bsdpax->option_interactive)
		only_mode(bsdpax, "-i",
		    PAXMODE_READ | PAXMODE_WRITE | PAXMODE_COPY);
	if (bsdpax->option_fast_read)
		only_mode(bsdpax, "-n", PAXMODE_LIST | PAXMODE_READ);
	if (bsdpax->option_dont_traverse_mounts)
		only_mode(bsdpax, "-X", PAXMODE_WRITE | PAXMODE_COPY);
	if (bsdpax->option_link)
		only_mode(bsdpax, "-l", PAXMODE_COPY);

	/* Check other parameters only permitted in certain modes. */
	if (bsdpax->create_compression != '\0') {
		strcpy(buff, "-?");
		buff[1] = bsdpax->create_compression;
		only_mode(bsdpax, buff,
		    PAXMODE_LIST | PAXMODE_READ | PAXMODE_WRITE);
	}
	if (bsdpax->create_format != NULL)
		only_mode(bsdpax, "-x", PAXMODE_WRITE);
	if (bsdpax->extract_flags & ARCHIVE_EXTRACT_NO_OVERWRITE)
		only_mode(bsdpax, "-k", PAXMODE_READ | PAXMODE_COPY);
	if (bsdpax->filename != NULL)
		only_mode(bsdpax, "-f",
		    PAXMODE_READ | PAXMODE_WRITE | PAXMODE_LIST);

	/* Filename "-" implies stdio. */
	if (bsdpax->filename != NULL && strcmp(bsdpax->filename, "-") == 0)
		bsdpax->filename = NULL;

	switch(bsdpax->mode) {
	default:
	case PAXMODE_LIST:
		bsdpax->verbose++;
		pax_mode_list(bsdpax);
		break;
	case PAXMODE_READ:
		pax_mode_read(bsdpax);
		break;
	case PAXMODE_WRITE:
		if (option_a)
			/* with -a option */
			pax_mode_append(bsdpax);
		else
			pax_mode_write(bsdpax);
		break;
	case PAXMODE_COPY:
		if (*bsdpax->argv == NULL)
			usage();
		else {
			char **p = bsdpax->argv;
			while (*p)
				p++;
			p--;
			if (stat(*p, &st) < 0)
				lafe_errc(1, errno, "Cannot access "
				    "destination directory %s", *p);
			if ((st.st_mode & S_IFMT) != S_IFDIR)
				lafe_errc(1, 0,
				    "Destination is not a directory");
			bsdpax->destdir = *p;
			bsdpax->destdir_len = strlen(*p);
			pax_mode_copy(bsdpax);
		}
		break;
	}

	archive_matching_free(bsdpax->matching);
#if HAVE_REGEX_H
	cleanup_substitution(bsdpax);
#endif
	lafe_free_options(bsdpax->options);

	if (bsdpax->return_value != 0)
		lafe_warnc(0,
		    "Error exit delayed from previous errors.");
	return (bsdpax->return_value);
}

static void
compression_name(char *name, size_t name_size, int compression)
{
	switch (compression) {
	case OPTION_COMPRESS:
		strncpy(name, "--compress", name_size-1);
		name[name_size-1] = '\0';
		break;
	case OPTION_LZIP:
		strncpy(name, "--lzip", name_size-1);
		name[name_size-1] = '\0';
		break;
	case OPTION_LZMA:
		strncpy(name, "--lzma", name_size-1);
		name[name_size-1] = '\0';
		break;
	case 'j':
	case 'J':
	case 'z':
		name[0] = '-'; name[1] = compression; name[2] = '\0';
		break;
	}
}

static void
compression_conflict_error(struct bsdpax *bsdpax, int compression)
{
	char name1[16], name2[16];

	compression_name(name1, sizeof(name1), bsdpax->create_compression);
	compression_name(name2, sizeof(name2), compression);
	lafe_errc(1, 0, "Can't specify both %s and %s", name1, name2);
}

/*
 * Verify that the mode is correct.
 */
static void
only_mode(struct bsdpax *bsdpax, const char *opt, char valid_modes)
{
	if ((valid_modes & bsdpax->mode) == 0) {
		const char *mode;
		switch (bsdpax->mode) {
		case PAXMODE_READ:
			mode = "-r";
			break;
		case PAXMODE_WRITE:
			mode = "-w";
			break;
		case PAXMODE_COPY:
			mode = "-r -w";
			break;
		default:
			mode = "<List>";
			break;
		}
		lafe_errc(1, 0,
		    "Option %s is not permitted in mode %s",
		    opt, mode);
	}
}

void
usage(void)
{
	const char	*p;

	p = lafe_progname;

	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "  List:    %s -f <archive-filename>\n", p);
	fprintf(stderr, "  Extract: %s -rf <archive-filename>\n", p);
	fprintf(stderr, "  Create:  %s -wf <archive-filename> [filenames...]\n", p);
	fprintf(stderr, "  Copy:    %s -r -w [filenames...] <dist-dir>\n", p);
	fprintf(stderr, "  Help:    %s --help\n", p);
	exit(1);
}

static void
version(void)
{
	printf("bsdpax %s - %s\n",
	    BSDPAX_VERSION_STRING,
	    archive_version_string());
	exit(0);
}

static const char *long_help_msg =
	"First option must be a mode specifier:\n"
	"  -w Create    -r Extract    -rw Copy\n"
	"Common Options:\n"
	"  -f <filename>  Location of archive (default standard input/output)\n"
	"  -v    Verbose\n"
	"Write: %p -w [options] [<file> | <dir> | @<archive> ]\n"
	"  <file>, <dir>  add these items to archive\n"
	"  -x {ustar|pax|cpio|shar}  Select archive format\n"
	"  @<archive>  Add entries from <archive> to output\n"
	"List: %p [options] [<patterns>]\n"
	"  <patterns>  If specified, list only entries that match\n"
	"Extract: %p -r [options] [<patterns>]\n"
	"  <patterns>  If specified, extract only entries that match\n"
	"Copy: %p -r -w [options] [<file> | <dir> ] <dist-dir>\n"
	"  <file>, <dir>  copy these items to <dist-dir>\n";


/*
 * Note that the word 'bsdpax' will always appear in the first line
 * of output.
 *
 * In particular, /bin/sh scripts that need to test for the presence
 * of bsdpax can use the following template:
 *
 * if (pax --help 2>&1 | grep bsdpax >/dev/null 2>&1 ) then \
 *          echo bsdpax; else echo not bsdpax; fi
 */
static void
long_help(void)
{
	const char	*prog;
	const char	*p;

	prog = lafe_progname;

	fflush(stderr);

	p = (strcmp(prog,"bsdpax") != 0) ? "(bsdpax)" : "";
	printf("%s%s: manipulate archive files\n", prog, p);

	for (p = long_help_msg; *p != '\0'; p++) {
		if (*p == '%') {
			if (p[1] == 'p') {
				fputs(prog, stdout);
				p++;
			} else
				putchar('%');
		} else
			putchar(*p);
	}
	version();
}

static void
parse_option_T(struct bsdpax *bsdpax, time_t now, const char *opt)
{
	char *s = strdup(opt);
	char *p;
	time_t t;
	int flag, mf;
#define USE_MTIME	1
#define USE_CTIME	2

	p = strrchr(s, '/');
	flag = USE_MTIME; /* Use mtime only by default. */
	if (p != NULL) {
		/* User Specifies which time, ctime or mtime or both. */
		if (strcmp(p, "/mc") == 0 || strcmp(p, "/cm") == 0) { 
			/* Use both mtime and ctime. */
			flag = USE_MTIME | USE_CTIME;
			*p = '\0';
		} else if (strcmp(p, "/c") == 0) {
			/* Use ctime only. */
			flag = USE_CTIME;
			*p = '\0';
		} else if (strcmp(p, "/m") == 0)
			/* Use mtime only. */
			*p = '\0';
	}
	p = strrchr(s, ',');
	if (p != NULL) {
		/* Parse 'to date'. */
		*p++ = '\0';
		t = get_date(now, p);
		mf = 0;
		if (flag & USE_MTIME)
			mf |= ARCHIVE_MATCHING_MTIME;
		if (flag & USE_CTIME)
			mf |= ARCHIVE_MATCHING_CTIME;
		if (t != (time_t)-1 && mf) {
			mf |= ARCHIVE_MATCHING_OLDER | ARCHIVE_MATCHING_EQUAL;
			archive_matching_include_time(bsdpax->matching,
			    mf, t, 0);
		}
	}
	p = s;
	while (*p == ' ' || *p == '\t')
		p++;
	if (strlen(p) > 0) {
		/* Parse 'from date'. */
		t = get_date(now, p);
		mf = 0;
		if (flag & USE_MTIME)
			mf |= ARCHIVE_MATCHING_MTIME;
		if (flag & USE_CTIME)
			mf |= ARCHIVE_MATCHING_CTIME;
		if (t != (time_t)-1 && mf) {
			mf |= ARCHIVE_MATCHING_NEWER | ARCHIVE_MATCHING_EQUAL;
			archive_matching_include_time(bsdpax->matching,
			    mf, t, 0);
		}
	}
	free(s);
}
