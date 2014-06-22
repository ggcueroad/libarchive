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

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#ifdef HAVE_GRP_H
#include <grp.h>
#endif
#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif
#ifdef HAVE_PWD_H
#include <pwd.h>
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
#ifdef HAVE_TIME_H
#include <time.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "bsdpax.h"
#include "err.h"

struct progress_data {
	struct bsdpax *bsdpax;
	struct archive *archive;
	struct archive_entry *entry;
};

static void	list_item_verbose(struct bsdpax *, FILE *,
		    struct archive_entry *);
static void	read_archive(struct bsdpax *bsdpax, char mode, struct archive *);
static int	unmatched_inclusions_warn(struct archive *, const char *);

void
pax_mode_list(struct bsdpax *bsdpax)
{
	read_archive(bsdpax, PAXMODE_LIST, NULL);
	if (unmatched_inclusions_warn(bsdpax->matching,
	    "Not found in archive") != 0)
		bsdpax->return_value = 1;
}

void
pax_mode_read(struct bsdpax *bsdpax)
{
	struct archive *writer;

	writer = archive_write_disk_new();
	if (writer == NULL)
		lafe_errc(1, ENOMEM, "Cannot allocate disk writer object");
	if (!bsdpax->option_numeric_owner)
		archive_write_disk_set_standard_lookup(writer);
	archive_write_disk_set_options(writer, bsdpax->extract_flags);

	read_archive(bsdpax, PAXMODE_READ, writer);

	if (unmatched_inclusions_warn(bsdpax->matching,
	    "Not found in archive") != 0)
		bsdpax->return_value = 1;
	archive_write_free(writer);
}

static void
progress_func(void *cookie)
{
	struct progress_data *progress_data = cookie;
	struct bsdpax *bsdpax = progress_data->bsdpax;
	struct archive *a = progress_data->archive;
	struct archive_entry *entry = progress_data->entry;
	uint64_t comp, uncomp;
	int compression;

	if (!need_report())
		return;

	if (bsdpax->verbose)
		fprintf(stderr, "\n");
	if (a != NULL) {
		comp = archive_filter_bytes(a, -1);
		uncomp = archive_filter_bytes(a, 0);
		if (comp > uncomp)
			compression = 0;
		else
			compression = (int)((uncomp - comp) * 100 / uncomp);
		fprintf(stderr,
		    "In: %s bytes, compression %d%%;",
		    pax_i64toa(comp), compression);
		fprintf(stderr, "  Out: %d files, %s bytes\n",
		    archive_file_count(a), pax_i64toa(uncomp));
	}
	if (entry != NULL) {
		safe_fprintf(stderr, "Current: %s",
		    archive_entry_pathname(entry));
		fprintf(stderr, " (%s bytes)\n",
		    pax_i64toa(archive_entry_size(entry)));
	}
}

/*
 * Handle 'READ' and 'LIST' modes.
 */
static void
read_archive(struct bsdpax *bsdpax, char mode, struct archive *writer)
{
	struct progress_data	progress_data;
	FILE			 *out;
	struct archive		 *a;
	struct archive_entry	 *entry;
	int			  r;
	int			  listopt, renamed = 0;

	while (*bsdpax->argv) {
		if (bsdpax->option_exclude)
			r = archive_match_exclude_pattern(bsdpax->matching,
			    *bsdpax->argv);
		else
			r = archive_match_include_pattern(bsdpax->matching,
			    *bsdpax->argv);
		if (r != ARCHIVE_OK)
			lafe_errc(1, 0, "Error : %s",
			    archive_error_string(bsdpax->matching));
		bsdpax->argv++;
	}

	a = archive_read_new();
	if (bsdpax->compress_program != NULL)
		archive_read_support_filter_program(a,
		    bsdpax->compress_program);
	else
		archive_read_support_filter_all(a);
	archive_read_support_format_all(a);
	bsdpax_set_options(bsdpax->options, archive_read_set_options, a);
	if (bsdpax->option_ignore_zeros)
		if (archive_read_set_options(a,
		    "read_concatenated_archives") != ARCHIVE_OK)
			lafe_errc(1, 0, "%s", archive_error_string(a));
	if (archive_read_open_filename(a, bsdpax->filename,
					bsdpax->bytes_per_block))
		lafe_errc(1, 0, "Error opening archive: %s",
		    archive_error_string(a));

	if (mode == PAXMODE_READ) {
		/* Set an extract callback so that we can handle SIGINFO. */
		progress_data.bsdpax = bsdpax;
		progress_data.archive = a;
		archive_read_extract_set_progress_callback(a, progress_func,
		    &progress_data);
		/* Create and setup a disk reader. */
		if ((bsdpax->diskenough = archive_read_disk_new()) == NULL)
			lafe_errc(1, 0, "Cannot create read_disk object");
		archive_read_disk_set_standard_lookup(bsdpax->diskenough);
	}

	if (mode == PAXMODE_READ && bsdpax->option_chroot) {
#if HAVE_CHROOT
		if (chroot(".") != 0)
			lafe_errc(1, errno, "Can't chroot to \".\"");
#else
		lafe_errc(1, 0,
		    "chroot isn't supported on this platform");
#endif
	}

	listopt = bsdpax_has_listopt(bsdpax->options);

	for (;;) {
		/* Support --fast-read option */
		if (bsdpax->option_fast_read &&
		    archive_match_path_unmatched_inclusions(
		      bsdpax->matching) == 0)
			break;

		r = archive_read_next_header(a, &entry);
		progress_data.entry = entry;
		if (r == ARCHIVE_EOF)
			break;
		if (r < ARCHIVE_OK)
			lafe_warnc(0, "%s", archive_error_string(a));
		if (r <= ARCHIVE_WARN)
			bsdpax->return_value = 1;
		if (r == ARCHIVE_RETRY) {
			/* Retryable error: try again */
			lafe_warnc(0, "Retrying...");
			continue;
		}
		if (r == ARCHIVE_FATAL)
			break;

		/*
		 * Note that pattern exclusions are checked before
		 * pathname rewrites are handled.  This gives more
		 * control over exclusions, since rewrites always lose
		 * information.  (For example, consider a rewrite
		 * s/foo[0-9]/foo/.  If we check exclusions after the
		 * rewrite, there would be no way to exclude foo1/bar
		 * while allowing foo2/bar.)
		 */
		if (archive_match_excluded(bsdpax->matching, entry))
			continue; /* Excluded by a pattern test. */

		if (mode == PAXMODE_LIST) {
			/* Perversely, gtar uses -O to mean "send to stderr"
			 * when used with -t. */
			out = bsdpax->option_stdout ? stderr : stdout;

			/*
			 * TODO: Provide some reasonable way to
			 * preview rewrites.  gtar always displays
			 * the unedited path in -t output, which means
			 * you cannot easily preview rewrites.
			 */
			if (listopt) {
				r = bsdpax_entry_fprintf(
				    bsdpax->options, out, entry);
				if (r != 0)
					lafe_errc(1, 0,
					    "listopt:invalid format string");
			} else if (bsdpax->verbose < 2) {
				safe_fprintf(out, "%s",
				    archive_entry_pathname(entry));
			} else
				list_item_verbose(bsdpax, out, entry);
			fflush(out);
			r = archive_read_data_skip(a);
			if (r == ARCHIVE_WARN) {
				fprintf(out, "\n");
				lafe_warnc(0, "%s",
				    archive_error_string(a));
			}
			if (r == ARCHIVE_RETRY) {
				fprintf(out, "\n");
				lafe_warnc(0, "%s",
				    archive_error_string(a));
			}
			if (r == ARCHIVE_FATAL) {
				fprintf(out, "\n");
				lafe_warnc(0, "%s",
				    archive_error_string(a));
				bsdpax->return_value = 1;
				break;
			}
			fprintf(out, "\n");
		} else {
			/*
			 * Exclude entries that are older than archived one
			 * which has the same name. (-u, -D option.)
			 */
		    	if (!disk_new_enough(bsdpax,
			      archive_entry_pathname(entry), entry, 0))
				continue;/* Skip it. */

			/* Note: some rewrite failures prevent extraction. */
			if (edit_pathname(bsdpax, entry))
				continue; /* Excluded by a rewrite failure. */

			if (bsdpax->option_interactive) {
				renamed = pax_rename(bsdpax, entry);
				if (renamed < 0)
					break;
				else if (renamed == 0)
					continue;/* Skip it. */
			}

			/*
			 * Exclude entries that are older than archived one
			 * which has the same name. (-Z, -Y option.)
			 */
			if (!disk_new_enough(bsdpax,
			      archive_entry_pathname(entry), entry, 1))
				continue;/* Skip it. */

			if (bsdpax->verbose) {
				safe_fprintf(stderr, "%s",
				    archive_entry_pathname(entry));
				fflush(stderr);
			}

			/*
			 * Overrite attributes.
			 */
			bsdpax_edit_entry(bsdpax->options, entry);

			if (bsdpax->option_no_atime)
				archive_entry_unset_atime(entry);
			if (bsdpax->option_no_mtime)
				archive_entry_unset_mtime(entry);

			// TODO siginfo_printinfo(bsdpax, 0);

			if (bsdpax->option_stdout)
				r = archive_read_data_into_fd(a, 1);
			else
				r = archive_read_extract2(a, entry, writer);
			if (r != ARCHIVE_OK) {
				if (!bsdpax->verbose)
					safe_fprintf(stderr, "%s",
					    archive_entry_pathname(entry));
				safe_fprintf(stderr, ": %s",
				    archive_error_string(a));
				if (!bsdpax->verbose)
					fprintf(stderr, "\n");
				bsdpax->return_value = 1;
			}
			if (bsdpax->verbose)
				fprintf(stderr, "\n");
			if (r == ARCHIVE_FATAL)
				break;
		}
	}


	r = archive_read_close(a);
	if (r != ARCHIVE_OK)
		lafe_warnc(0, "%s", archive_error_string(a));
	if (r <= ARCHIVE_WARN)
		bsdpax->return_value = 1;

	if (bsdpax->verbose) {
		int i;

		fprintf(stderr, "%s: %s,", lafe_progname, archive_format_name(a));
		for (i = 0; archive_filter_code(a, i) > 0; i++)
			if (i > 0)
				fprintf(stderr, "/%s", archive_filter_name(a, i));
			else
				fprintf(stderr, " %s", archive_filter_name(a, i));
		if (i > 0)
			fprintf(stderr, " filters,");
		fprintf(stderr,
		    " %d files, %s bytes read, 0 bytes written\n",
		    archive_file_count(a), pax_i64toa(archive_filter_bytes(a, 0)));
	}
	if (mode == PAXMODE_READ)
		archive_read_free(bsdpax->diskenough);

	archive_read_free(a);
}


/*
 * Display information about the current file.
 *
 * The format here roughly duplicates the output of 'ls -l'.
 * This is based on SUSv2, where 'tar tv' is documented as
 * listing additional information in an "unspecified format,"
 * and 'pax -l' is documented as using the same format as 'ls -l'.
 */
static void
list_item_verbose(struct bsdpax *bsdpax, FILE *out, struct archive_entry *entry)
{
	char			 tmp[100];
	size_t			 w;
	const char		*p;
	const char		*fmt;
	time_t			 tim;
	static time_t		 now;

	/*
	 * We avoid collecting the entire list in memory at once by
	 * listing things as we see them.  However, that also means we can't
	 * just pre-compute the field widths.  Instead, we start with guesses
	 * and just widen them as necessary.  These numbers are completely
	 * arbitrary.
	 */
	if (!bsdpax->u_width) {
		bsdpax->u_width = 6;
		bsdpax->gs_width = 13;
	}
	if (!now)
		time(&now);
	fprintf(out, "%s %d ",
	    archive_entry_strmode(entry),
	    archive_entry_nlink(entry));

	/* Use uname if it's present, else uid. */
	p = archive_entry_uname(entry);
	if ((p == NULL) || (*p == '\0')) {
		sprintf(tmp, "%lu ",
		    (unsigned long)archive_entry_uid(entry));
		p = tmp;
	}
	w = strlen(p);
	if (w > bsdpax->u_width)
		bsdpax->u_width = w;
	fprintf(out, "%-*s ", (int)bsdpax->u_width, p);

	/* Use gname if it's present, else gid. */
	p = archive_entry_gname(entry);
	if (p != NULL && p[0] != '\0') {
		fprintf(out, "%s", p);
		w = strlen(p);
	} else {
		sprintf(tmp, "%lu",
		    (unsigned long)archive_entry_gid(entry));
		w = strlen(tmp);
		fprintf(out, "%s", tmp);
	}

	/*
	 * Print device number or file size, right-aligned so as to make
	 * total width of group and devnum/filesize fields be gs_width.
	 * If gs_width is too small, grow it.
	 */
	if (archive_entry_filetype(entry) == AE_IFCHR
	    || archive_entry_filetype(entry) == AE_IFBLK) {
		sprintf(tmp, "%lu,%lu",
		    (unsigned long)archive_entry_rdevmajor(entry),
		    (unsigned long)archive_entry_rdevminor(entry));
	} else {
		strcpy(tmp, pax_i64toa(archive_entry_size(entry)));
	}
	if (w + strlen(tmp) >= bsdpax->gs_width)
		bsdpax->gs_width = w+strlen(tmp)+1;
	fprintf(out, "%*s", (int)(bsdpax->gs_width - w), tmp);

	/* Format the time using 'ls -l' conventions. */
	tim = archive_entry_mtime(entry);
#define	HALF_YEAR (time_t)365 * 86400 / 2
#if defined(_WIN32) && !defined(__CYGWIN__)
#define	DAY_FMT  "%d"  /* Windows' strftime function does not support %e format. */
#else
#define	DAY_FMT  "%e"  /* Day number without leading zeros */
#endif
	if (tim < now - HALF_YEAR || tim > now + HALF_YEAR)
		fmt = bsdpax->day_first ? DAY_FMT " %b  %Y" : "%b " DAY_FMT "  %Y";
	else
		fmt = bsdpax->day_first ? DAY_FMT " %b %H:%M" : "%b " DAY_FMT " %H:%M";
	strftime(tmp, sizeof(tmp), fmt, localtime(&tim));
	fprintf(out, " %s ", tmp);
	safe_fprintf(out, "%s", archive_entry_pathname(entry));

	/* Extra information for links. */
	if (archive_entry_hardlink(entry)) /* Hard link */
		safe_fprintf(out, " link to %s",
		    archive_entry_hardlink(entry));
	else if (archive_entry_symlink(entry)) /* Symbolic link */
		safe_fprintf(out, " -> %s", archive_entry_symlink(entry));
}

static int
unmatched_inclusions_warn(struct archive *matching, const char *msg)
{
	const char *p;
	int r;

	if (matching == NULL)
		return (0);

	while ((r = archive_match_path_unmatched_inclusions_next(
	    matching, &p)) == ARCHIVE_OK)
		lafe_warnc(0, "%s: %s", p, msg);
	if (r == ARCHIVE_FATAL)
		lafe_errc(1, errno, "Out of memory");

	return (archive_match_path_unmatched_inclusions(matching));
}

