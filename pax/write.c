/*-
 * Copyright (c) 2003-2010 Tim Kientzle
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

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_ATTR_XATTR_H
#include <attr/xattr.h>
#endif
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_GRP_H
#include <grp.h>
#endif
#ifdef HAVE_IO_H
#include <io.h>
#endif
#ifdef HAVE_LIBGEN_H
#include <libgen.h>
#endif
#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif
#ifdef HAVE_PATHS_H
#include <paths.h>
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
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "bsdpax.h"
#include "err.h"
#include "line_reader.h"

#ifndef O_BINARY
#define	O_BINARY 0
#endif

static int		 append_archive(struct bsdpax *, struct archive *,
			     struct archive *ina);
static int		 append_archive_filename(struct bsdpax *,
			     struct archive *, const char *fname);
static int		 copy_file_data_block(struct bsdpax *, struct archive *,
			     struct archive *, struct archive_entry *);
static void		 report_write(struct bsdpax *, struct archive *,
			     struct archive_entry *, int64_t progress);
static void		 test_for_append(struct bsdpax *);
static int		 metadata_filter(struct archive *, void *,
			    struct archive_entry *);
static void		 write_archive(struct archive *, struct bsdpax *);
static void		 write_entry(struct bsdpax *, struct archive *,
			     struct archive_entry *);
static void		 write_file(struct bsdpax *, struct archive *,
			     struct archive_entry *);
static int		 write_hierarchy(struct bsdpax *, struct archive *,
			     const char *);

#if defined(_WIN32) && !defined(__CYGWIN__)
/* Not a full lseek() emulation, but enough for our needs here. */
static int
seek_file(int fd, int64_t offset, int whence)
{
	LARGE_INTEGER distance;
	(void)whence; /* UNUSED */
	distance.QuadPart = offset;
	return (SetFilePointerEx((HANDLE)_get_osfhandle(fd),
		distance, NULL, FILE_BEGIN) ? 1 : -1);
}
#define	open _open
#define	close _close
#define	lseek seek_file
#endif

void
pax_mode_write(struct bsdpax *bsdpax)
{
	struct archive *a;
	int r;

	a = archive_write_new();

	/* Support any format that the library supports. */
	if (bsdpax->create_format == NULL) {
		r = archive_write_set_format_pax_restricted(a);
		bsdpax->create_format = "pax restricted";
	} else {
		r = archive_write_set_format_by_name(a, bsdpax->create_format);
	}
	if (r != ARCHIVE_OK) {
		fprintf(stderr, "Can't use format %s: %s\n",
		    bsdpax->create_format,
		    archive_error_string(a));
		usage();
	}

	archive_write_set_bytes_per_block(a, bsdpax->bytes_per_block);
	archive_write_set_bytes_in_last_block(a, bsdpax->bytes_in_last_block);

	if (bsdpax->compress_program) {
		archive_write_add_filter_program(a, bsdpax->compress_program);
	} else {
		switch (bsdpax->create_compression) {
		case 0:
			r = ARCHIVE_OK;
			break;
		case 'j':
			r = archive_write_add_filter_bzip2(a);
			break;
		case 'J':
			r = archive_write_add_filter_xz(a);
			break;
		case OPTION_LZIP:
			r = archive_write_add_filter_lzip(a);
			break;
		case OPTION_LZMA:
			r = archive_write_add_filter_lzma(a);
			break;
		case 'z':
			r = archive_write_add_filter_gzip(a);
			break;
		case OPTION_COMPRESS:
			r = archive_write_add_filter_compress(a);
			break;
		default:
			lafe_errc(1, 0,
			    "Unrecognized compression option -%c",
			    bsdpax->create_compression);
		}
		if (r != ARCHIVE_OK) {
			const char *zname;
			switch (bsdpax->create_compression) {
			case OPTION_LZIP: zname = "lzip"; break;
			case OPTION_LZMA: zname = "lzma"; break;
			case OPTION_COMPRESS: zname = "compress"; break;
			default: zname = NULL; break;
			}
			if (zname == NULL)
				lafe_errc(1, 0,
				    "Unsupported compression option -%c",
				    bsdpax->create_compression);
			else
				lafe_errc(1, 0,
				    "Unsupported compression option --%s",
				    zname);
		}
	}

	if (bsdpax->option_keep_newer_mtime_files_ar) {
		bsdpax->matching2 = archive_match_new();
		if (bsdpax->matching2 == NULL)
			lafe_errc(1, 0, "Out of memory");
	}
	bsdpax_set_options(bsdpax->options, archive_write_set_options, a);
	if (ARCHIVE_OK != archive_write_open_file(a, bsdpax->filename))
		lafe_errc(1, 0, "%s", archive_error_string(a));
	write_archive(a, bsdpax);
	if (bsdpax->matching2 != NULL) {
		archive_match_free(bsdpax->matching2);
		bsdpax->matching2 = NULL;
	}
}

void
pax_mode_append(struct bsdpax *bsdpax)
{
	int64_t			 end_offset;
	struct archive		*a;
	struct archive_entry	*entry;
	int			 format;

	format = ARCHIVE_FORMAT_TAR_PAX_RESTRICTED;

	/* Sanity-test some arguments and the file. */
	test_for_append(bsdpax);

	bsdpax->fd = open(bsdpax->filename, O_RDWR | O_BINARY);
	if (bsdpax->fd < 0)
		lafe_errc(1, errno,
		    "Cannot open %s", bsdpax->filename);

	a = archive_read_new();
	archive_read_support_filter_all(a);
	archive_read_support_format_empty(a);
	archive_read_support_format_tar(a);
	archive_read_support_format_gnutar(a);
	if (archive_read_open_fd(a, bsdpax->fd, bsdpax->bytes_per_block)
	    != ARCHIVE_OK) {
		lafe_errc(1, 0,
		    "Can't open %s: %s", bsdpax->filename,
		    archive_error_string(a));
	}

	if (bsdpax->option_keep_newer_mtime_files_ar) {
		bsdpax->matching2 = archive_match_new();
		if (bsdpax->matching2 == NULL)
			lafe_errc(1, 0, "Out of memory");
	}
	/* Build a list of all entries and their recorded mod times. */
	while (0 == archive_read_next_header(a, &entry)) {
		if (archive_compression(a) != ARCHIVE_COMPRESSION_NONE) {
			archive_read_free(a);
			close(bsdpax->fd);
			lafe_errc(1, 0,
			    "Cannot append to compressed archive.");
		}
		if (bsdpax->option_keep_newer_mtime_files_br) {
			if (archive_match_exclude_entry(
			    bsdpax->matching,
			    ARCHIVE_MATCH_MTIME |
			    ARCHIVE_MATCH_OLDER | ARCHIVE_MATCH_EQUAL,
			    entry) != ARCHIVE_OK)
				lafe_errc(1, 0, "Error : %s",
				    archive_error_string(bsdpax->matching));
		}
		if (bsdpax->option_keep_newer_mtime_files_ar) {
			if (archive_match_exclude_entry(
			    bsdpax->matching2,
			    ARCHIVE_MATCH_MTIME |
			    ARCHIVE_MATCH_OLDER | ARCHIVE_MATCH_EQUAL,
			    entry) != ARCHIVE_OK)
				lafe_errc(1, 0, "Error : %s",
				    archive_error_string(bsdpax->matching2));
		}
		/* Record the last format determination we see */
		format = archive_format(a);
		/* Keep going until we hit end-of-archive */
	}

	end_offset = archive_read_header_position(a);
	archive_read_free(a);

	/* Re-open archive for writing. */
	a = archive_write_new();
	archive_write_set_format(a, format);
	archive_write_set_bytes_per_block(a, bsdpax->bytes_per_block);
	archive_write_set_bytes_in_last_block(a, bsdpax->bytes_in_last_block);

	if (lseek(bsdpax->fd, end_offset, SEEK_SET) < 0)
		lafe_errc(1, errno, "Could not seek to archive end");
	bsdpax_set_options(bsdpax->options, archive_write_set_options, a);
	if (ARCHIVE_OK != archive_write_open_fd(a, bsdpax->fd))
		lafe_errc(1, 0, "%s", archive_error_string(a));

	write_archive(a, bsdpax);

	if (bsdpax->matching2 != NULL) {
		archive_match_free(bsdpax->matching2);
		bsdpax->matching2 = NULL;
	}
	close(bsdpax->fd);
	bsdpax->fd = -1;
}

/*
 * Write user-specified files/dirs to opened archive.
 */
static void
write_archive(struct archive *a, struct bsdpax *bsdpax)
{
	const char *arg;
	struct archive_entry *entry, *sparse_entry;

	/* Allocate a buffer for null data. */
	bsdpax->buff_size = 32 * 1024;
	if ((bsdpax->buff = malloc(bsdpax->buff_size)) == NULL)
		lafe_errc(1, 0, "cannot allocate memory");

	if ((bsdpax->resolver = archive_entry_linkresolver_new()) == NULL)
		lafe_errc(1, 0, "cannot create link resolver");
	archive_entry_linkresolver_set_strategy(bsdpax->resolver,
	    archive_format(a));

	/* Create and setup a disk reader. */
	if ((bsdpax->diskreader = archive_read_disk_new()) == NULL)
		lafe_errc(1, 0, "Cannot create read_disk object");
	/* Notify how handle symlink to the read_disk object. */
	switch (bsdpax->symlink_mode) {
	case 'H':
		archive_read_disk_set_symlink_hybrid(bsdpax->diskreader);
		break;
	case 'L':
		archive_read_disk_set_symlink_logical(bsdpax->diskreader);
		break;
	default:
		archive_read_disk_set_symlink_physical(bsdpax->diskreader);
		break;
	}
	archive_read_disk_set_matching(bsdpax->diskreader,
	    bsdpax->matching, NULL, NULL);
	archive_read_disk_set_metadata_filter_callback(bsdpax->diskreader,
	    metadata_filter, bsdpax);
	archive_read_disk_set_behavior(bsdpax->diskreader,
	    bsdpax->readdisk_flags);
	archive_read_disk_set_standard_lookup(bsdpax->diskreader);

	if (*bsdpax->argv == NULL) {
		/*
		 * Archive names specified in file.
		 */
		struct lafe_line_reader *lr;
		const char *line;

		lr = lafe_line_reader("-", bsdpax->option_null);
		while ((line = lafe_line_reader_next(lr)) != NULL) {
			if (write_hierarchy(bsdpax, a, line) < 0)
				break;
		}
		lafe_line_reader_free(lr);
	}
	while (*bsdpax->argv != NULL) {
		arg = *bsdpax->argv;
		if (bsdpax->mode == PAXMODE_WRITE && *arg == '@') {
			if (append_archive_filename(bsdpax, a, arg + 1) != 0)
				break;
		} else {
			if (write_hierarchy(bsdpax, a, arg) < 0)
				break;
		}
		bsdpax->argv++;
	}

	archive_read_disk_set_matching(bsdpax->diskreader, NULL, NULL, NULL);
	archive_read_disk_set_metadata_filter_callback(
	    bsdpax->diskreader, NULL, NULL);
	entry = NULL;
	archive_entry_linkify(bsdpax->resolver, &entry, &sparse_entry);
	while (entry != NULL) {
		int r;
		struct archive_entry *entry2;
		struct archive *disk = bsdpax->diskreader;

		/*
		 * This tricky code here is to correctly read the cotents
		 * of the entry because the disk reader bsdpax->diskreader
		 * is pointing at does not have any information about the
		 * entry by this time and using archive_read_data_block()
		 * with the disk reader consequently must fail. And we
		 * have to re-open the entry to read the contents.
		 */
		/* TODO: Work with -C option as well. */
		r = archive_read_disk_open(disk,
			archive_entry_sourcepath(entry));
		if (r != ARCHIVE_OK) {
			lafe_warnc(archive_errno(disk),
			    "%s", archive_error_string(disk));
			bsdpax->return_value = 1;
			archive_entry_free(entry);
			continue;
		}

		/*
		 * Invoke archive_read_next_header2() to work
		 * archive_read_data_block(), which is called via write_file(),
		 * without failure.
		 */
		entry2 = archive_entry_new();
		r = archive_read_next_header2(disk, entry2);
		archive_entry_free(entry2);
		if (r != ARCHIVE_OK) {
			lafe_warnc(archive_errno(disk),
			    "%s", archive_error_string(disk));
			if (r == ARCHIVE_FATAL)
				bsdpax->return_value = 1;
			else
				archive_read_close(disk);
			archive_entry_free(entry);
			continue;
		}

		write_file(bsdpax, a, entry);
		archive_entry_free(entry);
		archive_read_close(disk);
		entry = NULL;
		archive_entry_linkify(bsdpax->resolver, &entry, &sparse_entry);
	}

	if (archive_write_close(a)) {
		lafe_warnc(0, "%s", archive_error_string(a));
		bsdpax->return_value = 1;
	}

	/* Free file data buffer. */
	free(bsdpax->buff);
	archive_entry_linkresolver_free(bsdpax->resolver);
	bsdpax->resolver = NULL;
	archive_read_free(bsdpax->diskreader);
	bsdpax->diskreader = NULL;

	if (bsdpax->verbose) {
		int i;

		fprintf(stderr, "%s: %s,", lafe_progname, archive_format_name(a));
		for (i = 0; archive_filter_code(a, i) > 0; i++) {
			if (i > 0)
				fprintf(stderr, "/%s", archive_filter_name(a, i));
			else
				fprintf(stderr, " %s", archive_filter_name(a, i));
		}
		if (i > 0)
			fprintf(stderr, " filters,");
		fprintf(stderr,
		    " %d files, 0 bytes read, %s bytes written\n",
		    archive_file_count(a),
		    pax_i64toa(archive_filter_bytes(a, -1)));
	}

	archive_write_free(a);
}

/*
 * Copy from specified archive to current archive.  Returns non-zero
 * for write errors (which force us to terminate the entire archiving
 * operation).  If there are errors reading the input archive, we set
 * bsdpax->return_value but return zero, so the overall archiving
 * operation will complete and return non-zero.
 */
static int
append_archive_filename(struct bsdpax *bsdpax, struct archive *a,
    const char *raw_filename)
{
	struct archive *ina;
	const char *filename = raw_filename;
	int rc;

	if (strcmp(filename, "-") == 0)
		filename = NULL; /* Library uses NULL for stdio. */

	ina = archive_read_new();
	archive_read_support_format_all(ina);
	archive_read_support_filter_all(ina);
	if (archive_read_open_file(ina, filename, bsdpax->bytes_per_block)) {
		lafe_warnc(0, "%s", archive_error_string(ina));
		bsdpax->return_value = 1;
		return (0);
	}

	rc = append_archive(bsdpax, a, ina);

	if (rc != ARCHIVE_OK) {
		lafe_warnc(0, "Error reading archive %s: %s",
		    raw_filename, archive_error_string(ina));
		bsdpax->return_value = 1;
	}
	archive_read_free(ina);

	return (rc);
}

static int
append_archive(struct bsdpax *bsdpax, struct archive *a, struct archive *ina)
{
	struct archive_entry *in_entry;
	int e, renamed = 0;

	while (ARCHIVE_OK == (e = archive_read_next_header(ina, &in_entry))) {
		/*
		 * Exclude entries that are specified.
		 */
		if (archive_match_excluded(bsdpax->matching, in_entry))
			continue;/* Skip it. */

		if (bsdpax->option_interactive) {
			renamed = pax_rename(bsdpax, in_entry);
			if (renamed < 0)
				break; /* Do not add the following entries. */
			else if (renamed == 0)
				continue;/* Skip this entry. */
		}

		/*
		 * Exclude entries that are older than archived one which
		 * has the same name. (-Z option.)
		 */
		if (bsdpax->option_keep_newer_mtime_files_ar &&
		    archive_match_time_excluded(bsdpax->matching2, in_entry))
			continue;

		if (bsdpax->verbose)
			safe_fprintf(stderr, "%s",
			    archive_entry_pathname(in_entry));
		if (need_report())
			report_write(bsdpax, a, in_entry, 0);

		/*
		 * Overrite attributes.
		 */
		bsdpax_edit_entry(bsdpax->options, in_entry);

		e = archive_write_header(a, in_entry);
		if (e != ARCHIVE_OK) {
			if (!bsdpax->verbose)
				lafe_warnc(0, "%s: %s",
				    archive_entry_pathname(in_entry),
				    archive_error_string(a));
			else
				fprintf(stderr, ": %s", archive_error_string(a));
		}
		if (e == ARCHIVE_FATAL)
			exit(1);

		if (e >= ARCHIVE_WARN) {
			if (archive_entry_size(in_entry) == 0)
				archive_read_data_skip(ina);
			else if (copy_file_data_block(bsdpax, a, ina, in_entry))
				exit(1);
		}

		if (bsdpax->verbose)
			fprintf(stderr, "\n");
	}

	return (e == ARCHIVE_EOF ? ARCHIVE_OK : e);
}

static int
metadata_filter(struct archive *a, void *_data, struct archive_entry *entry)
{
	struct bsdpax *bsdpax = (struct bsdpax *)_data;

	(void)entry; /* UNUSED */
	/*
	 * User has asked us not to cross mount points.
	 */
	if (bsdpax->option_dont_traverse_mounts) {
		int fs = archive_read_disk_current_filesystem(a);
		if (bsdpax->first_fs == -1)
			bsdpax->first_fs = fs;
		else if (bsdpax->first_fs != fs)
			return (0);
	}

	return (1);
}

/*
 * Add the file or dir hierarchy named by 'path' to the archive
 */
static int
write_hierarchy(struct bsdpax *bsdpax, struct archive *a, const char *path)
{
	struct archive *disk = bsdpax->diskreader;
	struct archive_entry *entry = NULL, *spare_entry = NULL;
	int r, renamed = 0;

	bsdpax->first_fs = -1;
	r = archive_read_disk_open(disk, path);
	if (r != ARCHIVE_OK) {
		lafe_warnc(archive_errno(disk),
		    "%s", archive_error_string(disk));
		if (r == ARCHIVE_FATAL)
			exit(1);
		else if (r < ARCHIVE_WARN)
			return (-1);
	}

	for (;;) {
		archive_entry_free(entry);
		entry = archive_entry_new();
		r = archive_read_next_header2(disk, entry);
		if (r == ARCHIVE_EOF)
			break;
		else if (r != ARCHIVE_OK) {
			lafe_warnc(archive_errno(disk),
			    "%s", archive_error_string(disk));
			if (r == ARCHIVE_FATAL)
				exit(1);
			else if (r < ARCHIVE_WARN)
				continue;
		}

		/*
		 * If the user vetoes this file/directory, skip it.
		 * We want this to be fairly late; if some other
		 * check would veto this file, we shouldn't bother
		 * the user with it.
		 */
		if (bsdpax->option_interactive) {
			renamed = pax_rename(bsdpax, entry);
			if (renamed < 0)
				break; /* Do not add the following entries. */
			else if (renamed == 0)
				continue;/* Skip this entry. */
		}

		/*
		 * Rewrite the pathname to be archived.  If rewrite
		 * fails, skip the entry.
		 */
		if (edit_pathname(bsdpax, entry)) {
			/* Note: if user vetoes, we won't descend. */
			if (!bsdpax->option_no_subdirs &&
			    archive_read_disk_can_descend(disk))
				archive_read_disk_descend(disk);
			continue;
		}

		/*
		 * Exclude entries that are older than archived one which
		 * has the same name. (-Z options)
		 */
		if (bsdpax->option_keep_newer_mtime_files_ar &&
		    archive_match_time_excluded(bsdpax->matching2, entry))
			continue;

		/* Note: if user vetoes, we won't descend. */
		if (!bsdpax->option_no_subdirs &&
		    archive_read_disk_can_descend(disk))
			archive_read_disk_descend(disk);

		/* Update timestamps archived in the archive file. */ 
		if (bsdpax->option_keep_newer_mtime_files_br) {
			if (archive_match_exclude_entry(
			    bsdpax->matching,
			    ARCHIVE_MATCH_MTIME |
			    ARCHIVE_MATCH_OLDER | ARCHIVE_MATCH_EQUAL,
			    entry) != ARCHIVE_OK)
				lafe_errc(1, 0, "Error : %s",
				    archive_error_string(bsdpax->matching));
		}
		if (bsdpax->option_keep_newer_mtime_files_ar) {
			if (archive_match_exclude_entry(
			    bsdpax->matching2,
			    ARCHIVE_MATCH_MTIME |
			    ARCHIVE_MATCH_OLDER | ARCHIVE_MATCH_EQUAL,
			    entry) != ARCHIVE_OK)
				lafe_errc(1, 0, "Error : %s",
				    archive_error_string(bsdpax->matching2));
		}

		/* Display entry as we process it. */
		if (bsdpax->verbose)
			safe_fprintf(stderr, "%s",
			    archive_entry_pathname(entry));

		/* Non-regular files get archived with zero size. */
		if (archive_entry_filetype(entry) != AE_IFREG)
			archive_entry_set_size(entry, 0);

		/*
		 * Overrite attributes.
		 */
		bsdpax_edit_entry(bsdpax->options, entry);

		archive_entry_linkify(bsdpax->resolver, &entry, &spare_entry);

		while (entry != NULL) {
			write_file(bsdpax, a, entry);
			archive_entry_free(entry);
			entry = spare_entry;
			spare_entry = NULL;
		}

		if (bsdpax->verbose)
			fprintf(stderr, "\n");
	}
	archive_entry_free(entry);
	archive_read_close(disk);

	return (renamed);
}

/*
 * Write a single file (or directory or other filesystem object) to
 * the archive.
 */
static void
write_file(struct bsdpax *bsdpax, struct archive *a, struct archive_entry *entry)
{
	write_entry(bsdpax, a, entry);
}

/*
 * Write a single entry to the archive.
 */
static void
write_entry(struct bsdpax *bsdpax, struct archive *a,
    struct archive_entry *entry)
{
	int e;

	e = archive_write_header(a, entry);
	if (e != ARCHIVE_OK) {
		if (!bsdpax->verbose)
			lafe_warnc(0, "%s: %s",
			    archive_entry_pathname(entry),
			    archive_error_string(a));
		else
			fprintf(stderr, ": %s", archive_error_string(a));
	}

	if (e == ARCHIVE_FATAL)
		exit(1);

	/*
	 * If we opened a file earlier, write it out now.  Note that
	 * the format handler might have reset the size field to zero
	 * to inform us that the archive body won't get stored.  In
	 * that case, just skip the write.
	 */
	if (e >= ARCHIVE_WARN && archive_entry_size(entry) > 0) {
		if (copy_file_data_block(bsdpax, a, bsdpax->diskreader, entry))
			exit(1);
	}
}

static void
report_write(struct bsdpax *bsdpax, struct archive *a,
    struct archive_entry *entry, int64_t progress)
{
	uint64_t comp, uncomp;
	int compression;

	if (bsdpax->verbose)
		fprintf(stderr, "\n");
	comp = archive_position_compressed(a);
	uncomp = archive_position_uncompressed(a);
	fprintf(stderr, "In: %d files, %s bytes;",
	    archive_file_count(a), pax_i64toa(uncomp));
	if (comp > uncomp)
		compression = 0;
	else
		compression = (int)((uncomp - comp) * 100 / uncomp);
	fprintf(stderr,
	    " Out: %s bytes, compression %d%%\n",
	    pax_i64toa(comp), compression);
	/* Can't have two calls to pax_i64toa() pending, so split the output. */
	safe_fprintf(stderr, "Current: %s (%s",
	    archive_entry_pathname(entry),
	    pax_i64toa(progress));
	fprintf(stderr, "/%s bytes)\n",
	    pax_i64toa(archive_entry_size(entry)));
}


/* Helper function to copy file to archive. */
static int
copy_file_data_block(struct bsdpax *bsdpax, struct archive *a,
    struct archive *in_a, struct archive_entry *entry)
{
	size_t	bytes_read;
	ssize_t	bytes_written;
	int64_t	offset, progress = 0;
	char *null_buff = NULL;
	const void *buff;
	int r;

	while ((r = archive_read_data_block(in_a, &buff,
	    &bytes_read, &offset)) == ARCHIVE_OK) {
		if (need_report())
			report_write(bsdpax, a, entry, progress);

		if (offset > progress) {
			int64_t sparse = offset - progress;
			size_t ns;

			if (null_buff == NULL) {
				null_buff = bsdpax->buff;
				memset(null_buff, 0, bsdpax->buff_size);
			}

			while (sparse > 0) {
				if (sparse > bsdpax->buff_size)
					ns = bsdpax->buff_size;
				else
					ns = (size_t)sparse;
				bytes_written =
				    archive_write_data(a, null_buff, ns);
				if (bytes_written < 0) {
					/* Write failed; this is bad */
					lafe_warnc(0, "%s",
					     archive_error_string(a));
					return (-1);
				}
				if ((size_t)bytes_written < ns) {
					/* Write was truncated; warn but
					 * continue. */
					lafe_warnc(0,
					    "%s: Truncated write; file may "
					    "have grown while being archived.",
					    archive_entry_pathname(entry));
					return (0);
				}
				progress += bytes_written;
				sparse -= bytes_written;
			}
		}

		bytes_written = archive_write_data(a, buff, bytes_read);
		if (bytes_written < 0) {
			/* Write failed; this is bad */
			lafe_warnc(0, "%s", archive_error_string(a));
			return (-1);
		}
		if ((size_t)bytes_written < bytes_read) {
			/* Write was truncated; warn but continue. */
			lafe_warnc(0,
			    "%s: Truncated write; file may have grown "
			    "while being archived.",
			    archive_entry_pathname(entry));
			return (0);
		}
		progress += bytes_written;
	}
	if (r < ARCHIVE_WARN) {
		lafe_warnc(archive_errno(a), "%s", archive_error_string(a));
		return (-1);
	}
	return (0);
}

static void
test_for_append(struct bsdpax *bsdpax)
{
	struct stat s;

	if (bsdpax->filename == NULL)
		lafe_errc(1, 0, "Cannot append to stdout.");

	if (bsdpax->create_compression != 0)
		lafe_errc(1, 0,
		    "Cannot append to %s with compression", bsdpax->filename);

	if (stat(bsdpax->filename, &s) != 0)
		return;

	if (!S_ISREG(s.st_mode) && !S_ISBLK(s.st_mode))
		lafe_errc(1, 0,
		    "Cannot append to %s: not a regular file.",
		    bsdpax->filename);

/* Is this an appropriate check here on Windows? */
/*
	if (GetFileType(handle) != FILE_TYPE_DISK)
		lafe_errc(1, 0, "Cannot append");
*/

}

