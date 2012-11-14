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
#ifdef HAVE_LINUX_FS_H
#include <linux/fs.h>	/* for Linux file flags */
#endif
/*
 * Some Linux distributions have both linux/ext2_fs.h and ext2fs/ext2_fs.h.
 * As the include guards don't agree, the order of include is important.
 */
#ifdef HAVE_LINUX_EXT2_FS_H
#include <linux/ext2_fs.h>	/* for Linux file flags */
#endif
#if defined(HAVE_EXT2FS_EXT2_FS_H) && !defined(__CYGWIN__)
/* This header exists but is broken on Cygwin. */
#include <ext2fs/ext2_fs.h>
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

static void		 copy_entry(struct bsdpax *, struct archive *,
			     struct archive_entry *);
static void		 copy_disk(struct archive *, struct bsdpax *);
static void		 copy_file(struct bsdpax *, struct archive *,
			     struct archive_entry *, const char *);
static int		 copy_file_data_block(struct bsdpax *,
			     struct archive *);
static int		 copy_hierarchy(struct bsdpax *, struct archive *,
			     const char *);
static char *		 make_destpath(struct bsdpax *, const char *);
static int		 metadata_filter(struct archive *, void *,
			     struct archive_entry *);

void
pax_mode_copy(struct bsdpax *bsdpax)
{
	struct archive *a;

	a = archive_write_disk_new();
	if (a == NULL)
		lafe_errc(1, 0, "Failed to allocate archive object");

	archive_write_disk_set_standard_lookup(a);
	archive_write_disk_set_options(a, bsdpax->extract_flags);

	copy_disk(a, bsdpax);
}

/*
 * Write user-specified files/dirs to opened archive.
 */
static void
copy_disk(struct archive *a, struct bsdpax *bsdpax)
{
	const char *arg;
	int r;

	if ((bsdpax->resolver = archive_entry_linkresolver_new()) == NULL)
		lafe_errc(1, 0, "cannot create link resolver");

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

	/* Create and setup another disk reader. */
	if ((bsdpax->diskenough = archive_read_disk_new()) == NULL)
		lafe_errc(1, 0, "Cannot create read_disk object");
	archive_read_disk_set_standard_lookup(bsdpax->diskenough);

	/*
	 * Get an i-node and dev of the destination directory
	 * to prevent copying itself.
	 * Note: Implimentation of stat() on Windows is poor; we cannot
	 * get proper ino and dev, so we use our libarchive stuff instead.
	 */
	bsdpax->entryenough = archive_entry_new();
	archive_entry_set_pathname(bsdpax->entryenough, bsdpax->destdir);
	archive_entry_copy_sourcepath(bsdpax->entryenough, bsdpax->destdir);
	r = archive_read_disk_entry_from_file(bsdpax->diskenough,
	    bsdpax->entryenough, -1, NULL);
	if (r != ARCHIVE_OK)
		lafe_errc(1, archive_errno(bsdpax->diskenough),
		    "%s", archive_error_string(bsdpax->diskenough));
	bsdpax->dest_dev = archive_entry_dev(bsdpax->entryenough);
	bsdpax->dest_ino = archive_entry_ino(bsdpax->entryenough);

	if (*bsdpax->argv == bsdpax->destdir) {
		struct lafe_line_reader *lr;
		const char *line;

		lr = lafe_line_reader("-", bsdpax->option_null);
		while ((line = lafe_line_reader_next(lr)) != NULL) {
			if (copy_hierarchy(bsdpax, a, line) < 0)
				break;
		}
		lafe_line_reader_free(lr);
	} else {
		while (*bsdpax->argv != bsdpax->destdir) {
			arg = *bsdpax->argv;
			if (copy_hierarchy(bsdpax, a, arg) < 0)
				break;
			bsdpax->argv++;
		}
	}

	if (archive_write_close(a)) {
		lafe_warnc(0, "%s", archive_error_string(a));
		bsdpax->return_value = 1;
	}

	archive_entry_linkresolver_free(bsdpax->resolver);
	bsdpax->resolver = NULL;
	archive_read_free(bsdpax->diskenough);
	archive_read_free(bsdpax->diskreader);
	bsdpax->diskreader = NULL;
	free(bsdpax->destpath);
	bsdpax->destpath = NULL;
	bsdpax->destpath_size = 0;

	archive_write_free(a);
}


static int
metadata_filter(struct archive *a, void *_data, struct archive_entry *entry)
{
	struct bsdpax *bsdpax = (struct bsdpax *)_data;

	/*
	 * Do not copy destination directory itself.
	 */
	if (bsdpax->dest_dev == (int64_t)archive_entry_dev(entry) &&
	    bsdpax->dest_ino == (int64_t)archive_entry_ino(entry)) {
		lafe_warnc(0,
		    "Cannot copy destination directory itself %s",
		    bsdpax->destdir);
		return (0);
	}

	/*
	 * Exclude entries that are older than archived one
	 * which has the same name. (-u, -D option.)
	 */
	if (!disk_new_enough(bsdpax,
	      make_destpath(bsdpax, archive_entry_pathname(entry)), entry, 0))
		return (0);

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
copy_hierarchy(struct bsdpax *bsdpax, struct archive *a, const char *path)
{
	struct archive *disk = bsdpax->diskreader;
	struct archive_entry *entry = NULL, *spare_entry = NULL;
	int r, renamed = 0;
	char *hardlinkpath = NULL;

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
		if (hardlinkpath) {
			free(hardlinkpath);
			hardlinkpath = NULL;
		}
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

		if (bsdpax->option_link &&
		    archive_entry_filetype(entry) == AE_IFREG)
			hardlinkpath = strdup(archive_entry_pathname(entry));

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
			if (!bsdpax->option_no_subdirs)
				archive_read_disk_descend(disk);
			continue;
		}

		/*
		 * Exclude entries that are older than archived one which
		 * has the same name. (-Z, -Y option.)
		 */
		if (!disk_new_enough(bsdpax,
		      make_destpath(bsdpax, archive_entry_pathname(entry)),
		      entry, 1))
			continue;
		archive_entry_copy_pathname(entry, bsdpax->destpath);

		/* Note: if user vetoes, we won't descend. */
		if (!bsdpax->option_no_subdirs)
			archive_read_disk_descend(disk);

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
			copy_file(bsdpax, a, entry, hardlinkpath);
			archive_entry_free(entry);
			entry = spare_entry;
			spare_entry = NULL;
		}

		if (bsdpax->verbose)
			fprintf(stderr, "\n");
	}
	free(hardlinkpath);
	archive_entry_free(entry);
	archive_read_close(disk);

	return (renamed);
}

/*
 * Copy a single file (or directory or other filesystem object) to
 * disk(other directory).
 */
static void
copy_file(struct bsdpax *bsdpax, struct archive *to,
    struct archive_entry *entry, const char *hardlinkpath)
{
	int r;

	if (hardlinkpath) {
		struct archive_entry *t;
		/* Save the original entry in case we need it later. */
		t = archive_entry_clone(entry);
		if (t == NULL)
			lafe_errc(1, ENOMEM, "Can't create link");
		/* Note: link(2) doesn't create parent directories,
		 * so we use archive_write_header() instead as a
		 * convenience. */
		archive_entry_set_hardlink(t, hardlinkpath);
		/* This is a straight link that carries no data. */
		archive_entry_set_size(t, 0);
		r = archive_write_header(to, t);
		archive_entry_free(t);
		if (r == ARCHIVE_FATAL) {
			lafe_errc(1, archive_errno(to),
			    "%s", archive_error_string(to));
		}
#ifdef EXDEV
		if (r != ARCHIVE_OK && archive_errno(to) == EXDEV) {
			/* Cross-device link:  Just fall through and use
			 * the original entry to copy the file over without
			 * an error message. */
			archive_clear_error(to);
		} else
#endif
		{
			if (r != ARCHIVE_OK)
				lafe_warnc(archive_errno(to),
				    "%s", archive_error_string(to));
			return;
		}
	}
	copy_entry(bsdpax, to, entry);
}

/*
 * Copy a single entry to disk(other directory).
 */
static void
copy_entry(struct bsdpax *bsdpax, struct archive *to,
    struct archive_entry *entry)
{
	int e;

	e = archive_write_header(to, entry);
	if (e != ARCHIVE_OK) {
		if (!bsdpax->verbose)
			lafe_warnc(0, "%s: %s",
			    archive_entry_pathname(entry),
			    archive_error_string(to));
		else
			fprintf(stderr, ": %s", archive_error_string(to));
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
		if (copy_file_data_block(bsdpax, to) < 0)
			exit(1);
	}
}

/* Helper function to copy file to disk. */
static int
copy_file_data_block(struct bsdpax *bsdpax, struct archive *a)
{
	size_t	bytes_read;
	ssize_t	bytes_written;
	int64_t	offset;
	const void *buff;
	int r;

	while ((r = archive_read_data_block(bsdpax->diskreader, &buff,
	    &bytes_read, &offset)) == ARCHIVE_OK) {
		bytes_written = archive_write_data_block(a, buff, bytes_read,
		    offset);
		if (bytes_written < ARCHIVE_OK) {
			/* Write failed; this is bad */
			lafe_warnc(0, "%s", archive_error_string(a));
			return (-1);
		}
	}
	if (r < ARCHIVE_WARN) {
		lafe_warnc(archive_errno(a), "%s", archive_error_string(a));
		return (-1);
	}
	return (0);
}

/*
 * Make a destination path from the destination directory and
 * a source path.
 */
static char *
make_destpath(struct bsdpax *bsdpax, const char *path)
{
	size_t len = strlen(path);
	size_t size = bsdpax->destdir_len + 1 + len + 1;

	/* Make sure we have enough buffer to copy a destination path. */
	if (bsdpax->destpath_size < size) {
		free(bsdpax->destpath);
		size = ((size + 1023) / 1024) * 1024;
		bsdpax->destpath = malloc(size);
		if (bsdpax->destpath == NULL)
			lafe_errc(1, ENOMEM,
			    "Failed to make a dist filename by no memory");
		bsdpax->destpath_size = size;
	}

	size = bsdpax->destdir_len;
	memcpy(bsdpax->destpath, bsdpax->destdir, size);
	if (size > 0 && bsdpax->destpath[size-1] != '/')
		bsdpax->destpath[size++] = '/';
	memcpy(bsdpax->destpath+size, path, len);
	size += len;
	bsdpax->destpath[size] = '\0';
	return (bsdpax->destpath);
}
