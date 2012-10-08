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
 *
 * $FreeBSD$
 */

#include "bsdpax_platform.h"
#include <stdio.h>

#include "options.h"

#define	DEFAULT_BYTES_PER_BLOCK	(20*512)

/*
 * The internal state for the "bsdpax" program.
 *
 * Keeping all of the state in a structure like this simplifies memory
 * leak testing (at exit, anything left on the heap is suspect).  A
 * pointer to this structure is passed to most bsdpax internal
 * functions.
 */
struct bsdpax {
	/* Options */
	const char	 *filename; /* -f filename */
	const char	 *create_format; /* -x format */
	const char	 *destdir; /* -r -w Copy mode */
	size_t		  destdir_len;
	int64_t		  dest_dev;
	int64_t		  dest_ino;
	int		  bytes_per_block; /* -b block_size */
	int		  bytes_in_last_block; /* See -b handling. */
	int		  verbose;   /* -v */
	int		  extract_flags; /* Flags for extract operation */
	int		  readdisk_flags; /* Flags for read disk operation */
	int		  strip_components; /* Remove this many leading dirs */
	char		  mode; /* Program mode */
#define PAXMODE_LIST	1
#define PAXMODE_READ	2
#define PAXMODE_WRITE	4
#define PAXMODE_COPY	8

	char		  symlink_mode; /* H or L, per BSD conventions */
	char		  create_compression; /* J, j, y, or z */
	const char	 *compress_program;
	char		  add_filter; /* uuencode */
	char		  option_absolute_paths; /* -P */
	char		  option_chroot; /* --chroot */
	char		  option_dont_traverse_mounts; /* --one-file-system */
	char		  option_exclude;
	char		  option_fast_read; /* -n */
	char		  option_keep_newer_mtime_files_br;/* -u option */
	char		  option_keep_newer_ctime_files_br;/* -D option */
	char		  option_keep_newer_mtime_files_ar;/* -Z option */
	char		  option_keep_newer_ctime_files_ar;/* -Y option */
	char		  option_interactive; /* -i */
	char		  option_link; /* -l */
	char		  option_no_owner; /* -o */
	char		  option_no_subdirs; /* -d */
	char		  option_numeric_owner; /* --numeric-owner */
	char		  option_null; /* --null */
	char		  option_no_atime;/* -p a */
	char		  option_no_mtime;/* -p m */
	char		  option_stdout; /* -O */
	char		  option_unlink_first; /* -U */
	char		  option_warn_links; /* --check-links */
	char		  day_first; /* show day before month in -v output */

	/* Option parser state */
	int		  getopt_state;
	char		 *getopt_word;

	/* If >= 0, then close this when done. */
	int		  fd;

	/* Miscellaneous state information */
	int		  argc;
	char		**argv;
	const char	 *argument;
	size_t		  gs_width; /* For 'list_item' in read.c */
	size_t		  u_width; /* for 'list_item' in read.c */
	uid_t		  user_uid; /* UID running this program */
	int		  return_value; /* Value returned by main() */
	char		  warned_lead_slash; /* Already displayed warning */

	/*
	 * Data for various subsystems.  Full definitions are located in
	 * the file where they are used.
	 */
	struct archive		*diskreader;	/* for write.c/copy.c */
	struct archive		*diskenough;	/* for write.c/copy.c/util.c */
	struct archive_entry	*entryenough;	/* for util.c */
	struct archive_entry_linkresolver *resolver; /* for write.c */
	struct name_cache	*gname_cache;	/* for write.c */
	int			 first_fs;	/* for write.c */
	char			*buff;		/* for write.c */
	size_t			 buff_size;	/* for write.c */
	char			*destpath;	/* for copy.c */
	size_t			 destpath_size;	/* for copy.c */
	struct archive		*matching;	/* for copy.c/read.c/write.c */
	struct archive		*matching2;	/* for write.c */
	struct security		*security;	/* for read.c */
	struct name_cache	*uname_cache;	/* for write.c */
	struct siginfo_data	*siginfo;	/* for siginfo.c */
	struct substitution	*substitution;	/* for subst.c */
	struct bsdpax_options	*options;	/* for read.c or write.c */
};

/* Fake short equivalents for long options that otherwise lack them. */
enum {
	OPTION_B64ENCODE = 1,
	OPTION_COMPRESS,
	OPTION_DISABLE_COPYFILE,
	OPTION_HELP,
	OPTION_INSECURE,
	OPTION_LRZIP,
	OPTION_LZIP,
	OPTION_LZMA,
	OPTION_LZOP,
	OPTION_NODUMP,
	OPTION_NULL,
	OPTION_STRIP_COMPONENTS,
	OPTION_USE_COMPRESS_PROGRAM,
	OPTION_UUENCODE,
	OPTION_VERSION
};

int	bsdpax_getopt(struct bsdpax *);
int	edit_pathname(struct bsdpax *, struct archive_entry *);
int	need_report(void);
int	pathcmp(const char *a, const char *b);
void	safe_fprintf(FILE *, const char *fmt, ...);
const char *pax_i64toa(int64_t);
void	pax_mode_write(struct bsdpax *bsdpax);
void	pax_mode_append(struct bsdpax *bsdpax);
void	pax_mode_copy(struct bsdpax *bsdpax);
void	pax_mode_list(struct bsdpax *bsdpax);
void	pax_mode_read(struct bsdpax *bsdpax);
void	usage(void);
int	pax_rename(struct bsdpax *bsdpax, struct archive_entry *entry);
int	add_user(struct bsdpax *bsdpax, const char *user);
int	add_group(struct bsdpax *bsdpax, const char *group);
int	excluded_entry(struct bsdpax *bsdpax, struct archive_entry *entry);
int	disk_new_enough(struct bsdpax *bsdpax, const char *path,
	    struct archive_entry *entry, int);


#if HAVE_REGEX_H
void	add_substitution(struct bsdpax *, const char *);
int	apply_substitution(struct bsdpax *, const char *, char **, int, int);
void	cleanup_substitution(struct bsdpax *);
#endif
