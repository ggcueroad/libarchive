/*-
 * Copyright (c) 2008,2009 Michihiro NAKAJIMA
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

#include "archive_platform.h"

#include <sys/queue.h>
#include <sys/types.h>
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif
#include <stdio.h>


#include "archive.h"
#include "archive_entry.h"
#include "archive_private.h"
#include "archive_write_private.h"
#include "archive_endian.h"
#include "lha.h"


#define LIMIT_OF_HEADER_SIZE	4096

struct data_entry {
	size_t	s;
	char 	*buff;
	STAILQ_ENTRY(data_entry) next;
};

struct data_area {
	size_t	total;
	STAILQ_HEAD(, data_entry) entrylist;
};


struct lha {
	int			default_method;
	int			method;
	struct lha_stream	stream;
	uint64_t		entry_bytes_remaining;

	struct archive_string	pathname;
	struct archive_string	dirname;
	struct archive_string	filename;

	size_t			compsize;	/* compressed data size */
	size_t			origsize;	/* original data size	*/
	time_t			ctime;
	long			ctime_tv_nsec;
	time_t			mtime;
	long			mtime_tv_nsec;
	time_t			atime;
	long			atime_tv_nsec;
	mode_t			mode;
	__LA_GID_T		gid;
	__LA_UID_T		uid;
	struct archive_string	gname;
	struct archive_string	uname;
	uint16_t		crc;

	struct data_area	origdata;
	struct data_area	compdata;
	unsigned char 		outbuff[4096];
};

static int		 archive_write_lha_header(struct archive_write *,
			     struct archive_entry *);
static ssize_t		 archive_write_lha_data(struct archive_write *,
			     const void *buff, size_t s);
static int		 archive_write_lha_destroy(struct archive_write *);
static int		 archive_write_lha_finish(struct archive_write *);
static int		 archive_write_lha_finish_entry(struct archive_write *);
static void		 lha_split_path(struct lha *lha);
static int		 lha_write_header(struct archive_write *a,
			     struct lha *lha);
static void		 data_area_init(struct data_area *area);
static int		 data_area_save(struct archive_write *a,
			     struct data_area *area,
			     const void *buff, size_t s);
static void		 data_area_free(struct data_area *area);
static int		 data_area_write(struct archive_write *a,
			     struct data_area *area);
static uint64_t		 lha_to_win_time(time_t time, long ns);


/*
 * Set output format to 'lha' format.
 */
int
archive_write_set_format_lha(struct archive *_a)
{
	struct archive_write *a = (struct archive_write *)_a;
	struct lha *lha;

	/* If someone else was already registered, unregister them. */
	if (a->format_destroy != NULL)
		(a->format_destroy)(a);

	lha = (struct lha *)malloc(sizeof(*lha));
	if (lha == NULL) {
		archive_set_error(&a->archive, ENOMEM, "Can't allocate lha data");
		return (ARCHIVE_FATAL);
	}
	memset(lha, 0, sizeof(*lha));
	lha->default_method = LHA_METHOD_LH5;
	__lha_encodeInit(&lha->stream, lha->default_method);

	a->format_data = lha;
	a->format_name = "lha";
	a->format_options = NULL;
	a->format_write_header = archive_write_lha_header;
	a->format_write_data = archive_write_lha_data;
	a->format_finish_entry = archive_write_lha_finish_entry;
	a->format_finish = archive_write_lha_finish;
	a->format_destroy = archive_write_lha_destroy;
	a->archive.archive_format = ARCHIVE_FORMAT_LHA;
	a->archive.archive_format_name = "lha";
	return (ARCHIVE_OK);
}

static int
archive_write_lha_header(struct archive_write *a, struct archive_entry *entry)
{
	int ret;
	struct lha *lha;
	const char *pathname;

	ret = 0;
	lha = (struct lha *)a->format_data;

	lha->method = lha->default_method;
	__lha_encodeReset(&lha->stream);
	data_area_init(&lha->origdata);
	data_area_init(&lha->compdata);
	archive_string_empty(&lha->pathname);
	archive_string_empty(&lha->dirname);

	lha->mode = archive_entry_mode(entry);
	lha->mtime = archive_entry_mtime(entry);
	lha->mtime_tv_nsec = archive_entry_mtime_nsec(entry);
	lha->ctime = archive_entry_ctime(entry);
	lha->ctime_tv_nsec = archive_entry_ctime_nsec(entry);
	lha->atime = archive_entry_atime(entry);
	lha->atime_tv_nsec = archive_entry_atime_nsec(entry);
	lha->gid = archive_entry_gid(entry);
	lha->uid = archive_entry_uid(entry);
	archive_strcpy(&lha->gname, archive_entry_gname(entry));
	archive_strcpy(&lha->uname, archive_entry_uname(entry));

	/*
	 * Reject files with empty name.
	 */
	pathname = archive_entry_pathname(entry);
	if (*pathname == '\0') {
		archive_set_error(&a->archive, EINVAL,
		    "Invalid filename");
		return (ARCHIVE_WARN);
	}
	archive_strcpy(&lha->pathname, pathname);

	/*
	 * Get a dirname and filename from the pathname.
	 */
	if ((lha->mode & AE_IFDIR) == AE_IFDIR
	    && lha->pathname.s[archive_strlen(&lha->pathname)-1] != '/')
		archive_strappend_char(&lha->pathname, '/');
	lha_split_path(lha);

	if ((lha->mode & AE_IFDIR) == 0
	    && archive_strlen(&lha->filename) == 0) {
		/* Reject filenames with trailing "/" */
		archive_set_error(&a->archive, EINVAL,
		    "Invalid filename");
		return (ARCHIVE_WARN);
	}
	if ((lha->mode & AE_IFLNK) == AE_IFLNK) {
		pathname = archive_entry_symlink(entry);
		/*
		 * Reject files with empty name.
		 */
		if (*pathname == '\0') {
			archive_set_error(&a->archive, EINVAL,
			    "Invalid symlink name");
			return (ARCHIVE_WARN);
		}
		archive_strappend_char(&lha->pathname, '|');
		archive_strcat(&lha->pathname, pathname);
		/*
		 * Re-get a dirname and filename from the pathname.
		 */
		lha_split_path(lha);
	}

	lha->compsize = 0;
	lha->origsize = archive_entry_size(entry);
	lha->entry_bytes_remaining = lha->origsize;
	lha->crc = 0;

	if ((lha->mode & AE_IFMT) != AE_IFREG) {
		lha->method = LHA_METHOD_LHd;
		ret = lha_write_header(a, lha);
		if (ret != ARCHIVE_OK)
			return (ret);
	}

	return (ARCHIVE_OK);
}


static ssize_t
archive_write_lha_data(struct archive_write *a, const void *buff, size_t s)
{
	struct lha *lha;
	int ret;

	lha = (struct lha *)a->format_data;
	if (s > lha->entry_bytes_remaining)
		s = lha->entry_bytes_remaining;

	/* Compute the crc */
	lha->crc = __lha_crc16(lha->crc, buff, s);

	ret = data_area_save(a, &lha->origdata, buff, s);
	if (ret != ARCHIVE_OK)
		return (ret);
	lha->entry_bytes_remaining -= s;

	if (lha->method != LHA_METHOD_LHd && lha->method != LHA_METHOD_LH0) {
		lha->stream.next_in = buff;
		lha->stream.avail_in = s;

		do {
			lha->stream.next_out = lha->outbuff;
			lha->stream.avail_out = sizeof(lha->outbuff);
		
			if (lha->entry_bytes_remaining > 0)
				ret = __lha_encode(&lha->stream, LHA_NO_FINISH);
			else
				ret = __lha_encode(&lha->stream, LHA_FINISH);
			if (ret < 0) {
				archive_set_error(&a->archive,
				    ARCHIVE_ERRNO_MISC,
				    "Encoding error");
				return (ARCHIVE_FATAL);
			}
			ret = data_area_save(a, &lha->compdata, lha->outbuff,
			    sizeof(lha->outbuff) - lha->stream.avail_out);
			if (ret != ARCHIVE_OK)
				return (ret);
			if (lha->compdata.total > lha->origsize) {
				/* If compressed data size more than orignal
				 * data size, stop encoding process.
				 */
				lha->method = LHA_METHOD_LH0;
				break;
			}
		} while (lha->stream.avail_in > 0);
	}

	return (s);
}


static int
archive_write_lha_destroy(struct archive_write *a)
{
	struct lha *lha;

	lha = (struct lha *)a->format_data;

	__lha_encodeEnd(&lha->stream);
	archive_string_free(&lha->pathname);
	archive_string_free(&lha->dirname);
	archive_string_free(&lha->filename);

	data_area_free(&lha->origdata);
	data_area_free(&lha->compdata);

	free(lha);
	a->format_data = NULL;
	return (ARCHIVE_OK);
}

static int
archive_write_lha_finish(struct archive_write *a)
{
	int ret;

	/*
	 * We need to write the mark which is the end of the lha archive.
	 */
	ret = (a->compressor.write)(a, "\0", 1);
	return (ret);
}

static int
archive_write_lha_finish_entry(struct archive_write *a)
{
	struct lha *lha;
	int ret, enc;

	lha = (struct lha *)a->format_data;

	ret = ARCHIVE_OK;
	if (lha->entry_bytes_remaining != 0) {
		archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
		    "Entry remaining bytes larger than 0");
		return (ARCHIVE_WARN);
	}

	if (lha->method != LHA_METHOD_LHd && lha->method != LHA_METHOD_LH0) {
		lha->stream.next_in = NULL;
		lha->stream.avail_in = 0;

		do {
			lha->stream.next_out = lha->outbuff;
			lha->stream.avail_out = sizeof(lha->outbuff);
		
			enc = __lha_encode(&lha->stream, LHA_FINISH);
			if (enc < 0) {
				archive_set_error(&a->archive,
				    ARCHIVE_ERRNO_MISC,
				    "Encoding error");
				return (ARCHIVE_FATAL);
			}
			ret = data_area_save(a, &lha->compdata, lha->outbuff,
			    sizeof(lha->outbuff) - lha->stream.avail_out);
			if (ret != ARCHIVE_OK)
				return (ret);
			if (lha->compdata.total > lha->origsize) {
				lha->method = LHA_METHOD_LH0;/* no compressed */
				break;
			}
		} while (enc == LHA_OK);
	}

	if (lha->method != LHA_METHOD_LHd) {
		if (lha->method == LHA_METHOD_LH0)
			lha->compsize = lha->origsize;
		else
			lha->compsize = lha->compdata.total;
		ret = lha_write_header(a, lha);
		if (ret != ARCHIVE_OK)
			return (ret);
		if (lha->method == LHA_METHOD_LH0)
			ret = data_area_write(a, &lha->origdata);
		else
			ret = data_area_write(a, &lha->compdata);
	}
	data_area_free(&lha->origdata);
	data_area_free(&lha->compdata);

	return (ret);
}

static void
lha_split_path(struct lha *lha)
{
	const char *endp, *startp;
	const char *path;

	path = lha->pathname.s;
	endp = path + archive_strlen(&lha->pathname) - 1;
	/*
	 * For filename with trailing slash(es), we return
	 * NULL indicating an error.
	 */
	if (*endp == '/') {
		archive_string_copy(&lha->dirname, &lha->pathname);
		archive_string_empty(&lha->filename);
		return;
	}

	/* Find the start of the base */
	startp = endp;
	while (startp > path && *(startp - 1) != '/')
		startp--;
	
	archive_strcpy(&lha->filename, startp);
	archive_string_empty(&lha->dirname);
	if (startp != path)
		archive_strncat(&lha->dirname, path, (size_t)(startp - path));
}

static const char *
get_method_string(int method)
{
	switch (method) {
	case LHA_METHOD_LH0: return "-lh0-";
	case LHA_METHOD_LH5: return "-lh5-";
	case LHA_METHOD_LH6: return "-lh6-";
	case LHA_METHOD_LH7: return "-lh7-";
	case LHA_METHOD_LHd: return "-lhd-";
	default 	   : return "-lh5-";
	}
}

static void
convert_dir_separator(unsigned char *buff, size_t s)
{
	for (;s-- > 0; buff++)
		if (*buff == '/')
			*buff = 0xFF;
}

/*
 * Extend header id
 */
#define EXT_HEADER_CRC		0x00		/* Header crc and information*/
#define EXT_FILENAME		0x01		/* Filename 		    */
#define EXT_DIRECTORY		0x02		/* Directory name	    */
#define EXT_DOS_ATTR		0x40		/* MS-DOS attribute	    */
#define EXT_TIMESTAMP		0x41		/* Windows time stamp	    */
#define EXT_FILESIZE		0x42		/* Large file size	    */
#define EXT_TIMEZONE		0x43		/* Time zone		    */
#define EXT_UTF16_FILENAME	0x44		/* UTF-16 filename 	    */
#define EXT_UTF16_DIRECTORY	0x45		/* UTF-16 directory name    */
#define EXT_CODEPAGE		0x46		/* Codepage		    */
#define EXT_UNIX_MODE		0x50		/* File permission	    */
#define EXT_UNIX_GID_UID	0x51		/* gid,uid		    */
#define EXT_UNIX_GNAME		0x52		/* Group name		    */
#define EXT_UNIX_UNAME		0x53		/* User name		    */
#define EXT_UNIX_MTIME		0x54		/* Modified time	    */
#define EXT_OS2_NEW_ATTR	0x7f		/* new attribute(OS/2 only) */
#define EXT_NEW_ATTR		0xff		/* new attribute	    */

/*
 * Write level 2 header.
 */
#define H2_HEADER_SIZE		0
#define H2_METHOD		2
#define H2_COMP_SIZE		7
#define H2_ORIG_SIZE		11
#define H2_UTIME		15
#define H2_RESERVE		19
#define H2_LEVEL		20
#define H2_CRC			21
#define H2_SYSTEM		23
#define H2_EXT_HEADER		24

static int
lha_write_header_2(struct archive_write *a, struct lha *lha)
{
	unsigned char *buff;
	unsigned char *ext;
	unsigned char *hcrc_ptr;
	int	esize;
	int	hsize;
	int	ret;

	hsize = 4096;
	buff = malloc(hsize);
	if (buff == NULL) {
		archive_set_error(&a->archive, ENOMEM,
		    "Can't allocate data");
		return (ARCHIVE_FATAL);
	}

	memcpy(buff + H2_METHOD, get_method_string(lha->method), 5);
	if (lha->compsize > 0xFFFFFFFF || lha->origsize > 0xFFFFFFFF) {
		archive_le32enc(buff + H2_COMP_SIZE, 0);
		archive_le32enc(buff + H2_ORIG_SIZE, 0);
	} else {
		archive_le32enc(buff + H2_COMP_SIZE, lha->compsize);
		archive_le32enc(buff + H2_ORIG_SIZE, lha->origsize);
	}
	/* WARNING: This has been the year 2038 problem. */
	archive_le32enc(buff + H2_UTIME, lha->mtime);
	buff[H2_RESERVE] = 0x20;
	buff[H2_LEVEL] = 2;	/* fixed, which is this header level.	*/
	archive_le16enc(buff + H2_CRC, lha->crc);
	buff[H2_SYSTEM] = 'U';  /* create system type. 'U' is unix.	*/

	/* Set an extend header pointer to make extend headers */
	ext = buff + H2_EXT_HEADER;
	hsize -= H2_EXT_HEADER;

	/* Write a header's crc and infomation ext-header */
	esize = 3 + 2;
	archive_le16enc(ext, esize);	/* header size(including this size) */
	ext[2] = EXT_HEADER_CRC;	/* header id			*/
	archive_le16enc(ext + 3, 0);	/* header crc 			*/
	hcrc_ptr = ext + 3;		/* keep a header crc position	*/
	ext += esize;
	hsize -= esize;

	/*
	 * Write a filename name ext-header.
	 * It must be written to the extend header whether the file name is
	 * empty or not.
	 */
	esize = 3 + archive_strlen(&lha->filename);
	if (esize > 0xFFFF) {
		archive_set_error(&a->archive, EINVAL,
		    "Invalid pathname(too large)");
		free(buff);
		return (ARCHIVE_WARN);
	}
	if (hsize - esize < 0)
		goto sizeerr;
	archive_le16enc(ext, esize);
	ext[2] = EXT_FILENAME;
	memcpy(ext + 3, lha->filename.s, archive_strlen(&lha->filename));
	ext += esize;
	hsize -= esize;

	/* Write a directory name ext-header */
	if (archive_strlen(&lha->dirname) > 0) {
		esize = 3 + archive_strlen(&lha->dirname);
		if (esize > 0xFFFF) {
			archive_set_error(&a->archive, EINVAL,
			    "Invalid pathname(too large)");
			free(buff);
			return (ARCHIVE_WARN);
		}
		if (hsize - esize < 0)
			goto sizeerr;
		archive_le16enc(ext, esize);
		ext[2] = EXT_DIRECTORY;
		memcpy(ext + 3, lha->dirname.s, archive_strlen(&lha->dirname));
		/* Convert directory separator('/') into 0xFF */
		convert_dir_separator(ext + 3, archive_strlen(&lha->dirname));
		ext += esize;
		hsize -= esize;
	}

	/* Write a windows time stamp ext-header. */
	esize = 3 + sizeof(uint64_t) * 3;
	if (hsize - esize < 0)
		goto sizeerr;
	archive_le16enc(ext, esize);
	ext[2] = EXT_TIMESTAMP;
	archive_le64enc(ext + 3,
	    lha_to_win_time(lha->ctime, lha->ctime_tv_nsec));
	archive_le64enc(ext + 3 + sizeof(uint64_t),
	    lha_to_win_time(lha->mtime, lha->mtime_tv_nsec));
	archive_le64enc(ext + 3 + sizeof(uint64_t) * 2,
	    lha_to_win_time(lha->atime, lha->atime_tv_nsec));
	ext += esize;
	hsize -= esize;

	/*
	 * Write a file size ext-header, if the orignal file size or the encoded
	 * data size are large which it is more than 0xFFFFFFFF(4GB)
	 */
	if (lha->compsize > 0xFFFFFFFF || lha->origsize > 0xFFFFFFFF) {
		esize = 3 + sizeof(uint64_t) * 2;
		if (hsize - esize < 0)
			goto sizeerr;
		archive_le16enc(ext, esize);
		ext[2] = EXT_FILESIZE;
		archive_le64enc(ext + 3, lha->compsize);
		archive_le64enc(ext + 3 + sizeof(uint16_t), lha->origsize);
		ext += esize;
		hsize -= esize;
	}

	/* Write a unix file permission ext-header */
	esize = 3 + sizeof(uint16_t);
	if (hsize - esize < 0)
		goto sizeerr;
	archive_le16enc(ext, esize);
	ext[2] = EXT_UNIX_MODE;
	archive_le16enc(ext + 3, lha->mode);
	ext += esize;
	hsize -= esize;

	/* Write a gid/uid ext-header */
	esize = 3 + sizeof(uint16_t) * 2;
	if (hsize - esize < 0)
		goto sizeerr;
	archive_le16enc(ext, esize);
	ext[2] = EXT_UNIX_GID_UID;
	archive_le16enc(ext + 3, lha->gid);
	archive_le16enc(ext + 5, lha->uid);
	ext += esize;
	hsize -= esize;

	/* Write a group name */
	esize = 3 + archive_strlen(&lha->gname);
	if (esize > 0xFFFF) {
		archive_set_error(&a->archive, EINVAL,
		    "Invalid group name(too large)");
		free(buff);
		return (ARCHIVE_WARN);
	}
	if (hsize - esize < 0)
		goto sizeerr;
	archive_le16enc(ext, esize);
	ext[2] = EXT_UNIX_GNAME;
	memcpy(ext + 3, lha->gname.s, archive_strlen(&lha->gname));
	ext += esize;
	hsize -= esize;

	/* Write a user name */
	esize = 3 + archive_strlen(&lha->uname);
	if (esize > 0xFFFF) {
		archive_set_error(&a->archive, EINVAL,
		    "Invalid user name(too large)");
		free(buff);
		return (ARCHIVE_WARN);
	}
	if (hsize - esize < 0)
		goto sizeerr;
	archive_le16enc(ext, esize);
	ext[2] = EXT_UNIX_UNAME;
	memcpy(ext + 3, lha->uname.s, archive_strlen(&lha->uname));
	ext += esize;
	hsize -= esize;

	/* Write the end of the extned header */
	if (hsize - 2 < 0)
		goto sizeerr;
	archive_le16enc(ext, 0);
	ext += 2;

	hsize = ext - buff;
	if ((hsize & 0xff) == 0) {
		/* Add padding data.
		 * if a first byte of header data is 0, then all of lha
		 * decoder will exit reading lha archive file because
		 * the '0' means the end of the lha archive data.
		 */
		if (hsize <= 0)
			goto sizeerr;
		*ext++ = 0;
		hsize++;
	}
	/* Write header size */
	archive_le16enc(buff, hsize);

	/* Compute a header crc and write it to a part of header crc of
	 * extend header.
	 */
	archive_le16enc(hcrc_ptr, __lha_crc16(0, buff, hsize));

	/* Flush header data */
	ret = (a->compressor.write)(a, buff, hsize);
	free(buff);
	return (ret);

sizeerr:
	archive_set_error(&a->archive, EINVAL,
	    "Invalid data, which cannot create header.");
	free(buff);
	return (ARCHIVE_WARN);
}

static int
lha_write_header(struct archive_write *a, struct lha *lha)
{
	/* Currently, write level 2 header only. */
	return lha_write_header_2(a, lha);
}

static void
data_area_init(struct data_area *area)
{
	area->total = 0;
	STAILQ_INIT(&area->entrylist);
}

static int
data_area_save(struct archive_write *a, struct data_area *area,
    const void *buff, size_t s)
{
	struct data_entry *de;

	if (s == 0)
		return (ARCHIVE_OK);
	/*
	 * TODO: if file/encode size is too many to memory allocate,
	 * 	 try to save to temporarily file.
	 */
	de = malloc(sizeof(struct data_entry));
	if (de == NULL) {
		archive_set_error(&a->archive, ENOMEM,
		    "Can't allocate data");
		return (ARCHIVE_FATAL);
	}
	de->buff = malloc(s);
	if (de->buff == NULL) {
		archive_set_error(&a->archive, ENOMEM,
		    "Can't allocate data");
		return (ARCHIVE_FATAL);
	}

	de->s = s;
	memcpy(de->buff, buff, s);
	STAILQ_INSERT_TAIL(&area->entrylist, de, next);
	area->total += s;

	return (ARCHIVE_OK);
}

static void
data_area_free(struct data_area *area)
{
 
	if (!STAILQ_EMPTY(&area->entrylist)) {
		struct data_entry *data, *tdata;

		STAILQ_FOREACH_SAFE(data, &area->entrylist, next, tdata) {
			STAILQ_REMOVE(&area->entrylist, data, data_entry, next);
			free(data);
		}
	}
}

static int
data_area_write(struct archive_write *a, struct data_area *area)
{
	struct data_entry *data, *tdata;
	int ret;

	STAILQ_FOREACH_SAFE(data, &area->entrylist, next, tdata) {
		ret = (a->compressor.write)(a, data->buff, data->s);
		if (ret != ARCHIVE_OK)
			return (ret);
		/*
		 *
		 */
		STAILQ_REMOVE(&area->entrylist, data, data_entry, next);
		free(data);
	}

	return (ARCHIVE_OK);
}

/* Convert a time_t into an MS-Windows-style date/time */
static uint64_t
lha_to_win_time(time_t time, long ns)
{
	uint64_t wintime;

	wintime = time;
	wintime *= 10000000ULL;
	wintime += ns / 100;
	wintime += 0x019db1ded53e8000ULL;	/* 1970-01-01 00:00:00 (UTC) */

	return wintime;
}
