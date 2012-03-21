/*-
 * Copyright (c) 2012 Michihiro NAKAJIMA
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

#include "archive_platform.h"
__FBSDID("$FreeBSD$");

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#include <stdlib.h>
#ifdef HAVE_ZLIB_H
#include <zlib.h>
#endif

#include "archive.h"
#include "archive_endian.h"
#include "archive_entry.h"
#include "archive_entry_locale.h"
#include "archive_private.h"
#include "archive_string.h"
#include "archive_write_private.h"

/*
 * Cabinet file definitions.
 */
/* CFHEADER offset */
#define CFHEADER_signature	0
#define CFHEADER_cbCabinet	8
#define CFHEADER_coffFiles	16
#define CFHEADER_versionMinor	24
#define CFHEADER_versionMajor	25
#define CFHEADER_cFolders	26
#define CFHEADER_cFiles		28
#define CFHEADER_flags		30
#define CFHEADER_setID		32
#define CFHEADER_iCabinet	34
#define CFHEADER_cbCFHeader	36
#define CFHEADER_cbCFFolder	38
#define CFHEADER_cbCFData	39
/* CFFOLDER offset */
#define CFFOLDER_coffCabStart	0
#define CFFOLDER_cCFData	4
#define CFFOLDER_typeCompress	6
#define CFFOLDER_abReserve	8
/* CFFILE offset */
#define CFFILE_cbFile		0
#define CFFILE_uoffFolderStart	4
#define CFFILE_iFolder		8
#define CFFILE_date_time	10
#define CFFILE_attribs		14

#define COMPTYPE_NONE		0x0000
#define COMPTYPE_MSZIP		0x0001
#define COMPTYPE_QUANTUM	0x0002
#define COMPTYPE_LZX		0x0003

struct cffolder {
	int			 index;
	uint32_t		 offset_in_cab;
	uint16_t		 cfdata_count;
	uint16_t		 comptype;
	uint16_t		 cmpdata;
	uint32_t		 cfdata_sum;

	uint8_t			*cfdata;
	uint8_t			*uncompressed;
	size_t			 cfdata_allocated_size;
	size_t			 remaining;
	unsigned		 offset;
};

#define ATTR_RDONLY		0x01
#define ATTR_NAME_IS_UTF	0x80

struct cffile {
	struct cffile		*next;
	unsigned		 name_len;
	uint8_t			*name;/* UTF-8 name. */
	uint64_t		 size;
	time_t			 mtime;
	unsigned		 attr;
	unsigned		 offset;
	int			 folder;
};

struct cab {
	int			 temp_fd;
	uint64_t		 temp_offset;

	struct cffolder		 cffolder;
	struct cffile		*cur_file;
	size_t			 total_number_entry;
	uint64_t		 total_bytes_compressed;
	uint64_t		 total_bytes_uncompressed;
	uint64_t		 entry_bytes_remaining;

	unsigned		 opt_compression;
	int			 opt_compression_level;

	struct archive_string_conv *sconv;

	/*
	 * Compressed data buffer.
	 */
	unsigned char		 wbuff[512 * 20 * 6];
	size_t			 wbuff_remaining;

	/*
	 * The list of the file entries which has its contents is used to
	 * manage struct cffile objects.
	 * We use 'next' a menber of struct cffile to chain.
	 */
	struct {
		struct cffile	*first;
		struct cffile	**last;
	}			 file_list;

#ifdef HAVE_ZLIB_H
	z_stream		 zstrm;
	int			 zstrm_valid;
#endif
};

static uint32_t cab_checksum_cfdata_4(const void *, size_t, uint32_t);
static uint32_t cab_checksum_cfdata(const void *, size_t, uint32_t);
static int	cab_options(struct archive_write *,
		    const char *, const char *);
static int	cab_write_header(struct archive_write *,
		    struct archive_entry *);
static ssize_t	cab_write_data(struct archive_write *,
		    const void *, size_t);
static int	cab_finish_entry(struct archive_write *);
static int	cab_close(struct archive_write *);
static int	cab_free(struct archive_write *);
static int	file_new(struct archive_write *a, struct archive_entry *,
		    struct cffile **);
static void	file_free(struct cffile *);
static void	file_register(struct cab *, struct cffile *);
static void	file_init_register(struct cab *);
static void	file_free_register(struct cab *);
static ssize_t	compress_out(struct archive_write *, const void *, size_t);

int
archive_write_set_format_cab(struct archive *_a)
{
	struct archive_write *a = (struct archive_write *)_a;
	struct cab *cab;

	archive_check_magic(_a, ARCHIVE_WRITE_MAGIC,
	    ARCHIVE_STATE_NEW, "archive_write_set_format_cab");

	/* If another format was already registered, unregister it. */
	if (a->format_free != NULL)
		(a->format_free)(a);

	cab = calloc(1, sizeof(*cab));
	if (cab == NULL) {
		archive_set_error(&a->archive, ENOMEM,
		    "Can't allocate CAB data");
		return (ARCHIVE_FATAL);
	}
	cab->temp_fd = -1;
	file_init_register(cab);

	/* Set default compression type and its level. */
#if defined(HAVE_ZLIB_H)
	cab->opt_compression = COMPTYPE_MSZIP;
#else
	cab->opt_compression = COMPTYPE_NONE;
#endif
	cab->opt_compression_level = 6;

	a->format_data = cab;

	a->format_name = "cab";
	a->format_options = cab_options;
	a->format_write_header = cab_write_header;
	a->format_write_data = cab_write_data;
	a->format_finish_entry = cab_finish_entry;
	a->format_close = cab_close;
	a->format_free = cab_free;
	a->archive.archive_format = ARCHIVE_FORMAT_CAB;
	a->archive.archive_format_name = "cab";

	return (ARCHIVE_OK);
}

static int
cab_options(struct archive_write *a, const char *key, const char *value)
{
	struct cab *cab;

	cab = (struct cab *)a->format_data;

	if (strcmp(key, "compression") == 0) {
		const char *name = NULL;

		if (value == NULL || strcmp(value, "none") == 0 ||
		    strcmp(value, "NONE") == 0 ||
		    strcmp(value, "copy") == 0 ||
		    strcmp(value, "COPY") == 0 ||
		    strcmp(value, "store") == 0 ||
		    strcmp(value, "STORE") == 0)
			cab->opt_compression = COMPTYPE_NONE;
		else if (strcmp(value, "mszip") == 0 ||
		    strcmp(value, "MSZIP") == 0)
#if HAVE_ZLIB_H
			cab->opt_compression = COMPTYPE_MSZIP;
#else
			name = "mszip";
#endif
		else {
			archive_set_error(&(a->archive),
			    ARCHIVE_ERRNO_MISC,
			    "Unkonwn compression name: `%s'",
			    value);
			return (ARCHIVE_FAILED);
		}
		if (name != NULL) {
			archive_set_error(&(a->archive),
			    ARCHIVE_ERRNO_MISC,
			    "`%s' compression not supported "
			    "on this platform",
			    name);
			return (ARCHIVE_FAILED);
		}
		return (ARCHIVE_OK);
	}
	if (strcmp(key, "compression-level") == 0) {
		if (value == NULL ||
		    !(value[0] >= '0' && value[0] <= '9') ||
		    value[1] != '\0') {
			archive_set_error(&(a->archive),
			    ARCHIVE_ERRNO_MISC,
			    "Illeagal value `%s'",
			    value);
			return (ARCHIVE_FAILED);
		}
		cab->opt_compression_level = value[0] - '0';
		return (ARCHIVE_OK);
	}

	/* Note: The "warn" return is just to inform the options
	 * supervisor that we didn't handle it.  It will generate
	 * a suitable error if no one used this option. */
	return (ARCHIVE_WARN);
}

static int
cab_write_header(struct archive_write *a, struct archive_entry *entry)
{
	struct cab *cab;
	struct cffile *file;
	int r;

	cab = (struct cab *)a->format_data;
	cab->cur_file = NULL;
	cab->entry_bytes_remaining = 0;

	if (cab->sconv == NULL) {
		cab->sconv = archive_string_conversion_to_charset(
		    &a->archive, "UTF-8", 1);
		if (cab->sconv == NULL)
			return (ARCHIVE_FATAL);
	}

	if (archive_entry_filetype(entry) == AE_IFDIR) {
		archive_set_error(&(a->archive), ARCHIVE_ERRNO_MISC,
		    "Ignored: CAB cannot include a directory file");
		return (ARCHIVE_WARN);
	}

	r = file_new(a, entry, &file);
	if (r < ARCHIVE_WARN)
		return (r);
	file->offset = cab->cffolder.offset;
	file->folder = cab->cffolder.index;
	if ((int64_t)file->offset + file->size > (int64_t)0x7FFF8000) {
		archive_set_error(&(a->archive), ARCHIVE_ERRNO_MISC,
		    "Total file size is over 0x7FFF8000 bytes(CAB limitation)");
		return (ARCHIVE_FAILED);
	}

	cab->total_number_entry++;
	/* Register a non-empty file. */
	file_register(cab, file);

	/*
	 * Set the current file to cur_file to read its contents.
	 */
	cab->cur_file = file;

	/* Save a offset of current file in temporary file. */
	cab->entry_bytes_remaining = file->size;

	/*
	 * Store a symbolic link name as file contents.
	 */
	if (archive_entry_filetype(entry) == AE_IFLNK) {
		ssize_t bytes;
		const void *p = (const void *)archive_entry_symlink(entry);
		bytes = compress_out(a, p, (size_t)file->size);
		if (bytes < 0)
			return ((int)bytes);
		cab->entry_bytes_remaining = 0;
	}

	return (r);
}

/*
 * Write data to a temporary file.
 */
static int
write_to_temp(struct archive_write *a, const void *buff, size_t s)
{
	struct cab *cab;
	const unsigned char *p;
	ssize_t ws;

	cab = (struct cab *)a->format_data;

	/*
	 * Open a temporary file.
	 */
	if (cab->temp_fd == -1) {
		cab->temp_offset = 0;
		cab->temp_fd = __archive_mktemp(NULL);
		if (cab->temp_fd < 0) {
			archive_set_error(&a->archive, errno,
			    "Couldn't create temporary file");
			return (ARCHIVE_FATAL);
		}
	}

	p = (const unsigned char *)buff;
	while (s) {
		ws = write(cab->temp_fd, p, s);
		if (ws < 0) {
			archive_set_error(&(a->archive), errno,
			    "fwrite function failed");
			return (ARCHIVE_FATAL);
		}
		s -= ws;
		p += ws;
		cab->temp_offset += ws;
	}
	return (ARCHIVE_OK);
}

static int
cfdata_out(struct archive_write *a)
{
	struct cab *cab = (struct cab *)a->format_data;
	struct cffolder *cffolder = &(cab->cffolder);
	size_t compsize, uncompsize;
	int r;

	/* Compress file data. */
	switch (cab->opt_compression) {
#ifdef HAVE_ZLIB_H
	case COMPTYPE_MSZIP:
		cab->zstrm.next_in = cffolder->uncompressed;
		cab->zstrm.avail_in = 0x8000 - cffolder->remaining;
		cab->zstrm.total_in = 0;
		cab->zstrm.next_out = cffolder->cfdata + 8;
		cab->zstrm.avail_out = cffolder->cfdata_allocated_size - 8;
		cab->zstrm.total_out = 0;
		/* Add an MSZIP signature. */
		*cab->zstrm.next_out++ = 0x43;
		*cab->zstrm.next_out++ = 0x4b;
		cab->zstrm.avail_out -= 2;
		cab->zstrm.total_out = 2;
		r = deflate(&(cab->zstrm), Z_FINISH);
		if (r != Z_OK && r != Z_STREAM_END) {
			archive_set_error(&(a->archive), ARCHIVE_ERRNO_MISC,
			    "Deflate compression failed:"
			    " deflate() call returned status %d", r);
			return (ARCHIVE_FATAL);
		}
		compsize = (size_t)cab->zstrm.total_out;
		uncompsize = (size_t)cab->zstrm.total_in;
		break;
#endif
	case COMPTYPE_NONE:
	default:
		/* We've already copied the data to cffolder->cfdata. */
		r = 0;
		compsize = uncompsize = 0x8000 - cffolder->remaining;
		break;
	}
	
	/* Write compressed size. */
	archive_le16enc(cffolder->cfdata + 4, (uint16_t)compsize);
	/* Write uncompressed size. */
	archive_le16enc(cffolder->cfdata + 6, (uint16_t)uncompsize);
	/* Culculate CFDATA sum. */
	cffolder->cfdata_sum = cab_checksum_cfdata(cffolder->cfdata + 8,
	    compsize, 0);
	cffolder->cfdata_sum = cab_checksum_cfdata(cffolder->cfdata + 4,
	    4, cffolder->cfdata_sum);
	/* Write the sum of CFDATA. */
	archive_le32enc(cffolder->cfdata, cffolder->cfdata_sum);

	r = write_to_temp(a, cffolder->cfdata, 8 + compsize);
	if (r != ARCHIVE_OK)
		return (ARCHIVE_FATAL);
	cab->total_bytes_compressed += compsize;
	cab->total_bytes_uncompressed += uncompsize;
	cffolder->cfdata_count++;
	cffolder->remaining = 0x8000;
	return (ARCHIVE_OK);
}

static ssize_t
compress_out(struct archive_write *a, const void *buff, size_t s)
{
	struct cab *cab = (struct cab *)a->format_data;
	struct cffolder *cffolder = &(cab->cffolder);
	const char *b;
	uint8_t *dist;
	size_t l, ss;
	int r;

	if (cffolder->cfdata == NULL && s) {
		cffolder->remaining = 0x8000;
		cffolder->comptype = cab->opt_compression;
		cffolder->cfdata_allocated_size = 8 + 0x8000 + 6144;
		cffolder->cfdata = malloc(cffolder->cfdata_allocated_size);
		if (cffolder->cfdata == NULL) {
			archive_set_error(&a->archive, ENOMEM,
			    "Can't allocate memory");
			return (ARCHIVE_FATAL);
		}
#ifdef HAVE_ZLIB_H
		if (cab->opt_compression == COMPTYPE_MSZIP) {
			cffolder->uncompressed = malloc(0x8000);
			if (cffolder->uncompressed == NULL) {
				archive_set_error(&a->archive, ENOMEM,
				    "Can't allocate memory");
				return (ARCHIVE_FATAL);
			}
			if (deflateInit2(&(cab->zstrm),
			    cab->opt_compression_level, Z_DEFLATED,
			    -15, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
				archive_set_error(&a->archive,
				    ARCHIVE_ERRNO_MISC,
				    "Internal error initializing "
				    "compression library");
				return (ARCHIVE_FATAL);
			}
			cab->zstrm_valid = 1;
		}
#endif
	}
	ss = s;
	b = buff;
	switch (cab->opt_compression) {
#ifdef HAVE_ZLIB_H
	case COMPTYPE_MSZIP:
		dist = cffolder->uncompressed; break;
#endif
	case COMPTYPE_NONE:
	default:
		dist = cffolder->cfdata + 8; break;
	}
	while (ss) {
		l = ss;
		if (l > cffolder->remaining)
			l = cffolder->remaining;
		memcpy(dist + (cffolder->offset & 0x7FFF), b, l);
		ss -= l;
		cffolder->remaining -= l;
		cffolder->offset += l;
		if (cffolder->remaining != 0)
			return (s);

		r = cfdata_out(a);
		if (r != ARCHIVE_OK)
			return (r);
		b += l;
#ifdef HAVE_ZLIB_H
		if (cab->opt_compression == COMPTYPE_MSZIP) {
			deflateReset(&(cab->zstrm));
			if (deflateSetDictionary(&(cab->zstrm),
			    cffolder->uncompressed, 0x8000) != Z_OK) {
				archive_set_error(&a->archive,
				    ARCHIVE_ERRNO_MISC,
				    "Internal error initializing "
				    "compression library");
				return (ARCHIVE_FATAL);
			}
		}
#endif
	}

	return (s);
}

static ssize_t
cab_write_data(struct archive_write *a, const void *buff, size_t s)
{
	struct cab *cab;
	ssize_t bytes;

	cab = (struct cab *)a->format_data;

	if (s > cab->entry_bytes_remaining)
		s = (size_t)cab->entry_bytes_remaining;
	if (s == 0 || cab->cur_file == NULL)
		return (0);
	bytes = compress_out(a, buff, s);
	if (bytes < 0)
		return (bytes);
	cab->entry_bytes_remaining -= bytes;
	return (bytes);
}

static int
cab_finish_entry(struct archive_write *a)
{
	struct cab *cab;
	size_t s;
	ssize_t r;

	cab = (struct cab *)a->format_data;
	if (cab->cur_file == NULL)
		return (ARCHIVE_OK);

	while (cab->entry_bytes_remaining > 0) {
		s = (size_t)cab->entry_bytes_remaining;
		if (s > a->null_length)
			s = a->null_length;
		r = cab_write_data(a, a->nulls, s);
		if (r < 0)
			return (r);
	}
	cab->cur_file = NULL;

	return (ARCHIVE_OK);
}

static int
flush_wbuff(struct archive_write *a)
{
	struct cab *cab;
	int r;
	size_t s;

	cab = (struct cab *)a->format_data;
	s = sizeof(cab->wbuff) - cab->wbuff_remaining;
	r = __archive_write_output(a, cab->wbuff, s);
	if (r != ARCHIVE_OK)
		return (r);
	cab->wbuff_remaining = sizeof(cab->wbuff);
	return (r);
}

static int
copy_out(struct archive_write *a, uint64_t offset, uint64_t length)
{
	struct cab *cab;
	int r;

	cab = (struct cab *)a->format_data;
	if (cab->temp_offset > 0 &&
	    lseek(cab->temp_fd, offset, SEEK_SET) < 0) {
		archive_set_error(&(a->archive), errno, "lseek failed");
		return (ARCHIVE_FATAL);
	}
	while (length) {
		size_t rsize;
		ssize_t rs;
		unsigned char *wb;

		if (length > cab->wbuff_remaining)
			rsize = cab->wbuff_remaining;
		else
			rsize = (size_t)length;
		wb = cab->wbuff + (sizeof(cab->wbuff) - cab->wbuff_remaining);
		rs = read(cab->temp_fd, wb, rsize);
		if (rs < 0) {
			archive_set_error(&(a->archive), errno,
			    "Can't read temporary file(%jd)",
			    (intmax_t)rs);
			return (ARCHIVE_FATAL);
		}
		if (rs == 0) {
			archive_set_error(&(a->archive), 0,
			    "Truncated temporary file");
			return (ARCHIVE_FATAL);
		}
		cab->wbuff_remaining -= rs;
		length -= rs;
		if (cab->wbuff_remaining == 0) {
			r = flush_wbuff(a);
			if (r != ARCHIVE_OK)
				return (r);
		}
	}
	return (ARCHIVE_OK);
}

/* Convert into MSDOS-style date/time. */
static void
cab_dos_time(unsigned char *wp, const time_t unix_time)
{
	struct tm *t;
	unsigned int dt;

	/* This will not preserve time when creating/extracting the archive
	 * on two systems with different time zones. */
	t = localtime(&unix_time);

	/* MSDOS-style date/time is only between 1980-01-01 and 2107-12-31 */
	if (t->tm_year < 1980 - 1900)
		/* Set minimum date/time '1980-01-01 00:00:00'. */
		dt = 0x00210000U;
	else if (t->tm_year > 2107 - 1900)
		/* Set maximum date/time '2107-12-31 23:59:58'. */
		dt = 0xff9fbf7dU;
	else {
		dt = 0;
		dt += ((t->tm_year - 80) & 0x7f) << 9;
		dt += ((t->tm_mon + 1) & 0x0f) << 5;
		dt += (t->tm_mday & 0x1f);
		dt <<= 16;
		dt += (t->tm_hour & 0x1f) << 11;
		dt += (t->tm_min & 0x3f) << 5;
		/* Only counting every 2 seconds. */
		dt += (t->tm_sec & 0x3e) >> 1;
	}
	archive_le16enc(wp, dt >> 16);
	archive_le16enc(wp+2, dt & 0xffff);
}

static int
cab_close(struct archive_write *a)
{
	struct cab *cab;
	struct cffolder *cffolder;
	struct cffile *file;
	unsigned char *wb;
	uint32_t length;
	uint32_t cffile_offset;
	uint32_t cfdata_offset;
	int r;

	cab = (struct cab *)a->format_data;
	cffolder = &(cab->cffolder);

	/*
	 * Flush out remaing CFDATA.
	 */
	if (cffolder->cfdata != NULL && cffolder->remaining < 0x8000) {
		r = cfdata_out(a);
		if (r != ARCHIVE_OK)
			return (r);
	}
	length = (uint32_t)cab->temp_offset;

	/*
	 * Make the cab header on wbuff(write buffer).
	 */

	wb = cab->wbuff;
	cab->wbuff_remaining = sizeof(cab->wbuff);
	cffile_offset = 36 + 8;
	cfdata_offset = cffile_offset;
	file = cab->file_list.first;
	for (;file != NULL; file = file->next)
		cfdata_offset += 16 + file->name_len + 1;

	/*
	 * Write CFHEADER.
	 */
	memcpy(wb + CFHEADER_signature, "MSCF\0\0\0\0", 8);
	archive_le32enc(wb + CFHEADER_cbCabinet, cfdata_offset + length);
	archive_le32enc(wb + CFHEADER_coffFiles, cffile_offset);
	wb[CFHEADER_versionMinor] = 3;
	wb[CFHEADER_versionMajor] = 1;
	archive_le16enc(wb + CFHEADER_cFolders, cab->total_number_entry?1:0);
	archive_le16enc(wb + CFHEADER_cFiles, cab->total_number_entry);
	archive_le16enc(wb + CFHEADER_flags, 0);
	archive_le16enc(wb + CFHEADER_setID, 0);
	archive_le16enc(wb + CFHEADER_iCabinet, 0);
	cab->wbuff_remaining -= 36;
	wb += 36;

	/*
	 * Write CFFOLDER.
	 */
	archive_le32enc(wb + CFFOLDER_coffCabStart, cfdata_offset);
	archive_le16enc(wb + CFFOLDER_cCFData, cffolder->cfdata_count);
	archive_le16enc(wb + CFFOLDER_typeCompress,
	    (uint16_t)((cffolder->cmpdata << 8) + cffolder->comptype));
	cab->wbuff_remaining -= 8;
	wb += 8;

	/*
	 * Write CFFILE.
	 */
	file = cab->file_list.first;
	for (;file != NULL; file = file->next) {
		if (cab->wbuff_remaining < 16 + file->name_len + 1) {
			r = flush_wbuff(a);
			if (r != ARCHIVE_OK)
				return (r);
			wb = cab->wbuff;
		}
		archive_le32enc(wb + CFFILE_cbFile, (uint32_t)file->size);
		archive_le32enc(wb + CFFILE_uoffFolderStart, file->offset);
		archive_le16enc(wb + CFFILE_iFolder, file->folder);
		cab_dos_time(wb + CFFILE_date_time, file->mtime);
		archive_le16enc(wb + CFFILE_attribs, file->attr);
		memcpy(wb + 16, file->name, file->name_len + 1);
		wb += 16 + file->name_len + 1;
		cab->wbuff_remaining -= 16 + file->name_len + 1;
	}


	/*
	 * Read all file contents and an encoded header from the temporary
	 * file and write out it.
	 */
	r = copy_out(a, 0, length);
	if (r != ARCHIVE_OK)
		return (r);
	r = flush_wbuff(a);
	return (r);
}

static int
cab_free(struct archive_write *a)
{
	struct cab *cab = (struct cab *)a->format_data;
	int ret = ARCHIVE_OK;

	file_free_register(cab);
	free(cab->cffolder.cfdata);
	free(cab->cffolder.uncompressed);
#ifdef HAVE_ZLIB_H
	if (cab->zstrm_valid) {
		if (deflateEnd(&(cab->zstrm)) != Z_OK) {
			archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
			    "Failed to clean up compressor");
			ret = ARCHIVE_FATAL;
		}
	}
#endif
	free(cab);

	return (ret);
}

static int
file_new(struct archive_write *a, struct archive_entry *entry,
    struct cffile **newfile)
{
	struct cab *cab;
	struct cffile *file;
	const char *utf8;
	size_t ulen;
	int i, ret = ARCHIVE_OK;

	cab = (struct cab *)a->format_data;
	*newfile = NULL;

	file = calloc(1, sizeof(*file));
	if (file == NULL) {
		archive_set_error(&a->archive, ENOMEM,
		    "Can't allocate memory");
		return (ARCHIVE_FATAL);
	}

	if (0 > archive_entry_pathname_l(entry, &utf8, &ulen, cab->sconv)) {
		if (errno == ENOMEM) {
			free(file);
			archive_set_error(&a->archive, ENOMEM,
			    "Can't allocate memory for UTF-8");
			return (ARCHIVE_FATAL);
		}
		archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
		    "Pathname cannot be converted to UTF-8;"
		    "You should disable making Joliet extension");
		ret = ARCHIVE_WARN;
	}
	if (ulen > 255) {
		free(file);
		archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
		    "Pathname length is too long(>255 in UTF-8)");
		return (ARCHIVE_FAILED);
	}
	file->name = malloc(ulen + 1);
	if (file->name == NULL) {
		free(file);
		archive_set_error(&a->archive, ENOMEM,
		    "Can't allocate memory for Name");
		return (ARCHIVE_FATAL);
	}
	memcpy(file->name, utf8, ulen);
	file->name[ulen] = 0;
	file->name_len = ulen;
	file->attr = 0x20;
	for (i = 0; i < (int)ulen; i++) {
		if (utf8[i] & 0x80) {
			file->attr |= ATTR_NAME_IS_UTF;
			break;
		}
	}
	if ((archive_entry_mode(entry) & 0333) == 0)
		file->attr |= ATTR_RDONLY;
	if (archive_entry_filetype(entry) == AE_IFREG)
		file->size = archive_entry_size(entry);
	else
		archive_entry_set_size(entry, 0);
	if (archive_entry_filetype(entry) == AE_IFLNK)
		file->size = strlen(archive_entry_symlink(entry));
	file->mtime = archive_entry_mtime(entry);

	*newfile = file;
	return (ret);
}

static void
file_free(struct cffile *file)
{
	free(file->name);
	free(file);
}

static void
file_register(struct cab *cab, struct cffile *file)
{
	file->next = NULL;
	*cab->file_list.last = file;
	cab->file_list.last = &(file->next);
}

static void
file_init_register(struct cab *cab)
{
	cab->file_list.first = NULL;
	cab->file_list.last = &(cab->file_list.first);
}

static void
file_free_register(struct cab *cab)
{
	struct cffile *file, *file_next;

	file = cab->file_list.first;
	while (file != NULL) {
		file_next = file->next;
		file_free(file);
		file = file_next;
	}
}

static uint32_t
cab_checksum_cfdata_4(const void *p, size_t bytes, uint32_t seed)
{
	const unsigned char *b;
	int u32num;
	uint32_t sum;

	u32num = bytes / 4;
	sum = seed;
	b = p;
	while (--u32num >= 0) {
		sum ^= archive_le32dec(b);
		b += 4;
	}
	return (sum);
}

static uint32_t
cab_checksum_cfdata(const void *p, size_t bytes, uint32_t seed)
{
	const unsigned char *b;
	uint32_t sum;
	uint32_t t;

	sum = cab_checksum_cfdata_4(p, bytes, seed);
	b = p;
	b += bytes & ~3;
	t = 0;
	switch (bytes & 3) {
	case 3:
		t |= ((uint32_t)(*b++)) << 16;
		/* FALL THROUGH */
	case 2:
		t |= ((uint32_t)(*b++)) << 8;
		/* FALL THROUGH */
	case 1:
		t |= *b;
		/* FALL THROUGH */
	default:
		break;
	}
	sum ^= t;

	return (sum);
}

