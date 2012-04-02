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

#define LZX_OK			0
#define LZX_END			1
#define LZX_EOC			2
#define LZX_ERR_MISC		-1
#define LZX_ERR_PARAM		-2
#define LZX_ERR_MEM		-30

struct lzx_enc;
struct lzx_stream {
	const unsigned char	*next_in;
	int64_t			 avail_in;
	int64_t			 total_in;
	unsigned char		*next_out;
	int64_t			 avail_out;
	int64_t			 total_out;
	struct lzx_enc		*ds;
};

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
	uint16_t		 chunk_count;
	uint16_t		 cfdata_count;
	uint16_t		 comptype;
	uint16_t		 compdata;

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
	struct lzx_stream	 lzxstrm;
	int			 lzxstrm_valid;
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
static int	lzx_encode(struct lzx_stream *, int);
static int	lzx_encode_init(struct lzx_stream *, int);
static void	lzx_encode_free(struct lzx_stream *);

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
		else if (strcmp(value, "lzx") == 0 ||
		    strcmp(value, "LZX") == 0)
			cab->opt_compression = COMPTYPE_LZX;
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
write_cfdata(struct archive_write *a, struct cffolder *cffolder,
    size_t compsize, size_t uncompsize)
{
	uint8_t *p = cffolder->cfdata;
	uint32_t sum;

	/* Write compressed size. */
	archive_le16enc(p + 4, (uint16_t)compsize);
	/* Write uncompressed size. */
	archive_le16enc(p + 6, (uint16_t)uncompsize);
	/* Calculate CFDATA sum. */
	sum = cab_checksum_cfdata(p + 8, compsize, 0);
	sum = cab_checksum_cfdata(p + 4, 4, sum);
	/* Write the sum of CFDATA. */
	archive_le32enc(p, sum);

	cffolder->cfdata_count++;
	cffolder->remaining = 0x8000;
	return (write_to_temp(a, p, 8 + compsize));
}

#ifdef HAVE_ZLIB_H
static int
cfdata_compress_mszip(struct archive_write *a)
{
	struct cab *cab = (struct cab *)a->format_data;
	struct cffolder *cffolder = &(cab->cffolder);
	int r;

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
	if (r != Z_STREAM_END) {
		archive_set_error(&(a->archive), ARCHIVE_ERRNO_MISC,
		    "MSZip compression failed: return code %d", r);
		return (ARCHIVE_FATAL);
	}

	deflateReset(&(cab->zstrm));
	if (deflateSetDictionary(&(cab->zstrm),
	    cffolder->uncompressed, 0x8000) != Z_OK) {
		archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
		    "Internal error initializing compression library");
		return (ARCHIVE_FATAL);
	}
	r = write_cfdata(a, cffolder, (size_t)cab->zstrm.total_out,
		(size_t)cab->zstrm.total_in);
	if (r != ARCHIVE_OK)
		return (ARCHIVE_FATAL);
	cab->total_bytes_compressed += cab->zstrm.total_out;
	cab->total_bytes_uncompressed += cab->zstrm.total_in;
	return (ARCHIVE_OK);
}
#endif

static int
cfdata_compress_lzx(struct archive_write *a, int last)
{
	struct cab *cab = (struct cab *)a->format_data;
	struct cffolder *cffolder = &(cab->cffolder);
	size_t usize = 0x8000, last_size;
	int r;

	cab->lzxstrm.next_in = cffolder->uncompressed;
	cab->lzxstrm.avail_in = 0x8000 - cffolder->remaining;
	cab->lzxstrm.total_in = 0;
	cab->lzxstrm.next_out = cffolder->cfdata + 8;
	cab->lzxstrm.avail_out = cffolder->cfdata_allocated_size - 8;
	cab->lzxstrm.total_out = 0;
	if (!cab->lzxstrm.avail_in)
		last_size = 0x8000;
	else
		last_size = (size_t)cab->lzxstrm.avail_in;
	for (;;) {
		switch (r = lzx_encode(&(cab->lzxstrm), last)) {
		default:
			archive_set_error(&(a->archive), ARCHIVE_ERRNO_MISC,
			    "LZX compression failed: return code %d", r);
			return (ARCHIVE_FATAL);
		case LZX_OK: case LZX_END: case LZX_EOC:
			cab->total_bytes_compressed += cab->lzxstrm.total_out;
			cab->total_bytes_uncompressed += cab->lzxstrm.total_in;
			break;
		}
		if (r == LZX_OK)
			return (ARCHIVE_OK);
		if (r == LZX_END)
			usize = last_size;
		if (write_cfdata(a, cffolder, (size_t)cab->lzxstrm.total_out,
		    usize) != ARCHIVE_OK)
			return (ARCHIVE_FATAL);
		if (r == LZX_END)
			return (ARCHIVE_OK);
		cab->lzxstrm.next_out = cffolder->cfdata + 8;
		cab->lzxstrm.avail_out = cffolder->cfdata_allocated_size - 8;
		cab->lzxstrm.total_in = 0;
		cab->lzxstrm.total_out = 0;
	}
}

static int
cfdata_out(struct archive_write *a, int last)
{
	struct cab *cab = (struct cab *)a->format_data;
	struct cffolder *cffolder = &(cab->cffolder);
	size_t uncompsize;
	int r;

	switch (cab->opt_compression) {
	case COMPTYPE_NONE:
		uncompsize = 0x8000 - cffolder->remaining;
		r = write_cfdata(a, cffolder, uncompsize, uncompsize);
		if (r != ARCHIVE_OK)
			return (ARCHIVE_FATAL);
		cab->total_bytes_compressed += uncompsize;
		cab->total_bytes_uncompressed += uncompsize;
		break;
#ifdef HAVE_ZLIB_H
	case COMPTYPE_MSZIP:
		r = cfdata_compress_mszip(a);
		if (r < 0)
			return (r);
		break;
#endif
	case COMPTYPE_LZX:
		r = cfdata_compress_lzx(a, last);
		if (r < 0)
			return (r);
		break;
	}
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
		if (cab->opt_compression != COMPTYPE_NONE) {
			cffolder->uncompressed = malloc(0x8000);
			if (cffolder->uncompressed == NULL) {
				archive_set_error(&a->archive, ENOMEM,
				    "Can't allocate memory");
				return (ARCHIVE_FATAL);
			}
		}
	}

	switch (cab->opt_compression) {
	case COMPTYPE_LZX:
		if (!cab->lzxstrm_valid && s) {
			cffolder->compdata = 21;
			if (lzx_encode_init(&(cab->lzxstrm),
			    cffolder->compdata) != ARCHIVE_OK) {
				archive_set_error(&a->archive,
				    ARCHIVE_ERRNO_MISC,
				    "Internal error initializing "
				    "LZX compression");
				return (ARCHIVE_FATAL);
			}
			cab->lzxstrm_valid = 1;
		}
		dist = cffolder->uncompressed;
		break;
#ifdef HAVE_ZLIB_H
	case COMPTYPE_MSZIP:
		if (!cab->zstrm_valid && s) {
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
		dist = cffolder->uncompressed;
		break;
#endif
	case COMPTYPE_NONE:
	default:
		dist = cffolder->cfdata + 8;
		break;
	}
	ss = s;
	b = buff;

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

		cffolder->chunk_count++;
		r = cfdata_out(a, 0);
		if (r != ARCHIVE_OK)
			return (r);
		b += l;
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
	if (cffolder->cfdata != NULL &&
	    (cffolder->remaining < 0x8000 ||
	     cab->opt_compression == COMPTYPE_LZX)) {
		r = cfdata_out(a, 1);
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
	    (uint16_t)((cffolder->compdata << 8) + cffolder->comptype));
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
	if (cab->lzxstrm_valid)
		lzx_encode_free(&(cab->lzxstrm));
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

/*****************************************************************
 *
 * LZX
 *
 *****************************************************************/
#define LZX_ST_MATCHING		0
#define LZX_ST_PUT_BLOCK	1

#define SLOT_BASE		15
#define SLOT_MAX		21/*->25*/

#define MATCH_MIN		2
#define MATCH_MAX		257
#define MATCH_TOKEN_BITS	(12)
#define MATCH_HASH_SIZE		(1 << MATCH_TOKEN_BITS)

#define CACHE_BITS		64
#define CHUNK_SIZE		0x8000

#define VERBATIM_BLOCK		1
#define ALIGNED_OFFSET_BLOCK	2
#define UNCOMPRESSED_BLOCK	3

#define TREE_MAX		(256 + (289<<3))

struct lzx_enc {
	/* Encoding status. */
	int			 state;
	int			 block_state;


	/* Bit stream writer. */
	struct bit_writer {
		uint64_t	 buff;
		int		 count;
		int		 have_odd:5;
		int		 have_order:1;
		unsigned	 order_bits;
		int		 order_n;
	}			 bw;

	/*
	 * Position slot table.
	 */
	int32_t			*base_pos;
	uint8_t			*footer_bits;

	struct lzx_huf_stat {
		int		 size;
		int		 total_bits;
		uint16_t	*freq;
		uint8_t		*blen;
		uint8_t		*prev_blen;
		uint16_t	*code;
	}			 mt,lt,at, pt;

	struct lzx_huf_tree {
		int16_t		*heap;
		uint16_t	 len_cnt[17];
		uint16_t	*left;
		uint16_t	*right;
	}			 huf_tree;

	uint16_t		*mt_data;
	int			 mt_pos;
	int			 mt_max;
	int			 mt_rp;
	uint8_t			*lt_data;
	int			 lt_pos;
	int			 lt_max;
	int			 lt_rp;
	uint16_t		*ft_data;
	int			 ft_pos;
	int			 ft_max;
	int			 ft_rp;
	uint8_t			*pt_data;
	int			 pt_pos;
	int			 pt_max;
	int			 loop;
	int			 verbatim_bits;
	int			 aligned_offset_bits;

	struct lzx_match {
		enum _match_state {
			MATCH_FIRST_BYTE = 0,
			MATCH_FILL,
			MATCH_FINDING,
			MATCH_PENDING,
			MATCH_END
		}		 state;
		int		 rp_finding;

		int		 w_bits;
		int		 w_size;
		int		 w_mask;
		/* The insert position to the window. */
		int		 w_pos;
		/* Window buffer, which is a loop buffer and takes 
		 * from 32KBi to 2MBi. */
		uint8_t		*w_buff;

		/* Matching buffer. */
		uint8_t		*buff;
		uint8_t		*buff_top;

		int32_t		*hash_tbl;
		uint8_t		*link;
		int		 buff_avail;
		int		 r0;
		int		 r1;
		int		 r2;
		int		 pos;
		int		 len;
		int		 chunk_remaining_bytes;
		uint16_t	 token;
	}			 match;

	int			 block_bytes;
	int			 block_remaining_bytes;
	int			 block_singles;
	int			 chunk_bytes_out;
	int			(*output_block)(struct lzx_stream *);
	int			 make_aligned_offset_block;

	int			 error;
};

static void	lzx_bw_save_order(struct lzx_enc *, int, unsigned);
static int	lzx_bw_fill(struct lzx_stream *);
static int	lzx_bw_fixup(struct lzx_stream *);
static int	lzx_bw_flush(struct lzx_stream *);
static int	lzx_bw_putbits(struct lzx_stream *, int, unsigned);
static int	lzx_find_best_match(struct lzx_stream *, int);
static void	lzx_find_match_length(struct lzx_match *, int);
static void	lzx_find_match_overlapping(struct lzx_match *);
static void	lzx_update_token(struct lzx_match *, int, uint8_t);
static int	lzx_get_next_pos(struct lzx_match *, int);
static void	lzx_update_next_pos(struct lzx_match *, int, int);
static int	lzx_fill_match_buff(struct lzx_stream *, struct lzx_match *);
static int	lzx_make_tree(struct lzx_enc *, struct lzx_huf_stat *);

static const int slots[] = {
	30, 32, 34, 36, 38, 42, 50, 66, 98, 162, 290
};


static int
lzx_fill_match_buff(struct lzx_stream *strm, struct lzx_match *m)
{
	int l;

	if (0 == m->chunk_remaining_bytes)
		return (0);
	if (strm->avail_in <= 0)
		return (-1);
	l = MATCH_MAX - m->buff_avail;
	if (l > strm->avail_in)
		l = (int)strm->avail_in;
	if (l > m->chunk_remaining_bytes)
		l = (int)m->chunk_remaining_bytes;
	if (m->buff_top != m->buff) {
		memmove(m->buff_top, m->buff, m->buff_avail);
		m->buff = m->buff_top;
	}
	memcpy(m->buff + m->buff_avail, strm->next_in, l);
	m->buff_avail += l;
	m->chunk_remaining_bytes -= l;
	strm->avail_in -= l;
	strm->next_in += l;
	
	if (0 == m->chunk_remaining_bytes)
		return (0);
	return ((MATCH_MAX ==  m->buff_avail)?0:-1);
}

#define lzx_make_token(c1, c2)		\
		((((uint16_t)((~(c1))&0xff))<<4) ^ (uint16_t)(c2))

static void
lzx_update_next_pos(struct lzx_match *m, int pos, int next_pos)
{
	int w_bits = m->w_bits;
	int bits = pos * w_bits;
	int idx = bits >> 3;
	int b, mask;

	b = 8 - (pos & 0x7);
	if (b < 8) {
		mask = (1 << b) -1;
		m->link[idx] &= ~mask;
		m->link[idx] |= next_pos >> (w_bits - b);
	} else
		m->link[idx] = next_pos >> (w_bits - 8);
	idx++;
	b += 8;
	while (b < w_bits) {
		m->link[idx++] = next_pos >> (w_bits - b);
		b += 8;
	}
	b = w_bits - b + 8;
	if (b > 0) {
		mask = ((1 << b) -1) << (8 - b);
		m->link[idx] &= ~mask;
		m->link[idx] |= (next_pos & 0xff) << (8 -b);
	}
}

static int
lzx_get_next_pos(struct lzx_match *m, int pos)
{
	int w_bits = m->w_bits;
	int bits = pos * w_bits;
	int idx = bits >> 3;
	int b, mask;
	int next;

	b = 8 - (pos & 0x7);
	if (b < 8) {
		mask = (1 << b) -1;
		next = ((int)(m->link[idx] & mask)) << (w_bits - b);
	} else
		next = ((int)m->link[idx]) << (w_bits - 8);
	idx++;
	b += 8;
	while (b < w_bits) {
		next |= m->link[idx++] << (w_bits - b);
		b += 8;
	}
	b = w_bits - b + 8;
	if (b > 0) {
		mask = ((1 << b) -1) << (8 - b);
		next |= ((int)(m->link[idx+1] & mask)) >> (8 - b);
	}
	return (next);
}

static void
lzx_update_token(struct lzx_match *m, int pos, uint8_t c)
{
	int32_t prev;
	uint16_t token;

	/* Update hash data of the last byte. */
	token = lzx_make_token(m->w_buff[pos], c);
	prev = m->hash_tbl[token];
	m->hash_tbl[token] = pos;
	if (prev == -1)
		prev = pos;
	lzx_update_next_pos(m, pos, prev);
}

static void
lzx_find_match_overlapping(struct lzx_match *m)
{
	uint8_t *m_buff = m->buff, *front;
	int avail = m->buff_avail;
	int l = m->len;

	front = m_buff - ((m->w_pos - m->pos) & m->w_mask);
	while (l < avail && front[l] == m_buff[l])
		l++;
	m->len = l;
}

static void
lzx_find_match_length(struct lzx_match *m, int pos)
{
	uint8_t *w_buff = m->w_buff;
	uint8_t *m_buff = m->buff;
	int w_mask = m->w_mask;
	int avail, distance, l, p;

	distance = (m->w_pos - pos) & w_mask;
	if (m->len < MATCH_MIN) {
		avail = m->buff_avail;
		if (avail > distance)
			avail = distance;
		l = 0;
		p = pos;
		while (l < avail && w_buff[p] == m_buff[l]) {
			p = (p + 1) & w_mask;
			l++;
		}
		if (l > m->len) {
			m->pos = pos;
			m->len = l;
			if (l == distance)
				lzx_find_match_overlapping(m);
		}
	} else {
		l = m->len;
		if (l >= distance) {
			/* Find match bytes overlapping. */
			lzx_find_match_overlapping(m);
		} else {
			/* Matching bytes from the tail to the head. */
			p = (pos + l) & w_mask;
			while (l >= 0 && w_buff[p] == m_buff[l]) {
				p = (p - 1) & w_mask;
				l--;
			}
			if (l < 0) {
				avail = m->buff_avail;
				if (avail > distance)
					avail = distance;
				l = m->len + 1;
				p = (pos + l) & w_mask;
				while (l < avail && w_buff[p] == m_buff[l]) {
					p = (p + 1) & w_mask;
					l++;
				}
				m->pos = pos;
				m->len = l;
				if (l == distance)
					lzx_find_match_overlapping(m);
			}
		}
	}
}

static int
lzx_find_best_match(struct lzx_stream *strm, int last)
{
	struct lzx_match *m = &strm->ds->match;
	uint8_t *w_buff = m->w_buff;
	int c, w_mask = m->w_mask;
	int32_t pos;
	uint16_t token, xtoken;
	int rp_finding;

	if (m->state == MATCH_FIRST_BYTE) {
		if (strm->avail_in <= 0)
			return (-1);
		/* The first byte, this is a single. */
		c = *strm->next_in++;
		m->chunk_remaining_bytes--;
		strm->avail_in--;
		w_buff[++m->w_pos] = c;
		m->state = MATCH_FILL;
		return (c);
	}

	if (m->buff_avail < MATCH_MAX) {
		if (lzx_fill_match_buff(strm, m) != 0 && !last)
			return (-1);
		if (m->buff_avail == 0 &&
			m->chunk_remaining_bytes == 0 && !last) {
			m->chunk_remaining_bytes = CHUNK_SIZE;
			if (lzx_fill_match_buff(strm, m) != 0 && !last)
				return (-1);
		}
		if (m->buff_avail == 0) {
			m->state = MATCH_END;
			return (-2);
		} else if (m->buff_avail == 1) {
			/* The last byte, this is a single. */
			c = m->buff[0];
			m->buff_avail = 0;
			return (c);
		}
	}

	if (m->state != MATCH_PENDING) {
		int ppos;

		m->state = MATCH_FINDING;
		ppos = m->w_pos;
		/* Update hash data of the last byte. */
		lzx_update_token(m, ppos, m->buff[0]);
		m->w_pos = (ppos + 1) & w_mask;

		m->len = 0;
		token = lzx_make_token(m->buff[0], m->buff[1]);
		pos = m->hash_tbl[token];

		/* Check if the position the hash table holds is outdated. */
		if (pos != -1 && pos != ppos) {
			xtoken = lzx_make_token(w_buff[pos],
					w_buff[(pos+1) & w_mask]);
			if (xtoken != token) {
				/* Mark as no links. */
				m->hash_tbl[token] = -1;
				pos = -1;
			}
		}

		/* Check if the position is proper range. */
		if (((m->w_pos - pos) & w_mask) > m->w_size -3)
			pos = -1;/* Out of range. */

		if (pos == -1) {
			/* There isn't the same token, this is a single. */
			c = *m->buff++;
			m->buff_avail--;
			w_buff[m->w_pos] = c;
			return (c);
		}
		m->token = token;
		rp_finding = 1;/* Find repeated positions. */
	} else {
		m->state = MATCH_FINDING;
		token = m->token;
		pos = m->pos;
		rp_finding = 5;
	}

	for (;;) {
		int next, next_distance, pos_distance;

		/*
		 * First of all, find repeated positions to reduece
		 * compressed data.
		 */
		switch (rp_finding) {
		case 0: break;
		case 1:
			++rp_finding;
			pos = (m->w_pos - m->r0) & w_mask;
			break;
		case 2:
			++rp_finding;
			if (m->r1 != m->r0) {
				pos = (m->w_pos - m->r1) & w_mask;
				break;
			}
			/* FALL THROUGH */
		case 3:
			++rp_finding;
			if (m->r2 != m->r0 && m->r2 != m->r1) {
				pos = (m->w_pos - m->r2) & w_mask;
				break;
			}
			/* FALL THROUGH */
		case 4:
			rp_finding = 0;
			token = m->token;
			pos = m->hash_tbl[token];
			break;
		case 5:
			rp_finding = m->rp_finding;
			break;
		}
	
		lzx_find_match_length(m, pos);
		if (m->len == MATCH_MAX)
			break;	/* We've got enough matching bytes. */

		/* If it is a shortage of matching buffer, we have to
		 * fill it up. */
		if (m->len == m->buff_avail) {
			if (lzx_fill_match_buff(strm, m) != 0 && !last) {
				m->state = MATCH_PENDING;
				m->rp_finding = rp_finding;
				return (-1);
			}
			if (m->len == m->buff_avail)
				break;
		}
		if (rp_finding)
			continue;

		next = lzx_get_next_pos(m, pos);

		/* If next position is the same, it means that the hash
		 * link is the end, stop matching. */
		if (next == pos)
			break;

		/* Next position is outdated if that is nearer than the
		 * current position or longer than WINDOW_SIZE-3. */
		next_distance = (m->w_pos - next) & w_mask;
		pos_distance = (m->w_pos - pos) & w_mask;
		if (pos_distance > next_distance ||
		    next_distance > (m->w_size - 3)) {
			/* Mark next position as the terminal. */
			lzx_update_next_pos(m, pos, pos);
			break;
		}

		/* If the token is different, next position is outdated. */
		xtoken = lzx_make_token(w_buff[next], w_buff[(next+1)&w_mask]);
		if (xtoken != token) {
			/* Mark next position as the terminal. */
			lzx_update_next_pos(m, pos, pos);
			break;
		}

		pos = next;
	}
	m->rp_finding = rp_finding;

	if (m->len < MATCH_MIN) {
		/* There isn't the same pattern, this is a single. */
		c = *m->buff++;
		m->buff_avail--;
		w_buff[m->w_pos] = c;
		return (c);
	} else {
		int mlen;
		int w_pos = m->w_pos;
		uint8_t *m_buff = m->buff;

		/* Make the tokens of the matched pattern. */
		for (mlen = m->len; mlen > 1; mlen--) {
			w_buff[w_pos] = *m_buff++;
			lzx_update_token(m, w_pos, m_buff[0]);
			w_pos = (w_pos + 1) & w_mask;
		}
		/* The last bytes of the matched pattern is just copied. */
		w_buff[w_pos] = *m_buff++;
		m->buff = m_buff;
		m->buff_avail -= m->len;
		/* Convert an absolute position to an offset position. */
		m->pos = (m->w_pos - m->pos) & w_mask;
		m->w_pos = w_pos;
		return (256);
	}
}

static void
lzx_bw_save_order(struct lzx_enc *ds, int n, unsigned bits)
{
	ds->bw.have_order = 1;
	ds->bw.order_bits = bits;
	ds->bw.order_n = n;
}

static int
lzx_bw_fill(struct lzx_stream *strm)
{
	struct lzx_enc *ds = strm->ds;
	int i = 8 - ds->bw.have_odd;

	while (strm->avail_out > 1 && ds->bw.have_odd) {
		strm->next_out[0] = (uint8_t)(ds->bw.buff >> (48 - (i * 8)));
		strm->next_out[1] = (uint8_t)(ds->bw.buff >> (56 - (i * 8)));
		strm->next_out += 2;
		strm->avail_out -= 2;
		strm->total_out += 2;
		ds->bw.have_odd -= 2;
		i += 2;
	}
	if (strm->avail_out && ds->bw.have_odd) {
		*strm->next_out++ = (uint8_t)(ds->bw.buff >> (48 - (i * 8)));
		strm->avail_out--;
		strm->total_out++;
		ds->bw.have_odd--;
	}
	if (ds->bw.have_odd == 0)
		ds->bw.buff = 0;
	return (strm->avail_out > 0);
}

static int
lzx_bw_fixup(struct lzx_stream *strm)
{
	struct lzx_enc *ds = strm->ds;

	if (ds->bw.have_odd) {
		if (strm->avail_out == 0)
			return (0);
		if (ds->bw.have_odd & 1) {
			int i = 8 - ds->bw.have_odd;
			*strm->next_out++ = (uint8_t)
				(ds->bw.buff >> (64 - (i * 8)));
			strm->avail_out--;
			strm->total_out++;
			ds->bw.have_odd--;
			if (ds->bw.have_odd == 0)
				ds->bw.buff = 0;
			if (strm->avail_out == 0)
				return (0);
		}
		if (ds->bw.have_odd) {
			if (lzx_bw_fill(strm) == 0)
				return (0);
		}
	}
	if (ds->bw.have_order) {
		int n = ds->bw.order_n;
		unsigned bits = ds->bw.order_bits;

		if (strm->avail_out == 0)
			return (0);
		ds->bw.order_n = 0;
		ds->bw.have_order = 0;
		if (lzx_bw_putbits(strm, n, bits) == 0)
			return (0);
	}
	return (1);
}

static int
lzx_bw_flush(struct lzx_stream *strm)
{
	struct lzx_enc *ds = strm->ds;

	if (ds->bw.count == CACHE_BITS)
		return (1);
	ds->bw.have_odd = (CACHE_BITS - ds->bw.count + 7) >> 3;
	if (ds->bw.have_odd & 1)
		ds->bw.have_odd++;
	ds->bw.buff >>= (8 - ds->bw.have_odd) * 8;
	return (lzx_bw_fill(strm));
}

static int
lzx_bw_putbits(struct lzx_stream *strm, int n, unsigned bits)
{
	struct lzx_enc *ds = strm->ds;
	unsigned x = bits & (0xFFFFFFFF >> (CACHE_BITS - n));

	while (n >= ds->bw.count) {
		ds->bw.buff |= x >> (n - ds->bw.count);
		n -= ds->bw.count;
		ds->bw.count = CACHE_BITS;
		if (strm->avail_out == 0) {
			if (n > 0)
				lzx_bw_save_order(ds, n, x);
			return (0);
		} else if (strm->avail_out < sizeof(ds->bw.buff)) {
			ds->bw.have_odd = sizeof(ds->bw.buff);
			lzx_bw_fill(strm);
			if (n > 0)
				lzx_bw_save_order(ds, n, x);
			return (0);
		} else {
			strm->next_out[0] = (uint8_t)(ds->bw.buff >> 48);
			strm->next_out[1] = (uint8_t)(ds->bw.buff >> 56);
			strm->next_out[2] = (uint8_t)(ds->bw.buff >> 32);
			strm->next_out[3] = (uint8_t)(ds->bw.buff >> 40);
			strm->next_out[4] = (uint8_t)(ds->bw.buff >> 16);
			strm->next_out[5] = (uint8_t)(ds->bw.buff >> 24);
			strm->next_out[6] = (uint8_t)(ds->bw.buff & 0xFF);
			strm->next_out[7] = (uint8_t)(ds->bw.buff >> 8);
			strm->next_out += sizeof(ds->bw.buff);
			strm->avail_out -= sizeof(ds->bw.buff);
			strm->total_out += sizeof(ds->bw.buff);
			ds->bw.buff = 0;
			if (strm->avail_out == 0) {
				if (n > 0)
					lzx_bw_save_order(ds, n, x);
				return (0);
			}
		}
	}
	if (n > 0)
		ds->bw.buff |= ((uint64_t)x) << (ds->bw.count -= n);
	return (1);
}

static int
lzx_init_huf_stat(struct lzx_huf_stat *hs, int size)
{

	if (hs->freq == NULL || hs->size < size) {
		free(hs->freq);
		hs->freq = calloc(sizeof(hs->freq[0]), size << 1);
		if (hs->freq == NULL)
			return (-1);
		free(hs->blen);
		hs->blen = calloc(sizeof(hs->blen[0]), size);
		if (hs->blen == NULL)
			return (-1);
		free(hs->prev_blen);
		hs->prev_blen = calloc(sizeof(hs->prev_blen[0]), size);
		if (hs->prev_blen == NULL)
			return (-1);
		free(hs->code);
		hs->code = malloc(sizeof(hs->code[0]) * size);
		if (hs->code == NULL)
			return (-1);
	} else {
		memset(hs->freq, 0, sizeof(hs->freq[0]) * (size << 1));
		memset(hs->blen, 0, sizeof(hs->blen[0]) * size);
		memset(hs->prev_blen, 0, sizeof(hs->prev_blen[0]) * size);
	}
	hs->size = size;
	hs->total_bits = 0;
	return (0);
}

static void
lzx_reset_huf_stat(struct lzx_huf_stat *hs)
{
	hs->total_bits = 0;
	memset(hs->freq, 0, sizeof(hs->freq[0]) * (hs->size << 1));
	memcpy(hs->prev_blen, hs->blen, sizeof(hs->prev_blen[0]) * hs->size);
	memset(hs->blen, 0, sizeof(hs->blen[0]) * hs->size);
}

static void
lzx_free_huf_stat(struct lzx_huf_stat *hs)
{
	free(hs->freq);
	free(hs->blen);
	free(hs->prev_blen);
	free(hs->code);
}

static int
lzx_make_slot_table(struct lzx_enc *ds, int w_slot)
{
	int slot;
	int base, footer;
	int base_inc[18];

	free(ds->base_pos);
	ds->base_pos = malloc(sizeof(ds->base_pos[0]) * w_slot);
	if (ds->base_pos == NULL)
		return (-1);
	free(ds->footer_bits);
	ds->footer_bits = malloc(sizeof(ds->footer_bits[0]) * w_slot);
	if (ds->footer_bits == NULL)
		return (-1);

	for (footer = 0; footer < 18; footer++)
		base_inc[footer] = 1 << footer;
	base = footer = 0;
	for (slot = 0; slot < w_slot; slot++) {
		int n;
		if (footer == 0)
			base = slot;
		else
			base += base_inc[footer];
		if (footer < 17) {
			footer = -2;
			for (n = base; n; n >>= 1)
				footer++;
			if (footer <= 0)
				footer = 0;
		}
		ds->base_pos[slot] = (int32_t)base;
		ds->footer_bits[slot] = (uint8_t)footer;
	}
	return (0);
}

static int
lzx_encode_init(struct lzx_stream *strm, int w_bits)
{
	struct lzx_enc *ds;
	int w_size, w_slot;
	int size;

	if (strm->ds == NULL) {
		strm->ds = calloc(1, sizeof(*strm->ds));
		if (strm->ds == NULL)
			return (LZX_ERR_MEM);
	}
	ds = strm->ds;
	ds->error = LZX_ERR_PARAM;

	/* Allow bits from 15(32KBi) up to 21(2MBi) */
	if (w_bits < SLOT_BASE || w_bits > SLOT_MAX)
		return (LZX_ERR_PARAM);

	ds->error = LZX_ERR_MEM;

	/*
	 * Alloc window
	 */
	w_size = ds->match.w_size;
	w_slot = slots[w_bits - SLOT_BASE];
	ds->match.w_bits = w_bits;
	ds->match.w_size = 1U << w_bits;
	ds->match.w_mask = ds->match.w_size -1;
	if (ds->match.w_buff == NULL || w_size != ds->match.w_size) {
		free(ds->match.w_buff);
		ds->match.w_buff = malloc(ds->match.w_size);
		if (ds->match.w_buff == NULL)
			goto error;
		free(ds->huf_tree.heap);
		ds->huf_tree.heap =
		    malloc(sizeof(ds->huf_tree.heap[0])
				* (256 + (w_slot << 3) + 1));
		if (ds->huf_tree.heap == NULL)
			goto error;
		free(ds->huf_tree.left);
		ds->huf_tree.left =
		    malloc(sizeof(ds->huf_tree.left[0])
				* (256 + (w_slot << 3) +1));
		if (ds->huf_tree.left == NULL)
			goto error;
		free(ds->huf_tree.right);
		ds->huf_tree.right =
		    malloc(sizeof(ds->huf_tree.right[0])
				* (256 + (w_slot << 3) +1));
		if (ds->huf_tree.right == NULL)
			goto error;
		if (lzx_make_slot_table(ds, w_slot) < 0)
			goto error;
	}

	if (lzx_init_huf_stat(&ds->mt, (w_slot << 3) + 256) < 0)
		goto error;
	if (lzx_init_huf_stat(&ds->lt, 249) < 0)
		goto error;
	if (lzx_init_huf_stat(&ds->at, 8) < 0)
		goto error;

	if (ds->mt_max == 0) {
		ds->mt_max = 0x4000;
		ds->mt_data = malloc(ds->mt_max * sizeof(ds->mt_data[0]));
		if (ds->mt_data == NULL)
			goto error;
	}
	ds->mt_pos = 0;
	if (ds->lt_max == 0) {
		ds->lt_max = 0x1000;
		ds->lt_data = malloc(ds->lt_max * sizeof(ds->lt_data[0]));
		if (ds->lt_data == NULL)
			goto error;
	}
	ds->lt_pos = 0;
	if (ds->ft_max == 0) {
		ds->ft_max = 0x1000;
		ds->ft_data = malloc(ds->ft_max * sizeof(ds->ft_data[0]));
		if (ds->ft_data == NULL)
			goto error;
	}
	ds->ft_pos = 0;
	if (ds->pt_max == 0) {
		ds->pt_max = (w_slot << 3) + 256;
		ds->pt_data = malloc(ds->pt_max * sizeof(ds->pt_data[0]));
		if (ds->pt_data == NULL)
			goto error;
	}

	ds->bw.count = CACHE_BITS;

	if (ds->match.buff == NULL) {
		ds->match.buff_top = malloc(MATCH_MAX);
		if (ds->match.buff_top == NULL)
			goto error;
		ds->match.buff = ds->match.buff_top;
	}
	if (ds->match.hash_tbl == NULL) {
		size = MATCH_HASH_SIZE * sizeof(ds->match.hash_tbl[0]);
		ds->match.hash_tbl = malloc(size);
		if (ds->match.hash_tbl == NULL)
			goto error;
		memset(ds->match.hash_tbl, 0xff, size);
	}
	if (ds->match.link == NULL || w_size != ds->match.w_size) {
		free(ds->match.link);
		size = ((ds->match.w_bits * ds->match.w_size) + 7) >> 3;
		ds->match.link = calloc(size, 1);
		if (ds->match.link == NULL)
			goto error;
	}
	ds->match.state = MATCH_FIRST_BYTE;
	ds->match.chunk_remaining_bytes = CHUNK_SIZE;
	ds->match.w_pos = -1;
	ds->match.r0 = ds->match.r1 = ds->match.r2 = 1;
	ds->chunk_bytes_out = CHUNK_SIZE;
	ds->error = LZX_OK;

	return (LZX_OK);
error:
	lzx_encode_free(strm);
	return (ds->error);
}

static void
lzx_encode_free(struct lzx_stream *strm)
{
	if (strm->ds == NULL)
		return;
	free(strm->ds->base_pos);
	free(strm->ds->footer_bits);
	free(strm->ds->huf_tree.heap);
	free(strm->ds->huf_tree.left);
	free(strm->ds->huf_tree.right);
	lzx_free_huf_stat(&(strm->ds->mt));
	lzx_free_huf_stat(&(strm->ds->lt));
	lzx_free_huf_stat(&(strm->ds->at));
	lzx_free_huf_stat(&(strm->ds->pt));
	free(strm->ds->mt_data);
	free(strm->ds->lt_data);
	free(strm->ds->ft_data);
	free(strm->ds->pt_data);
	free(strm->ds->match.w_buff);
	free(strm->ds->match.buff_top);
	free(strm->ds->match.hash_tbl);
	free(strm->ds->match.link);
	free(strm->ds);
	strm->ds = NULL;
}

static int
lzx_ensure_mt_data(struct lzx_enc *ds, int len)
{
	void *p;

	if (ds->mt_pos + len <= ds->mt_max)
		return (0);
	ds->mt_max += 0x1000;
	p = realloc(ds->mt_data, ds->mt_max * sizeof(ds->mt_data[0]));
	if (p == NULL)
		return (-1);
	ds->mt_data = p;
	return (0);
}

static int
lzx_ensure_lt_data(struct lzx_enc *ds, int len)
{
	void *p;

	if (ds->lt_pos + len <= ds->lt_max)
		return (0);
	ds->lt_max += 0x1000;
	p = realloc(ds->lt_data, ds->lt_max * sizeof(ds->lt_data[0]));
	if (p == NULL)
		return (-1);
	ds->lt_data = p;
	return (0);
}

static int
lzx_ensure_ft_data(struct lzx_enc *ds, int len)
{
	void *p;

	if (ds->ft_pos + len <= ds->ft_max)
		return (0);
	ds->ft_max += 0x1000;
	p = realloc(ds->ft_data, ds->ft_max * sizeof(ds->ft_data[0]));
	if (p == NULL)
		return (-1);
	ds->ft_data = p;
	return (0);
}

static int
lzx_encode_match(struct lzx_enc *ds, int c)
{
	struct lzx_match *m = &(ds->match);

	if (c < 256) {
fprintf(stderr, "single c = 0x%X\n", c);
		ds->block_bytes++;
		ds->block_singles++;
	} else {
		int f_offset, t;
		int slot;
		int pos_footer;
		int len_header, len_footer;
		int offset_bits;

fprintf(stderr, "offset = %d, len = %d\n", m->pos, m->len);
		ds->block_bytes += m->len;
		/*
		 * Converting match offset into formatted offset value.
		 */
		if (m->r0 == m->pos)
			f_offset = 0;
		else if (m->r1 == m->pos) {
			f_offset = 1;
			t = m->r0;
			m->r0 = m->r1;
			m->r1 = t;
		} else if (m->r2 == m->pos) {
			f_offset = 2;
			t = m->r0;
			m->r0 = m->r2;
			m->r2 = t;
		} else {
			f_offset = m->pos + 2;
			m->r2 = m->r1;
			m->r1 = m->r0;
			m->r0 = m->pos;
		}

		/*
		 * Converting formatted offset into positin slot and
		 * position footer values.
		 */
		if (f_offset > 3) {
			int slot_max = slots[m->w_bits - SLOT_BASE];
			for (slot = 5; slot < slot_max; slot++) {
				if (f_offset < ds->base_pos[slot])
					break;
			}
			--slot;
			pos_footer = f_offset - ds->base_pos[slot];
		} else {
			slot = f_offset;
			pos_footer = 0;
		}

		/*
		 * Converting match length into length header and length
		 * footer values.
		 */
		if (m->len <= 8) {
			len_header = m->len - 2;
			len_footer = -1;
		} else {
			len_header = 7;
			len_footer = m->len - 9;
			if (len_footer > 248)
				len_footer = 248;
		}

		/*
		 * Converting length header and position slot into
		 * length/position header value.
		 */
		c = (slot << 3) + len_header + 256;

		if ((offset_bits = ds->footer_bits[slot]) > 0) {
			ds->verbatim_bits += offset_bits;
			if (offset_bits >= 3) {
				ds->at.freq[pos_footer&0x7]++;
				ds->aligned_offset_bits += offset_bits - 3;
			} else
				ds->aligned_offset_bits += offset_bits;

			if (lzx_ensure_ft_data(ds, 2) < 0)
				return (LZX_ERR_MEM);
			ds->ft_data[ds->ft_pos++] = (uint16_t)pos_footer;
		}

		if (len_footer >= 0) {
			if (lzx_ensure_lt_data(ds, 1) < 0)
				return (LZX_ERR_MEM);
			ds->lt.freq[len_footer]++;
			ds->lt_data[ds->lt_pos++] = len_footer;
		}
	}
	if (lzx_ensure_mt_data(ds, 1) < 0)
		return (LZX_ERR_MEM);
	ds->mt_data[ds->mt_pos++] = c;
	ds->mt.freq[c]++;

	return (LZX_OK);
}

static int
lzx_make_pre_tree(struct lzx_enc *ds, struct lzx_huf_stat *hs,
    int start, int end)
{
	uint16_t *freq;
	uint8_t *blen, *prev_blen;
	uint8_t *pt_data;
	int pt_pos = 0;
	int i;

	if (lzx_init_huf_stat(&ds->pt, 20) < 0)
		return (-1);
	if (end < 0 || end > hs->size)
		end = hs->size;
	blen = hs->blen;
	prev_blen = hs->prev_blen;
	pt_data = ds->pt_data;
	freq = ds->pt.freq;
	for (i = start; i < end;) {
		int c, j;

		/* Find continuous zeroes. */
		for (j = i; j < end; j++) {
			if (blen[j])
				break;
		}
		if (j - i >= 20) {
			freq[18]++;
			pt_data[pt_pos++] = 18;
			c = j - i - 20;
			if (c > 0x1f)
				c = 0x1f;
			pt_data[pt_pos++] = c;
			i += c + 20;
			continue;
		}
		if (j - i >= 4) {
			freq[17]++;
			pt_data[pt_pos++] = 17;
			c = j - i - 4;
			if (c > 0x0f)
				c = 0x0f;
			pt_data[pt_pos++] = c;
			i += c + 4;
			continue;
		}

		/* Find the same continuous values. */
		c = blen[i];
		for (j = i+1; j < end; j++) {
			if (blen[j] != c)
				break;
		}
		c = j - i;
		if (c == 4 || c == 5) {
			freq[19]++;
			pt_data[pt_pos++] = 19;
			pt_data[pt_pos++] = c & 1;
			if (blen[i] > prev_blen[i])
				c = 17 - (blen[i] - prev_blen[i]);
			else
				c = prev_blen[i] - blen[i];
			freq[c]++;
			pt_data[pt_pos++] = c;
			i += j - i;
			continue;
		}

		if (blen[i] > prev_blen[i])
			c = 17 - (blen[i] - prev_blen[i]);
		else
			c = prev_blen[i] - blen[i];
		freq[c]++;
		pt_data[pt_pos++] = c;
		i++;
	}
	ds->pt_pos = pt_pos;

	lzx_make_tree(ds, &(ds->pt));
	return (0);
}

static int
lzx_output_pre_tree(struct lzx_stream *strm, struct lzx_enc *ds)
{
	uint8_t *blen;
	int i;

	blen = ds->pt.blen;
	for (i = ds->loop; i < ds->pt.size; i++) {
		if (lzx_bw_putbits(strm, 4, blen[i]) == 0) {
			ds->loop = i + 1;
			return (0);
		}
	}
	ds->loop = i;
	return (1);
}

static int
lzx_output_path_lengths(struct lzx_stream *strm, struct lzx_enc *ds)
{
	uint8_t *pt_data;
	uint8_t *blen;
	uint16_t *code;
	int i;

	pt_data = ds->pt_data;
	blen = ds->pt.blen;
	code = ds->pt.code;
	for (i = ds->loop; i < ds->pt_pos;) {
		int c, s, w; 

		c = pt_data[i++];
		s = blen[c];
		w = code[c];
		switch (c) {
		case 17:
			c = pt_data[i++];
			s += 4;
			w = (w << 4) + c;
			break;
		case 18:
			c = pt_data[i++];
			s += 5;
			w = (w << 5) + c;
			break;
		case 19:
			c = pt_data[i++];
			s += 1;
			w = (w << 1) + c;
			c = pt_data[i++];
			s += blen[c];
			w = (w << blen[c]) + code[c];
			break;
		}
		if (lzx_bw_putbits(strm, s, w) == 0) {
			ds->loop = i;
			return (0);
		}
	}
	return (1);
}

static void
lzx_reset_block(struct lzx_enc *ds)
{
	ds->block_state = 0;
	ds->output_block = NULL;
	ds->state = LZX_ST_MATCHING;
	ds->mt_pos = 0;
	lzx_reset_huf_stat(&(ds->mt));
	ds->lt_pos = 0;
	lzx_reset_huf_stat(&(ds->lt));
	lzx_reset_huf_stat(&(ds->at));
	ds->ft_pos = 0;
	ds->block_bytes = 0;
	ds->block_singles = 0;
	ds->verbatim_bits = 0;
	ds->aligned_offset_bits = 0;
}

static int
lzx_output_uncompressed_block(struct lzx_stream *strm)
{
	struct lzx_enc *ds = strm->ds;
	uint8_t *outp, *endp, *w_buff;
	int r, r_pos, w_mask;

	switch (ds->block_state) {
	case 0:
		/*
		 * Make an uncompressed block.
		 */
		/* Translation = OFF */
		if (!lzx_bw_putbits(strm, 1, 0)) {
			ds->block_state = 1;
			return (LZX_OK);
		}
		/* FALL THROUGH */
	case 1:
		/* Output Block Type. */
		if (!lzx_bw_putbits(strm, 3, UNCOMPRESSED_BLOCK)) {
			ds->block_state = 2;
			return (LZX_OK);
		}
		/* FALL THROUGH */
	case 2:
		/* Output Block Size. */
		if (!lzx_bw_putbits(strm, 24, (unsigned)ds->block_bytes)) {
			ds->block_state = 3;
			return (LZX_OK);
		}
		/* FALL THROUGH */
	case 3:
		/* Align the bit stream by 16 bits. */
		if ((ds->bw.count & 0xF) == 0)
			r = lzx_bw_putbits(strm, 16, 0);
		else
			r = lzx_bw_putbits(strm, ds->bw.count & 0xF, 0);
		if (!r) {
			ds->block_state = 4;
			return (LZX_OK);
		}
		/* FALL THROUGH */
	case 4:
		if (!lzx_bw_putbits(strm, 32, (unsigned)ds->match.r0)) {
			ds->block_state = 5;
			return (LZX_OK);
		}
		/* FALL THROUGH */
	case 5:
		if (!lzx_bw_putbits(strm, 32, (unsigned)ds->match.r1)) {
			ds->block_state = 6;
			return (LZX_OK);
		}
		/* FALL THROUGH */
	case 6:
		if (!lzx_bw_putbits(strm, 32, (unsigned)ds->match.r2)) {
			ds->block_state = 7;
			return (LZX_OK);
		}
		/* FALL THROUGH */
	case 7:
		if (!lzx_bw_flush(strm)) {
			ds->block_state = 8;
			return (LZX_OK);
		}
		/* FALL THROUGH */
	case 8:
		ds->block_remaining_bytes = ds->block_bytes;
		/* FALL THROUGH */
	case 9:
		outp = strm->next_out;
		if (strm->avail_out > ds->chunk_bytes_out)
			endp = outp + ds->chunk_bytes_out;
		else
			endp = outp + strm->avail_out;
		if (endp - outp > ds->block_remaining_bytes)
			endp = outp + ds->block_remaining_bytes;
		w_mask = ds->match.w_mask;
		w_buff = ds->match.w_buff;
		r_pos = (ds->match.w_pos -
			     ds->block_remaining_bytes + 1) & w_mask;
		if (endp - outp > ds->match.w_size - r_pos) {
			int l = ds->match.w_size - r_pos;
			memcpy(outp, w_buff+r_pos, l);
			outp += l;
			r_pos = (r_pos + l) & w_mask;
		}
		if (outp < endp) {
			memcpy(outp, w_buff+r_pos, endp - outp);
			outp = endp;
		}
		ds->block_remaining_bytes -= outp - strm->next_out;
		strm->avail_out -= outp - strm->next_out;
		strm->total_out += outp - strm->next_out;
		ds->chunk_bytes_out -= outp - strm->next_out;
		strm->next_out = outp;
		if (ds->chunk_bytes_out == 0) {
			ds->chunk_bytes_out = CHUNK_SIZE;
			if (ds->block_remaining_bytes == 0)
				ds->block_state = 10;
			else
				ds->block_state = 9;
			return (LZX_EOC);
		}
		if (strm->avail_out == 0) {
			if (ds->block_remaining_bytes == 0)
				ds->block_state = 10;
			else
				ds->block_state = 9;
			return (LZX_OK);
		}
		/* FALL THROUGH */
	case 10:
		if (ds->block_bytes & 1) {
			if (strm->avail_out <= 0) {
				ds->block_state = 10;
				return (LZX_OK);
			}
			*strm->next_out++ = 0;
			strm->avail_out--;
			strm->total_out++;
		}
		break;
	}
	lzx_reset_block(ds);
	if (ds->chunk_bytes_out == 0) {
		ds->chunk_bytes_out = CHUNK_SIZE;
		return (LZX_EOC);
	}
	return (LZX_OK);
}

static int
lzx_output_verbatim_block(struct lzx_stream *strm)
{
	struct lzx_enc *ds = strm->ds;
	int i, aligned, blocktype;

	switch (ds->block_state) {
	case 0:
		ds->loop = 0;
		/* FALL THROUGH */
	case 1:
		if (ds->make_aligned_offset_block) {
			for (i = ds->loop; i < 8; i++) {
				if (!lzx_bw_putbits(strm, 3, ds->at.blen[i])) {
					ds->loop = i + 1;
					ds->block_state = 1;
					return (LZX_OK);
				}
			}
		}
		/* FALL THROUGH */
	case 2:
		if (lzx_make_pre_tree(ds, &(ds->mt), 0, 256) < 0)
			return (LZX_ERR_MEM);
		ds->loop = 0;
		/* FALL THROUGH */
	case 3:
		if (!lzx_output_pre_tree(strm, ds)) {
			ds->block_state = 3;
			return (LZX_OK);
		}
		ds->loop = 0;
		/* FALL THROUGH */
	case 4:
		if (!lzx_output_path_lengths(strm, ds)) {
			ds->block_state = 4;
			return (LZX_OK);
		}
		/* FALL THROUGH */
	case 5:
		if (lzx_make_pre_tree(ds, &(ds->mt), 256, -1) < 0)
			return (LZX_ERR_MEM);
		ds->loop = 0;
		/* FALL THROUGH */
	case 6:
		if (!lzx_output_pre_tree(strm, ds)) {
			ds->block_state = 6;
			return (LZX_OK);
		}
		ds->loop = 0;
		/* FALL THROUGH */
	case 7:
		if (!lzx_output_path_lengths(strm, ds)) {
			ds->block_state = 7;
			return (LZX_OK);
		}
		/* FALL THROUGH */
	case 8:
		if (lzx_make_pre_tree(ds, &(ds->lt), 0, -1) < 0)
			return (LZX_ERR_MEM);
		ds->loop = 0;
		/* FALL THROUGH */
	case 9:
		if (!lzx_output_pre_tree(strm, ds)) {
			ds->block_state = 9;
			return (LZX_OK);
		}
		ds->loop = 0;
		/* FALL THROUGH */
	case 10:
		if (!lzx_output_path_lengths(strm, ds)) {
			ds->block_state = 10;
			return (LZX_OK);
		}
		/* FALL THROUGH */
	case 11:
		/* Output Translation = OFF, Block Type. */
		if (ds->make_aligned_offset_block)
			blocktype = ALIGNED_OFFSET_BLOCK;
		else
			blocktype = VERBATIM_BLOCK;
		if (!lzx_bw_putbits(strm, 4, blocktype)) {
			ds->block_state = 12;
			return (LZX_OK);
		}
		/* FALL THROUGH */
	case 12:
		/* Output Block Size. */
		if (!lzx_bw_putbits(strm, 24, (unsigned)ds->block_bytes)) {
			ds->block_state = 13;
			return (LZX_OK);
		}
		/* FALL THROUGH */
	case 13:
		ds->mt_rp = 0;
		ds->lt_rp = 0;
		ds->ft_rp = 0;
		/* FALL THROUGH */
	case 14:
		aligned = ds->make_aligned_offset_block;
		while (ds->mt_rp < ds->mt_pos) {
			int c, b, d;

			/* Output Main Tree element. */
			c = ds->mt_data[ds->mt_rp++];
			b = ds->mt.blen[c];
			d = ds->mt.code[c];
			if (c < 256) {
				ds->chunk_bytes_out--;
			} else {
				int bits;

				c -= 256;
				if ((c & 7) == 7) {
					int lf;

					/* Output Length Tree element. */
					lf = ds->lt_data[ds->lt_rp++];
					bits = ds->lt.blen[lf];
					b += bits;
					d = (d << bits) + ds->lt.code[lf];
					ds->chunk_bytes_out -= lf + 9;
				} else
					ds->chunk_bytes_out -= (c & 7) + 2;

				bits = ds->footer_bits[c >> 3];
				if (bits > 0) {
					int pf;

					pf = ds->ft_data[ds->ft_rp++];
					if (bits > 16)
						pf |= 0x10000;
					if (aligned && bits >= 3) {
						/* Output Verbatim bits. */
						b += bits - 3;
						d = (d << (bits-3)) + (pf>>3);
						/* Output Aligned offset. */
						pf &= 7;
						bits = ds->at.blen[pf];
						b += bits;
						d = (d << bits) +
							ds->at.code[pf];
					} else {
						/* Output Verbatim bits. */
						b += bits;
						d = (d << bits) + pf;
					}
				}
			}
			if (!lzx_bw_putbits(strm, b, d)) {
				ds->block_state = 14;
				return (LZX_OK);
			}
			if (ds->chunk_bytes_out == 0) {
				ds->block_state = 14;
				ds->chunk_bytes_out = CHUNK_SIZE;
				return (LZX_EOC);
			}
		}
		break;
	}
	lzx_reset_block(ds);
	if (ds->chunk_bytes_out == 0) {
		ds->chunk_bytes_out = CHUNK_SIZE;
		return (LZX_EOC);
	}
	return (LZX_OK);
}

static int
lzx_encode(struct lzx_stream *strm, int last)
{
	struct lzx_enc *ds = strm->ds;
	int64_t avail_in, total_bits;
	int64_t v_bits, a_bits;
	int c, r;

	if (ds->error)
		return (ds->error);

	if (lzx_bw_fixup(strm) == 0)
		return (LZX_OK);

	if (ds->output_block != NULL) {
		r = ds->output_block(strm);
		if (r != LZX_OK)
			return (r);
		if (ds->state == LZX_ST_PUT_BLOCK)
			return (LZX_OK);
	}

	avail_in = strm->avail_in;
	while ((c = lzx_find_best_match(strm, last)) >= 0) {
		r = lzx_encode_match(ds, c);
		if (r != LZX_OK)
			return (r);
		if (ds->match.chunk_remaining_bytes == 0 &&
		    ds->mt_pos > 0x2000)
			break;
	}
	strm->total_in += avail_in - strm->avail_in;
	if (ds->match.chunk_remaining_bytes == 0)
		ds->match.chunk_remaining_bytes = CHUNK_SIZE;
	if (c == -1)
		return (LZX_OK);

	lzx_make_tree(ds, &(ds->mt));
	lzx_make_tree(ds, &(ds->lt));
	lzx_make_tree(ds, &(ds->at));

	ds->state = LZX_ST_PUT_BLOCK;
	total_bits = ds->mt.total_bits + ds->lt.total_bits;
	v_bits = ds->verbatim_bits;
	a_bits = 24 + ds->aligned_offset_bits + ds->at.total_bits;
	if (v_bits > a_bits) {
		ds->make_aligned_offset_block = 1;
		total_bits += a_bits;
	} else {
		ds->make_aligned_offset_block = 0;
		total_bits += v_bits;
	}
	total_bits += 80 * 3;
	
	if ((total_bits >> 3) > ds->block_bytes)
		ds->output_block = lzx_output_uncompressed_block;
	else
		ds->output_block = lzx_output_verbatim_block;

	r = ds->output_block(strm);
	if (r != LZX_OK)
		return (r);
	if (ds->state == LZX_ST_PUT_BLOCK || c >= 0)
		return (LZX_OK);
	return (LZX_END);
}

static void
lzx_count_len(uint16_t i, int depth, uint16_t size, struct lzx_huf_tree *tp)
{
	if (i < size)
		tp->len_cnt[(depth < 16) ? depth : 16]++;
	else {
		lzx_count_len(tp->left [i], depth+1, size, tp);
		lzx_count_len(tp->right[i], depth+1, size, tp);
	}
}

static void
lzx_make_bitlen(uint16_t root, struct lzx_huf_tree *tp, struct lzx_huf_stat *hs)
{
	int i, k;
	unsigned cum;
	uint8_t *blen = hs->blen;
	uint16_t *len_cnt = tp->len_cnt;
	uint16_t *sortptr = hs->code;

	memset(len_cnt, 0, sizeof(tp->len_cnt));
	lzx_count_len(root, 0, (uint16_t)hs->size, tp);
	cum = 0;
	for (i = 16; i > 0; i--)
		cum += len_cnt[i] << (16 - i);
	while (cum != (1U << 16)) {
		len_cnt[16]--;
		for (i = 15; i > 0; i--) {
			if (len_cnt[i] != 0) {
				len_cnt[i]--;
				len_cnt[i+1] += 2;
				break;
			}
		}
		cum--;
	}
	for (i = 16; i > 0; i--) {
		k = len_cnt[i];
		while (--k >= 0)
			blen[*sortptr++] = i;
	}
}

/* priority queue; send i-th entry down heap */
static void
lzx_downheap(struct lzx_huf_tree *tp, struct lzx_huf_stat *hs, int i,
    int heapsize)
{
	uint16_t *freq = hs->freq;
	int16_t *heap = tp->heap;
	int j, k;

	k = heap[i];
	while ((j = 2 * i) <= heapsize) {
		if (j < heapsize && freq[heap[j]] > freq[heap[j + 1]])
		 	j++;
		if (freq[k] <= freq[heap[j]])
			break;
		heap[i] = heap[j];
		i = j;
	}
	heap[i] = k;
}

static void
lzx_make_code(struct lzx_huf_tree *tp, struct lzx_huf_stat *hs)
{
	uint16_t start[18];
	uint16_t *len_cnt = tp->len_cnt;
	uint16_t *code = hs->code;
	uint8_t *blen = hs->blen;
	int i, n = hs->size;

	start[1] = 0;
	for (i = 1; i <= 16; i++)
		start[i + 1] = (start[i] + len_cnt[i]) << 1;
	for (i = 0; i < n; i++)
		code[i] = start[blen[i]]++;
}

static int
lzx_make_tree(struct lzx_enc *ds, struct lzx_huf_stat *hs)
{
	struct lzx_huf_tree *tp = &(ds->huf_tree);
	uint16_t *freq = hs->freq;
	uint16_t *code = hs->code;
	uint16_t *sortptr = hs->code;
	uint8_t *blen = hs->blen;
	int16_t *heap;
	int i, j, k, nn, avail;
	int heapsize, total_bits;

	heap = tp->heap;
	avail = nn = hs->size;
	heapsize = 0;
	heap[1] = 0;

	for (i = 0; i < nn; i++) {
		if (freq[i])
			heap[++heapsize] = i;
	}
	if (heapsize < 2) {
		code[heap[1]] = 0;
		blen[heap[1]] = heapsize;
		hs->total_bits = heapsize * freq[heap[1]];
		return (heap[1]);
	}

	/* make priority queue */
	for (i = heapsize >> 1; i >= 1; i--)
		lzx_downheap(tp, hs, i, heapsize);
	do {  /* while queue has at least two entries */
		i = heap[1];  /* take out least-freq entry */
		if (i < nn)
			*sortptr++ = i;
		heap[1] = heap[heapsize--];
		lzx_downheap(tp, hs, 1, heapsize);
		j = heap[1];  /* next least-freq entry */
		if (j < nn)
			*sortptr++ = j;
		k = avail++;  /* generate new node */
		freq[k] = freq[i] + freq[j];
		heap[1] = k;
		lzx_downheap(tp, hs, 1, heapsize);  /* put into queue */
		tp->left[k] = i;
		tp->right[k] = j;
	} while (heapsize > 1);
	lzx_make_bitlen(k, tp, hs);
	lzx_make_code(tp, hs);

	total_bits = 0;
	for (i = 0; i < nn; i++) {
		if (freq[i])
			total_bits += blen[i] * freq[i];
	}
	hs->total_bits = total_bits;
	return (k);  /* return root */
}

