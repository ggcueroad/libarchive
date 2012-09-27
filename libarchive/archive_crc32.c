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

#ifdef HAVE_ZLIB_H
#include <zlib.h>
#endif

#include "archive.h"
#include "archive_crc32.h"

#ifdef HAVE_ZLIB_H
/*
 * We use the crc32 function zlib provides if zlib is available.
 */
unsigned long
__archive_crc32(unsigned long crc, const void *_p, size_t len)
{
	return crc32(crc, _p, (uInt)len);
}

#else /* HAVE_ZLIB_H */

/*
 * When zlib is unavailable, we should still be able to validate
 * uncompressed zip archives.  That requires us to be able to compute
 * the CRC32 check value.  This is a drop-in compatible replacement
 * for crc32() from zlib.
 * This uses Slicing-By-8 algorithm and is based on public domain
 * code http://www.strchr.com/media/cksum.c.
 * Benchmarking CRC32 is available at http://www.strchr.com/crc32_popcnt
 */
static uint32_t crc_tbl[8][256];

static void
crc32_init()
{
	uint32_t crc2, b, i;

	for (b = 0; b < 256; ++b) {
		crc2 = b;
		for (i = 8; i > 0; --i) {
			if (crc2 & 1)
				crc2 = (crc2 >> 1) ^ 0xedb88320UL;
			else
				crc2 = (crc2 >> 1);
		}
		crc_tbl[0][b] = crc2;
	}
	for (b = 0; b < 256; ++b) {
		crc2 = crc_tbl[0][b];
		crc2 = (crc2 >> 8) ^ crc_tbl[0][crc2 & 0xff];
		crc_tbl[1][b] = crc2;
		crc2 = (crc2 >> 8) ^ crc_tbl[0][crc2 & 0xff];
		crc_tbl[2][b] = crc2;
		crc2 = (crc2 >> 8) ^ crc_tbl[0][crc2 & 0xff];
		crc_tbl[3][b] = crc2;
		crc2 = (crc2 >> 8) ^ crc_tbl[0][crc2 & 0xff];
		crc_tbl[4][b] = crc2;
		crc2 = (crc2 >> 8) ^ crc_tbl[0][crc2 & 0xff];
		crc_tbl[5][b] = crc2;
		crc2 = (crc2 >> 8) ^ crc_tbl[0][crc2 & 0xff];
		crc_tbl[6][b] = crc2;
		crc2 = (crc2 >> 8) ^ crc_tbl[0][crc2 & 0xff];
		crc_tbl[7][b] = crc2;
	}
}

#if !defined(ARCHIVE_BIG_ENDIAN)
/*
 * CRC32 calculation for little endian machine.
 */
static unsigned long
__archive_crc32_le(unsigned long crc, const void *_p, size_t len)
{
	const unsigned char *p = _p;
	static volatile int crc_tbl_inited = 0;
	size_t i;

	if (!crc_tbl_inited) {
		crc32_init();
		crc_tbl_inited = 1;
	}

	crc = crc ^ 0xffffffffUL;
	/* Compute crc32 to the first 4 bytes boundary. */
	for (;(((uintptr_t)p) & (sizeof(uint32_t) -1)) != 0 && len; --len)
		crc = crc_tbl[0][(crc ^ *p++) & 0xff] ^ (crc >> 8);

	for (i = 0; i < (len & ~15); i += 16) {
		uint32_t crc2;

		crc ^= *(const uint32_t *)(p + i);
		crc2 = *(const uint32_t *)(p + i + 4);
		crc = crc_tbl[7][ crc & 0x000000ff] ^
		      crc_tbl[6][(crc & 0x0000ff00) >> 8] ^
		      crc_tbl[5][(crc & 0x00ff0000) >> 16] ^
		      crc_tbl[4][(crc & 0xff000000) >> 24] ^
		      crc_tbl[3][ crc2 & 0x000000ff] ^
		      crc_tbl[2][(crc2 & 0x0000ff00) >> 8] ^
		      crc_tbl[1][(crc2 & 0x00ff0000) >> 16] ^
		      crc_tbl[0][(crc2 & 0xff000000) >> 24] ^
		      *(const uint32_t *)(p + i + 8);
		crc2 = *(const uint32_t *)(p + i + 12);
		crc = crc_tbl[7][ crc & 0x000000ff] ^
		      crc_tbl[6][(crc & 0x0000ff00) >> 8] ^
		      crc_tbl[5][(crc & 0x00ff0000) >> 16] ^
		      crc_tbl[4][(crc & 0xff000000) >> 24] ^
		      crc_tbl[3][ crc2 & 0x000000ff] ^
		      crc_tbl[2][(crc2 & 0x0000ff00) >> 8] ^
		      crc_tbl[1][(crc2 & 0x00ff0000) >> 16] ^
		      crc_tbl[0][(crc2 & 0xff000000) >> 24];
	}

	for (; i < len; i++)
		crc = crc_tbl[0][(crc ^ p[i]) & 0xff] ^ (crc >> 8);
	return (crc ^ 0xffffffffUL);
}
#endif /* !ARCHIVE_BIG_ENDIAN */

#if !defined(ARCHIVE_LITTLE_ENDIAN)
/*
 * CRC32 calculation for big endian machine.
 */
static unsigned long
__archive_crc32_be(unsigned long crc, const void *_p, size_t len)
{
	const uint8_t *p = _p;
	static volatile int crc_tbl_inited = 0;
	unsigned i;

	if (!crc_tbl_inited) {
		int b, i;

		crc32_init();
		for (i = 0; i < 8; i++) {
			for (b = 0; b < 256; ++b) {
				uint32_t crc2 = crc_tbl[i][b];
				crc_tbl[i][b] = ((crc2 & 0x000000ff) << 24) |
						((crc2 & 0x0000ff00) <<  8) |
						((crc2 & 0x00ff0000) >>  8) |
						((crc2 & 0xff000000) >> 24);
			}
		}
		crc_tbl_inited = 1;
	}

	crc = (((crc & 0x000000ff) << 24) |
	       ((crc & 0x0000ff00) <<  8) |
	       ((crc & 0x00ff0000) >>  8) |
	       ((crc & 0xff000000) >> 24)) ^ 0xffffffffUL;

	/* Compute crc32 to the first 4 bytes boundary. */
	for (;(((uintptr_t)p) & (sizeof(uint32_t) -1)) != 0 && len; --len)
		crc = crc_tbl[0][((crc >> 24) ^ *p++) & 0xff] ^ (crc << 8);

	for (i = 0; i < (len & ~15); i += 16) {
		uint32_t crc2;

		crc ^= *(const uint32_t *)(p + i);
		crc2 = *(const uint32_t *)(p + i + 4);
		crc = crc_tbl[4][ crc & 0x000000ff] ^
		      crc_tbl[5][(crc & 0x0000ff00) >> 8] ^
		      crc_tbl[6][(crc & 0x00ff0000) >> 16] ^
		      crc_tbl[7][(crc & 0xff000000) >> 24] ^
		      crc_tbl[0][ crc2 & 0x000000ff] ^
		      crc_tbl[1][(crc2 & 0x0000ff00) >> 8] ^
		      crc_tbl[2][(crc2 & 0x00ff0000) >> 16] ^
		      crc_tbl[3][(crc2 & 0xff000000) >> 24] ^
		      *(const uint32_t *)(p + i + 8);
		crc2 = *(const uint32_t *)(p + i + 12);
		crc = crc_tbl[4][ crc & 0x000000ff] ^
		      crc_tbl[5][(crc & 0x0000ff00) >> 8] ^
		      crc_tbl[6][(crc & 0x00ff0000) >> 16] ^
		      crc_tbl[7][(crc & 0xff000000) >> 24] ^
		      crc_tbl[0][ crc2 & 0x000000ff] ^
		      crc_tbl[1][(crc2 & 0x0000ff00) >> 8] ^
		      crc_tbl[2][(crc2 & 0x00ff0000) >> 16] ^
		      crc_tbl[3][(crc2 & 0xff000000) >> 24];
	}
	for (; i < len; i++)
		crc = crc_tbl[0][((crc >> 24) ^ p[i]) & 0xff] ^ (crc << 8);
	return (((crc & 0x000000ff) << 24) |
	        ((crc & 0x0000ff00) <<  8) |
	        ((crc & 0x00ff0000) >>  8) |
	        ((crc & 0xff000000) >> 24)) ^ 0xffffffffUL;
}
#endif /* !ARCHIVE_LITTLE_ENDIAN */

unsigned long
__archive_crc32(unsigned long crc, const void *_p, size_t len)
{
#if defined(ARCHIVE_LITTLE_ENDIAN)
	return __archive_crc32_le(crc, _p, len);
#elif defined(ARCHIVE_BIG_ENDIAN)
	return __archive_crc32_be(crc, _p, len);
#else
	/*
	 * When endianness is unknown in compile time, check which
	 *  endian the program is running on.
	 */
	static const int crc32_endianness = 0x12345678;
	const char *p = (const char *)&crc32_endianness;
	if (*p == 0x12)
		return __archive_crc32_be(crc, _p, len);
	else
		return __archive_crc32_le(crc, _p, len);
#endif
}

#endif /* HAVE_ZLIB_H */
