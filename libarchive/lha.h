/*-
 * Copyright (c) 2008,2009 NAKAJIMA Michihiro
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


#ifndef LIBLHA_H
#define LIBLHA_H

struct lha_stream {
	const unsigned char	*next_in;  /* input buffer. 		   */
	ssize_t			 avail_in; /* available bytes.		   */
	ssize_t			 total_in; /* total number of input bytes  */
	unsigned char		*next_out; /* output buffer.		   */
	ssize_t			 avail_out;/* remaining free space.	   */
	ssize_t			 total_out;/* total number of output bytes */
	void			*private;  /* private object		   */
};

#define LHA_NO_FINISH		0
#define LHA_FINISH		4

#define LHA_OK			0
#define LHA_STREAM_END		1

#define LHA_ERRNO		(-1)
#define LHA_STREAM_ERROR	(-2)
#define LHA_DATA_ERROR		(-3)
#define LHA_MEM_ERROR		(-4)
#define LHA_BUF_ERROR		(-5)

/*
 * This couple of methods are to use for the LHA archive header.
 * DO NOT USE __lha_decodeInit/__lha_encodeInit functions!
 */
#define LHA_METHOD_LH0		10000	/* No compression 		*/
#define LHA_METHOD_LHd		10010	/* LHA archive to indicate the
					 * compressed object is an empty
					 * directory.
					 */
/*
 * Compression methods
 */
#define LHA_METHOD_LZS		1000
#define LHA_METHOD_LZ5		1005
#define LHA_METHOD_LH1		3001
#define LHA_METHOD_LH2		3002
#define LHA_METHOD_LH3		3003
#define LHA_METHOD_LH4		3004
#define LHA_METHOD_LH5		3005	/* Default compression		*/
#define LHA_METHOD_LH6		3006
#define LHA_METHOD_LH7		3007

int	__lha_decodeInit(struct lha_stream *strm, int method, size_t orgsize);
int	__lha_decodeReset(struct lha_stream *strm, size_t orgsize);
int	__lha_decode(struct lha_stream *strm, int flush);
int	__lha_decodeEnd(struct lha_stream *strm);
int	__lha_encodeInit(struct lha_stream *strm, int method);
int	__lha_encode(struct lha_stream *strm, int flush);
int 	__lha_encodeEnd(struct lha_stream *strm);
int	__lha_encodeReset(struct lha_stream *strm);
uint16_t __lha_crc16(uint16_t crc, const void *pp, size_t len);


#endif /* LIBLHA_H */
