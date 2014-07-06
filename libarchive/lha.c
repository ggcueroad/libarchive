/*-
 * Copyright (c) 2008,2009 Michihiro NAKAJIMA
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
/*
 * This file is based on the ar002 written by Haruhiko Okumura.
 */

#include "archive_platform.h"

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
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
        
#include "lha.h"

struct decode_state {
	int			 method;	/* type of compression	    */
	int     		 state;		/* status of decode	    */
	unsigned char		*buffer;	/* decode buffer	    */
	int			 pos;
	int     		 match_len;
	int     		 match_pos;
	int			 adjust;

	unsigned char		 rcache[0x40000];/* read cache for UI	    */
	size_t			 rpos;		/* data read position	    */
	size_t			 spos;		/* data store position	    */
	size_t			 ravail;

	int			 dicbit;
	int			 dicsize;
	int			 dicmask;
	uint32_t		 decode_bytes;

	int			 err;
	char			*errmsg;
	size_t			 remain;	/* orignal file size	    */

	/* Bit reader */
	uint16_t		 bitbuf; 	/* buffer of bit-reader	    */
	uint16_t		 subbitbuf;	/* sub-buffer of bit-reader */
	int			 bitcount;	/* bit counter		    */

	/* Decode functions */
	int			 (*init)(struct decode_state *ds, int reset);
	void 			 (*prepare)(struct lha_stream *strm);
	int			 (*get_c)(struct lha_stream *strm);
	int			 (*get_p)(struct lha_stream *strm);
	int			 (*free)(struct decode_state *ds);
};

static void		lha_decode_register(struct decode_state *ds, 
			    int (*init)(struct decode_state *ds, int reset),
			    void (*prepare)(struct lha_stream *strm),
			    int (*get_c)(struct lha_stream *strm),
			    int (*get_p)(struct lha_stream *strm),
			    int (*free)(struct decode_state *ds));

#define BITBUFSIZ	((int)(CHAR_BIT * sizeof(uint16_t)))
static int		lha_br_getbyte(struct lha_stream *strm);
static void		lha_br_init(struct lha_stream *strm);
static void		lha_br_fillbuf(int n, struct lha_stream *strm);
static inline uint16_t	lha_br_peekbits(int n, struct lha_stream *strm);
static inline uint16_t	lha_br_peekbitfull(struct lha_stream *strm);
static uint16_t		lha_br_getbits(int n, struct lha_stream *strm);

static int		lha_lzs_decode_new(struct decode_state **ds);
static int		lha_lz5_decode_new(struct decode_state **ds);
static int		lha_lh1_decode_new(struct decode_state **ds);
static int		lha_lh2_decode_new(struct decode_state **ds);
static int		lha_lh3_decode_new(struct decode_state **ds);
static int		lha_lh4_decode_new(struct decode_state **ds);
static int		lha_lh5_decode_new(struct decode_state **ds);
static int		lha_lh6_decode_new(struct decode_state **ds);
static int		lha_lh7_decode_new(struct decode_state **ds);
static void		lha_stream_init(struct lha_stream *strm);
static int		lha_getdicbit(int method);


#define MAXMATCH 256    /* formerly F (not more than UCHAR_MAX + 1) */
#define THRESHOLD  3    /* choose optimal value */

#define NC (UCHAR_MAX + MAXMATCH + 2 - THRESHOLD)
				/* alphabet = {0, 1, 2, ..., NC - 1} 	    */
#define CBIT 		9	/* $\lfloor \log_2 NC \rfloor + 1$ 	    */
#define CODE_BIT  	16	/* codeword length */
#define TBIT 		5	/* smallest integer such
				 * that (1U << TBIT) > NT
				 */
#define NPT		0x80
#define C_TABLE_SIZE	4096
#define PT_TABLE_SIZE	256

struct huf_work {
	uint16_t	left[2 * NC -1];
	uint16_t	right[2 * NC -1];
};

struct huf_val {
	int		NP;
	int		NT;
	int		PBIT;
};

static void		lha_huf_init_work(struct huf_work *hw);
static void		lha_huf_init_val(struct huf_val *val, int dicbit);
static int		lha_make_table(int nchar, unsigned char bitlen[],
			    int tablebits, uint16_t table[],
			    struct huf_work *hw);
static void		lha_huf_ready_made(int type, int np,
			    unsigned char *pt_len, uint16_t *pt_code);
static int		lha_huf_next_c(int bits, int np,
			    unsigned char *pt_len, uint16_t *pt_table,
			    struct huf_work *hw, struct lha_stream *strm);
static int		lha_make_tree(int nparm, uint16_t freqparm[],
			    unsigned char lenparm[], uint16_t codeparm[],
			    struct huf_work *hw);

static int
lha_decode_init_state(struct decode_state *ds, int method, int reset)
{
	ds->method = method;
	ds->dicbit = lha_getdicbit(method);
	ds->dicsize = 1U << ds->dicbit;
	ds->dicmask = ds->dicsize -1;
	ds->state = 0;
	if (!reset) {
		ds->buffer = malloc(ds->dicsize * sizeof(*ds->buffer));
		if (ds->buffer == NULL)
			return (LHA_ERRNO);
	}
	memset(ds->buffer, ' ', ds->dicsize * sizeof(*ds->buffer));
	ds->match_len = 0;
	ds->match_pos = 0;
	ds->adjust = UCHAR_MAX + 1 - THRESHOLD;
        ds->ravail = 0;
        ds->rpos = 0;
        ds->spos = 0;
        ds->err = 0;
        ds->errmsg = NULL;
	ds->remain = 0;

	return (LHA_OK);
}

static int
lha_decode_free_state(struct decode_state *ds)
{
	free(ds->buffer);

	return (LHA_OK);
}

static void
lha_decode_register(struct decode_state *ds, 
    int (*init)(struct decode_state *ds, int reset),
    void (*prepare)(struct lha_stream *strm),
    int (*get_c)(struct lha_stream *strm),
    int (*get_p)(struct lha_stream *strm),
    int (*free)(struct decode_state *ds))
{

	ds->init = init;
	ds->prepare = prepare;
	ds->get_c = get_c;
	ds->get_p = get_p;
	ds->free = free;
}

int
__lha_decodeInit(struct lha_stream *strm, int method, size_t orgsize)
{
	struct decode_state *ds;
	int ret;

	lha_stream_init(strm);

	ds = strm->private = NULL;
	switch (method) {
	case LHA_METHOD_LZS:
		ret = lha_lzs_decode_new(&ds);
		break;
	case LHA_METHOD_LZ5:
		ret = lha_lz5_decode_new(&ds);
		break;
	case LHA_METHOD_LH1:
		ret = lha_lh1_decode_new(&ds);
		break;
	case LHA_METHOD_LH2:
		ret = lha_lh2_decode_new(&ds);
		break;
	case LHA_METHOD_LH3:
		ret = lha_lh3_decode_new(&ds);
		break;
	case LHA_METHOD_LH4:
		ret = lha_lh4_decode_new(&ds);
		break;
	case LHA_METHOD_LH5:
		ret = lha_lh5_decode_new(&ds);
		break;
	case LHA_METHOD_LH6:
		ret = lha_lh6_decode_new(&ds);
		break;
	case LHA_METHOD_LH7:
		ret = lha_lh7_decode_new(&ds);
		break;
	default:
		ret = LHA_ERRNO;
		break;
	}
	if (ret != LHA_OK)
		return (ret);

	ret = lha_decode_init_state(ds, method, 0);
	if (ret != LHA_OK) {
		free(ds);
		return (ret);
	}
	if (ds->init != NULL) {
		ret = ds->init(ds, 0);
		if (ret != LHA_OK) {
			free(ds);
			return (ret);
		}
	}

	strm->private = ds;
	ds->remain = orgsize;

	return (LHA_OK);
}

int
__lha_decodeEnd(struct lha_stream *strm)
{
	struct decode_state *ds;

	if (strm->private != NULL) {
		ds = (struct decode_state *)strm->private;
		lha_decode_free_state(ds);
		if (ds->free != NULL)
			ds->free(ds);
		free(ds);

		strm->private = NULL;
	}

	return (LHA_OK);
}

int
__lha_decodeReset(struct lha_stream *strm, size_t orgsize)
{
	struct decode_state *ds;
	int ret;

	lha_stream_init(strm);
	if (strm->private == NULL)
		return (LHA_ERRNO);
	ds = (struct decode_state *)strm->private;
	ret = lha_decode_init_state(ds, ds->method, 1);
	if (ret != LHA_OK)
		return (ret);
	ds->remain = orgsize;
	if (ds->init != NULL)
		ret = ds->init(ds, 1);

	return (ret);
}

static void
lha_copy_in(struct lha_stream *strm)
{
	struct decode_state *ds;
	int len, xlen;

	ds = (struct decode_state *)strm->private;
	len = sizeof(ds->rcache) - ds->ravail;
	if (len > strm->avail_in)
		len = strm->avail_in;
	if ((sizeof(ds->rcache) - ds->spos) < len) {
		xlen = sizeof(ds->rcache) - ds->spos;
		memcpy(&ds->rcache[ds->spos], strm->next_in, xlen);
		strm->next_in += xlen;
		strm->total_in += xlen;
		ds->ravail += xlen;
		ds->spos = 0;
		len -= xlen;
	}
	memcpy(&ds->rcache[ds->spos], strm->next_in, len);
	strm->next_in += len;
	strm->avail_in -= len;
	strm->total_in += len;
	ds->ravail += len;
	ds->spos += len;
	if (ds->spos >= sizeof(ds->rcache))
		ds->spos = 0;
}

int
__lha_decode(struct lha_stream *strm, int finish)
{
	struct decode_state *ds;
	uint code;

	ds = (struct decode_state *)strm->private;
	if (ds->state == -1) {
		if (finish == LHA_FINISH)
			return (LHA_STREAM_END);
		else
			return (LHA_OK);
	}

	if (strm->next_out == NULL || strm->avail_out == 0)
		return (LHA_BUF_ERROR);

	if (ds->ravail < sizeof(ds->rcache) && strm->avail_in > 0)
		lha_copy_in(strm);

	ds->err = LHA_OK;
	for (;;) {
		if (finish != LHA_FINISH && strm->avail_in == 0
		    && ds->ravail < sizeof(ds->rcache)/4)
			return (LHA_OK);
		if (ds->remain <= 0) {
			if (finish == LHA_FINISH)
				return (LHA_STREAM_END);
			else
				return (LHA_OK);
		}

		switch (ds->state) {
		case 0:
			ds->prepare(strm);
			ds->pos = 0;
			ds->state = 1;
			ds->decode_bytes = 0;
			break;

		case 1:
			code = ds->get_c(strm);
			if (ds->err != LHA_OK)
				return (ds->err);
			if (code == (uint)-1) {
				ds->state = -1;
				if (finish == LHA_FINISH)
					return (LHA_STREAM_END);
				else
					return (LHA_OK);
			}
			if (code <= UCHAR_MAX) {
				ds->decode_bytes++;
				ds->buffer[ds->pos++] = code;
				*strm->next_out++ = code;
				strm->avail_out--;
				strm->total_out++;
				ds->remain--;
				if (ds->pos >= ds->dicsize)
					ds->pos = 0;
				if (strm->avail_out <= 0)
					return (LHA_OK);
			} else {
				ds->match_len = code - ds->adjust;
				ds->match_pos =
				    (ds->pos - ds->get_p(strm) - 1) &
				    ds->dicmask;
				if (ds->match_len > 0)
					ds->state = 2;
			}
			break;

		case 2:
			if (--ds->match_len >= 0) {
				code = ds->buffer[ds->match_pos];
				ds->decode_bytes++;
				ds->match_pos =
				    (ds->match_pos + 1) & ds->dicmask;
				ds->buffer[ds->pos++] = code;
				*strm->next_out++ = code;
				strm->avail_out--;
				strm->total_out++;
				ds->remain--;
				if (ds->pos >= ds->dicsize)
					ds->pos = 0;
				if (strm->avail_out <= 0)
					return (LHA_OK);
			} else
				ds->state = 1;
			break;
		}
	}
}


static int
lha_br_getbyte(struct lha_stream *strm)
{
	struct decode_state *ds = (struct decode_state *)strm->private;
	int ret;

	if (ds->ravail > 0) {
		ret = ds->rcache[ds->rpos++];
		if (ds->rpos >= sizeof(ds->rcache))
			ds->rpos = 0;
		ds->ravail--;
		if (ds->ravail == 0 && strm->avail_in > 0)
			lha_copy_in(strm);
	} else
		ret = -1;

	return (ret);
}

static void
lha_br_init(struct lha_stream *strm)
{
	struct decode_state *ds = (struct decode_state *)strm->private;

	ds->bitbuf = 0;
	ds->subbitbuf = 0;
	ds->bitcount = 0;
	lha_br_fillbuf(BITBUFSIZ, strm);
}

/* Shift bitbuf n bits left, read n bits */
static void
lha_br_fillbuf(int n, struct lha_stream *strm)
{
	struct decode_state *ds = (struct decode_state *)strm->private;
	int r;

	ds->bitbuf <<= n;
	while (n > ds->bitcount) {
		ds->bitbuf |= ds->subbitbuf << (n -= ds->bitcount);
		r = lha_br_getbyte(strm);
		if (r < 0)
			ds->subbitbuf = 0;
		else
			ds->subbitbuf = (uint16_t)r;

		ds->bitcount = CHAR_BIT;
	}
	ds->bitbuf |= ds->subbitbuf >> (ds->bitcount -= n);
}

static inline uint16_t
lha_br_peekbits(int n, struct lha_stream *strm)
{
	struct decode_state *ds = (struct decode_state *)strm->private;

	return ((uint16_t)(ds->bitbuf >> (BITBUFSIZ - n)));
}

static inline uint16_t
lha_br_peekbitfull(struct lha_stream *strm)
{
	struct decode_state *ds = (struct decode_state *)strm->private;

	return (ds->bitbuf);
}

static uint16_t
lha_br_getbits(int n, struct lha_stream *strm)
{
	struct decode_state *ds = (struct decode_state *)strm->private;
	uint16_t x;

	if (n == 0)
		return (0);

	x = ds->bitbuf >> (BITBUFSIZ - n);
	lha_br_fillbuf(n, strm);

	return (x);
}

static int
lha_huf_next_c(int bits, int np, unsigned char *pt_len, uint16_t *pt_table,
	struct huf_work *hw, struct lha_stream *strm)
{
	uint16_t si;
	uint16_t data, mask;

	si = pt_table[lha_br_peekbits(bits, strm)];
	if (si >= np) {
		data = lha_br_peekbitfull(strm);
		mask = 1U << (BITBUFSIZ - 1 - bits);
		do {
			if (data & mask)
				si = hw->right[si];
			else
				si = hw->left[si];
			mask >>= 1;
		} while (si >= np && (mask || si != hw->left[si]));
					/* CVE-2006-4338	*/
	}
	lha_br_fillbuf(pt_len[si], strm);

	return si;
}


static void
lha_huf_init_work(struct huf_work *hw)
{
	memset(hw->left, 0, sizeof(hw->left));
	memset(hw->right, 0, sizeof(hw->right));
}

static void
lha_huf_init_val(struct huf_val *val, int dicbit)
{
	val->NP = dicbit + 1;
	val->NT = CODE_BIT + 3;
	if (dicbit == 15 || dicbit == 16)
		val->PBIT = 5;
	else
		val->PBIT = 4;
}

static void
lha_huf_ready_made(int type, int np, unsigned char *pt_len,
    uint16_t *pt_code)
{
	static const char fixed0[] = { 3, 1, 4, 12, 24, 48, 0 };
	static const char fixed1[] = { 2, 1, 1, 3, 6, 13, 31, 78, 0 };
	const char *fixed;
	int i, dd, aa;
	char c;

	if (type == 0)
		fixed = fixed0;
	else
		fixed = fixed1;
	c = *fixed++;
	dd = 1 << (16 - c);
	i = 0;
	aa = 0;
	do {
		while (*fixed == i) {
			c++;
			fixed++;
			dd >>= 1;
		}
		pt_len[i] = c;
		pt_code[i] = aa;
		aa += dd;
	} while (++i < np);
}

#define N_CHAR		(256 + 60 - THRESHOLD + 1)
#define TREESIZE_C	(N_CHAR * 2)
#define TREESIZE_P	256
#define TREESIZE	(TREESIZE_C + TREESIZE_P)
#define ROOT_C		0
#define ROOT_P		TREESIZE_C
#define NP1		64
struct dhufdecode_state {
	struct decode_state	ds;
	struct huf_work 	hw;

	/* for -lh1- and -lh2- */
	int			avail;
	int			n1;
	int			n_max;
	int16_t			block[TREESIZE_C + TREESIZE_P];
	int16_t			stock[TREESIZE_C + TREESIZE_P];
	int16_t			edge[TREESIZE_C + 256];
	int16_t			node[N_CHAR + 128];
	uint16_t		freq[2 * NC -1];
	int16_t			child[2 * NC -1];
	int16_t			parent[2 * NC -1];
	/* for -lh2- only	*/
	uint16_t		total_p;
	uint16_t		most_p;
	int			nn;
	uint32_t		nextcount;
	/* for -lh1- only */
	unsigned char		pt_len[NPT];
	uint16_t		pt_table[PT_TABLE_SIZE];
};

static void	lh1_decode_prepare(struct lha_stream *strm);
static void	lh2_decode_prepare(struct lha_stream *strm);
static int	dym_decode_c(struct lha_stream *strm);
static void	dym_huf_init(struct dhufdecode_state *huf, int n_max,
		    int maxmatch);
static void	dym_huf_reconst(struct dhufdecode_state *huf, int start,
		    int end);
static uint16_t dym_huf_swap_inc(struct dhufdecode_state *huf, int p);
static int	lh2_decode_p(struct lha_stream *strm);
static int	lh1_decode_p(struct lha_stream *strm);

static int
lha_lh1_decode_new(struct decode_state **ds)
{

	*ds = malloc(sizeof(struct dhufdecode_state));
	if (*ds == NULL)
		return (LHA_ERRNO);
	lha_decode_register(*ds, NULL, lh1_decode_prepare,
	    dym_decode_c, lh1_decode_p, NULL);

	return (LHA_OK);
}

static int
lha_lh2_decode_new(struct decode_state **ds)
{

	*ds = malloc(sizeof(struct dhufdecode_state));
	if (*ds == NULL)
		return (LHA_ERRNO);
	lha_decode_register(*ds, NULL, lh2_decode_prepare,
	    dym_decode_c, lh2_decode_p, NULL);

	return (LHA_OK);
}

static void
dym_update_c(struct dhufdecode_state *huf, uint16_t p)
{
	uint16_t bi;

	if (huf->freq[ROOT_C] == 0x8000)
		dym_huf_reconst(huf, 0,  (huf->n_max << 1) - 1);

	huf->freq[ROOT_C]++;
	bi = huf->node[p];
	do {
		bi = dym_huf_swap_inc(huf, bi);
	} while (bi != ROOT_C);
}

static int
dym_decode_c(struct lha_stream *strm)
{
	struct dhufdecode_state *huf;
	int16_t si, bb;
	int16_t cc;

	huf = (struct dhufdecode_state *)strm->private;
	si = huf->child[ROOT_C];
	cc = 16;
	bb = lha_br_peekbitfull(strm);
	do {
		if (--cc < 0) {
			lha_br_fillbuf(16, strm);
			bb = lha_br_peekbitfull(strm);
			cc = 15;
		}
		if (bb < 0)
			si = huf->child[si - 1];
		else
			si = huf->child[si];
		bb <<= 1;
	} while (si > 0);
	lha_br_fillbuf(16 - cc, strm);
	si = ~si;
	dym_update_c(huf, si);
	if (si == huf->n1)
		si += lha_br_getbits(8, strm);

	return si;
}

static void
lh2_update_p(struct dhufdecode_state *huf, uint16_t p)
{
	uint16_t bi;

	if (huf->total_p == 0x8000) {
		dym_huf_reconst(huf, ROOT_P, huf->most_p + 1);
		huf->total_p = huf->freq[ROOT_P];
		huf->freq[ROOT_P] = 0xffff;
	}
	bi = huf->node[p + N_CHAR];
	while (bi != ROOT_P)
		bi = dym_huf_swap_inc(huf, bi);
	huf->total_p++;
}

static void
lh2_make_new_node(struct dhufdecode_state *huf, uint16_t p)
{
	uint16_t di, bi;

	di = huf->most_p;
	bi = huf->child[di + 1] = huf->child[di];
	bi = ~bi;
	huf->node[bi] = di + 1;
	huf->child[di + 2] = ~(p + N_CHAR);
	huf->child[di] = di + 2;
	huf->freq[di + 1] = huf->freq[di];
	huf->freq[di + 2] = 0;
	huf->block[di + 1] = huf->block[di];
	if (di == ROOT_P) {
		huf->freq[ROOT_P] = 0xffff;
		huf->edge[huf->block[ROOT_P]]++;
	}
	huf->parent[di + 1] = huf->parent[di + 2] = di;
	di += 2;
	huf->most_p = di;
	huf->node[p + N_CHAR] = di;
	bi = huf->avail++;
	bi = huf->block[di] = huf->stock[bi];
	huf->edge[bi] = di;
	lh2_update_p(huf, p);
}

static int
lh2_decode_p(struct lha_stream *strm)
{
	struct dhufdecode_state *huf;
	int16_t si, bb;
	int16_t cc;

	huf = (struct dhufdecode_state *)strm->private;
	while (huf->ds.decode_bytes > huf->nextcount) {
		lh2_make_new_node(huf, (uint16_t)(huf->nextcount >> 6));
		if ((huf->nextcount += 64) >= huf->nn)
			huf->nextcount = ~0UL;
	}
	si = huf->child[ROOT_P];
	cc = 16;
	bb = lha_br_peekbitfull(strm);
	while (si > 0) {
		if (--cc < 0) {
			lha_br_fillbuf(16, strm);
			bb = lha_br_peekbitfull(strm);
			cc = 15;
		}
		if (bb < 0)
			si = huf->child[si - 1];
		else
			si = huf->child[si];
		bb <<= 1;
	}
	lha_br_fillbuf(16 - cc, strm);
	si = ~si - N_CHAR;
	lh2_update_p(huf, si);

	return (si << 6) + lha_br_getbits(6, strm);
}

static void
dym_huf_init(struct dhufdecode_state *huf, int n_max, int maxmatch)
{
	uint16_t si, di;
	int bi;

	huf->n_max = n_max;
	if (huf->n_max < (maxmatch + 256 - 2))
		huf->n1 = huf->n_max - 1;
	else
		huf->n1 = 512;

	memset(huf->block, 0, sizeof(huf->block[0]) * TREESIZE_C);
	for (di = 0; di < TREESIZE_C; di++)
		huf->stock[di] = di;

	huf->edge[1] = bi = huf->n_max -1;
	bi <<= 1;
	for (di = 0; di < huf->n_max; di++, bi--) {
		huf->freq[bi] = 1;
		huf->block[bi] = 1;
		huf->child[bi] = ~di;
		huf->node[di] = bi;
	}
	huf->avail = 2;
	for (di = (huf->n_max - 1) << 1; bi >= 0; bi--, di -= 2) {
		huf->freq[bi] = huf->freq[di] + huf->freq[di - 1];
		huf->child[bi] = di;
		huf->parent[di] = huf->parent[di - 1] = bi;
		if (huf->freq[bi] == huf->freq[bi + 1])
			si = huf->block[bi + 1];
		else
			si = huf->stock[huf->avail++];
		huf->block[bi] = si;
		huf->edge[si] = bi;
	}
}

static void
dym_huf_reconst(struct dhufdecode_state *huf, int start, int end)
{
	int si, di, bi, bj, xx;

	for (si = di = start; si < end; si++) {
		if (((int16_t)huf->child[si]) < 0) {
			huf->freq[di] = (huf->freq[si] + 1) >> 1;
			huf->child[di] = huf->child[si];
			di++;
		}
		if (huf->edge[huf->block[si]] == si) {
			huf->avail --;
			huf->stock[huf->avail] = huf->block[si];
		}
	}
	di--;
	si--;
	bi = si - 1;
	while (si >= start) {
		while (si >= bi) {
			huf->freq[si] = huf->freq[di];
			huf->child[si] = huf->child[di];
			di--;
			si--;
		}
		xx = huf->freq[bi] + huf->freq[bi + 1];
		bj = start;
		while (xx < huf->freq[bj])
			bj++;
		while (di >= bj) {
			huf->freq[si] = huf->freq[di];
			huf->child[si] = huf->child[di];
			di--;
			si--;
		}
		huf->freq[si] = xx;
		huf->child[si] = bi + 1;
		si--;
		bi -= 2;
	}

	xx = 0;
	for (si = start; si < end; si++) {
		di = huf->child[si];
		if (di < 0)
			huf->node[~di] = si;
		else
			huf->parent[di] = huf->parent[di - 1] = si;
		if (huf->freq[si] == xx)
			huf->block[si] = bi;
		else {
			bi = huf->stock[huf->avail++];
			huf->block[si] = bi;
			huf->edge[bi] = si;
			xx = huf->freq[si];
		}
	}

}

static uint16_t
dym_huf_swap_inc(struct dhufdecode_state *huf, int p)
{
	int si, di, bb;
	int sx, dx;

	si = p;
	bb = huf->block[si];
	di = huf->edge[bb];
	if (di != si) {
		sx = huf->child[si];
		dx = huf->child[di];
		huf->child[si] = dx;
		huf->child[di] = sx;
		if (sx >= 0)
			huf->parent[sx] = huf->parent[sx - 1] = di;
		else
			huf->node[~sx] = di;
		if (dx >= 0)
			huf->parent[dx] = huf->parent[dx - 1] = si;
		else
			huf->node[~dx] = si;
		si = di;
		goto Adjust;
	}
	if (bb == huf->block[si + 1]) {
Adjust:
		huf->edge[bb]++;
		huf->freq[si]++;
		if (huf->freq[si] == huf->freq[si -1])
			huf->block[si] = huf->block[si -1];
		else {
			bb = huf->avail++;
			bb = huf->stock[bb];
			huf->block[si] = bb;
			huf->edge[bb] = si;
		}
	} else  {
		huf->freq[si]++;
		if (huf->freq[si] == huf->freq[si -1]) {
			di = --huf->avail;
			huf->stock[di] = bb;
			huf->block[si] = huf->block[si -1];
		}
	}

	return huf->parent[si];
}

static int
lh1_decode_p(struct lha_stream *strm)
{
	struct dhufdecode_state *huf;
	int si;

	huf = (struct dhufdecode_state *)strm->private;
	si = lha_huf_next_c(8, NP1, huf->pt_len, huf->pt_table, &huf->hw, strm);

	return (si << 6) + lha_br_getbits(6, strm);
}

static void
lh1_decode_prepare(struct lha_stream *strm)
{
	struct dhufdecode_state *huf;

	huf = (struct dhufdecode_state *)strm->private;
	lha_br_init(strm);
	lha_huf_init_work(&huf->hw);
	dym_huf_init(huf, 314, 60);
	lha_huf_ready_made(0, NP1, huf->pt_len, huf->pt_table);
	lha_make_table(NP1, huf->pt_len, 8, huf->pt_table, &huf->hw);
}

static void
lh2_decode_prepare(struct lha_stream *strm)
{
	struct dhufdecode_state *huf;
	uint16_t bi;

	huf = (struct dhufdecode_state *)strm->private;
	lha_br_init(strm);
	lha_huf_init_work(&huf->hw);
	dym_huf_init(huf, 286, MAXMATCH);

	huf->freq[ROOT_P] = 1;
	huf->child[ROOT_P] = ~N_CHAR;
	huf->node[N_CHAR] = ROOT_P;
	bi = huf->stock[huf->avail++];
	huf->block[ROOT_P] = bi;
	huf->edge[bi] = ROOT_P;
	huf->most_p = ROOT_P;
	huf->nn = 1 << huf->ds.dicbit;
	huf->nextcount = 64L;
	huf->total_p = 0;
}

#define NP3	128
struct lh3decode_state {
	struct decode_state	ds;
	struct huf_work 	hw;

	int			blocksize;
	unsigned char		c_len[NC];
	uint16_t		c_table[C_TABLE_SIZE];
	unsigned char		pt_len[NPT];
	uint16_t		pt_table[PT_TABLE_SIZE];
};

static void	lh3_decode_prepare(struct lha_stream *strm);
static int	lh3_decode_c(struct lha_stream *strm);
static int	lh3_decode_p(struct lha_stream *strm);

static int
lha_lh3_decode_new(struct decode_state **ds)
{

	*ds = malloc(sizeof(struct lh3decode_state));
	if (*ds == NULL)
		return (LHA_ERRNO);

	lha_decode_register(*ds, NULL, lh3_decode_prepare, lh3_decode_c,
	    lh3_decode_p, NULL);

	return (LHA_OK);
}

static void
lh3_read_tree_c(struct lha_stream *strm)
{
	struct lh3decode_state *lh3;
	unsigned char *c_len;
	int i;
	uint16_t cc;

	lh3 = (struct lh3decode_state *)strm->private;
	c_len = lh3->c_len;
	for (i = 0; i < 3; i++) {
		if (lha_br_getbits(1, strm))
			c_len[i] = lha_br_getbits(4, strm) + 1;
		else
			c_len[i] = 0;
	}
	if (c_len[0] == 1 && c_len[1] == 1 && c_len[2] == 1) {
		memset(c_len, 0, 286);
		cc = lha_br_getbits(9, strm);
		for (i = 0; i < C_TABLE_SIZE; i++)
			lh3->c_table[i] = cc;
		return;
	}
	for (i = 3; i < 286; i++) {
		if (lha_br_getbits(1, strm))
			c_len[i] = lha_br_getbits(4, strm) + 1;
		else
			c_len[i] = 0;
	}
	lha_make_table(286, lh3->c_len, 12, lh3->c_table, &lh3->hw);
}

static void
lh3_read_tree_p(struct lha_stream *strm)
{
	struct lh3decode_state *lh3;
	unsigned char *pt_len;
	int i;
	uint16_t cc;

	lh3 = (struct lh3decode_state *)strm->private;
	pt_len = lh3->pt_len;
	for (i = 0; i < 3; i++)
		pt_len[i] = lha_br_getbits(4, strm);

	if (pt_len[0] == 1 && pt_len[1] == 1 && pt_len[2] == 1) {
		memset(pt_len, 0, 128);
		cc = lha_br_getbits(lh3->ds.dicbit - 6, strm);
		for (i = 0; i < PT_TABLE_SIZE; i++);
			lh3->pt_table[i] = cc;
		return;
	}
	for (i = 3; i < 128; i++)
		pt_len[i] = lha_br_getbits(4, strm);
}

static int
lh3_decode_c(struct lha_stream *strm)
{
	struct lh3decode_state *lh3;
	int si;

	lh3 = (struct lh3decode_state *)strm->private;
	if (lh3->blocksize == 0) {
		lh3->blocksize = lha_br_getbits(16, strm);
		lh3_read_tree_c(strm);
		if (lha_br_getbits(1, strm))
			lh3_read_tree_p(strm);
		else
			lha_huf_ready_made(1, NP3, lh3->pt_len, lh3->pt_table);
		lha_make_table(NP3, lh3->pt_len, 8, lh3->pt_table, &lh3->hw);
	}
	lh3->blocksize--;

	si = lha_huf_next_c(12, 286, lh3->c_len, lh3->c_table, &lh3->hw, strm);
	if (si == 285)
		si += lha_br_getbits(8, strm);

	return si;
}

static int
lh3_decode_p(struct lha_stream *strm)
{
	struct lh3decode_state *lh3;
	int si;

	lh3 = (struct lh3decode_state *)strm->private;
	si = lha_huf_next_c(8, NP3, lh3->pt_len, lh3->pt_table, &lh3->hw, strm);

	return (si << 6) + lha_br_getbits(6, strm);
}

static void
lh3_decode_prepare(struct lha_stream *strm)
{
	struct lh3decode_state *lh3;

	lh3 = (struct lh3decode_state *)strm->private;
	lha_br_init(strm);
	lha_huf_init_work(&lh3->hw);
	lh3->blocksize = 0;
	memset(lh3->c_len, 0, NC * sizeof(*lh3->c_len));
	memset(lh3->c_table, 0, C_TABLE_SIZE * sizeof(*lh3->c_table));
}


struct hufdecode_state {
	struct decode_state	ds;
	struct huf_work		hw;
	struct huf_val		val;

	int			blocksize;
	unsigned char		c_len[NC];
	uint16_t		c_table[C_TABLE_SIZE];
	unsigned char		pt_len[NPT];
	uint16_t		pt_table[PT_TABLE_SIZE];
};

static int	sta_huf_decode_new(struct decode_state **ds, int method);
static void	sta_huf_decode_prepare(struct lha_stream *strm);
static int	sta_huf_decode_c(struct lha_stream *strm);
static int	sta_huf_decode_p(struct lha_stream *strm);

static int
lha_lh4_decode_new(struct decode_state **ds)
{
	return sta_huf_decode_new(ds, LHA_METHOD_LH4);
}

static int
lha_lh5_decode_new(struct decode_state **ds)
{
	return sta_huf_decode_new(ds, LHA_METHOD_LH5);
}

static int
lha_lh6_decode_new(struct decode_state **ds)
{
	return sta_huf_decode_new(ds, LHA_METHOD_LH6);
}

static int
lha_lh7_decode_new(struct decode_state **ds)
{
	return sta_huf_decode_new(ds, LHA_METHOD_LH7);
}

static int
sta_huf_decode_new(struct decode_state **ds, int method)
{

	*ds = malloc(sizeof(struct hufdecode_state));
	if (*ds == NULL)
		return (LHA_ERRNO);

	lha_decode_register(*ds, NULL, sta_huf_decode_prepare,
	    sta_huf_decode_c, sta_huf_decode_p, NULL);

	return (LHA_OK);
}

static void
read_pt_len(int nn, int nbit, int i_special, struct lha_stream *strm)
{
	struct hufdecode_state *huf;
	int i, c, n, r;
	uint mask, data;

	huf = (struct hufdecode_state *)strm->private;
	n = lha_br_getbits(nbit, strm);
	if (n == 0) {
		c = lha_br_getbits(nbit, strm);
		memset(huf->pt_len, 0, sizeof(huf->pt_len[0]) * nn);
		memset(huf->pt_table, c,
		    sizeof(huf->pt_table[0]) * PT_TABLE_SIZE);
	} else {
		i = 0;
		while (i < n) {
			c = lha_br_peekbits(3, strm);
			if (c == 7) {
				mask = 1U << (BITBUFSIZ - 1 - 3);
				data = lha_br_peekbitfull(strm);
				while (mask & data) {
					mask >>= 1;
					c++;
				}
			}
			lha_br_fillbuf((c < 7) ? 3 : c - 3, strm);
			huf->pt_len[i++] = c;
			if (i == i_special) {
				c = lha_br_getbits(2, strm);
				while (--c >= 0)
					huf->pt_len[i++] = 0;
			}
		}
		if (i < nn)
			memset(&huf->pt_len[i], 0,
				sizeof(huf->pt_len[0]) * (nn - i));

		r = lha_make_table(nn, huf->pt_len, 8, huf->pt_table, &huf->hw);
		if (r < 0)
			huf->ds.err = r;
	}
}

static void
read_c_len(struct lha_stream *strm)
{
	struct hufdecode_state *huf;
	int i, c, n, r;

	huf = (struct hufdecode_state *)strm->private;
	n = lha_br_getbits(CBIT, strm);
	if (n == 0) {
		c = lha_br_getbits(CBIT, strm);
		memset(huf->c_len, 0, sizeof(huf->c_len[0]) * NC);
		memset(huf->c_table, c,
		    sizeof(huf->c_table[0]) * C_TABLE_SIZE);
	} else {
		i = 0;
		while (i < n) {
			c = lha_huf_next_c(8, huf->val.NT,
			    huf->pt_len, huf->pt_table, &huf->hw, strm);
			if (c <= 2) {
				if (c == 0)
					c = 1;
				else if (c == 1)
					c = lha_br_getbits(4, strm) + 3;
				else
					c = lha_br_getbits(CBIT, strm) + 20;
				while (--c >= 0)
					huf->c_len[i++] = 0;
			} else
				huf->c_len[i++] = c - 2;
		}
		if (i < NC)
			memset(&huf->c_len[i], 0,
			    sizeof(huf->c_len[0]) * (NC - i));
		r = lha_make_table(NC, huf->c_len, 12, huf->c_table, &huf->hw);
		if (r < 0)
			huf->ds.err = r;
	}
}

static int
sta_huf_decode_c(struct lha_stream *strm)
{
	struct hufdecode_state *huf;

	huf = (struct hufdecode_state *)strm->private;
	if (huf->blocksize == 0) {
		huf->blocksize = lha_br_getbits(16, strm);
		read_pt_len(huf->val.NT, TBIT, 3, strm);
		if (huf->ds.err != LHA_OK)
			return ((uint)-1);
		read_c_len(strm);
		if (huf->ds.err != LHA_OK)
			return ((uint)-1);
		read_pt_len(huf->val.NP, huf->val.PBIT, -1, strm);
		if (huf->ds.err != LHA_OK)
			return ((uint)-1);
	}
	huf->blocksize--;

	return (lha_huf_next_c(12, NC, huf->c_len, huf->c_table, &huf->hw,
	    strm));
}

static int
sta_huf_decode_p(struct lha_stream *strm)
{
	struct hufdecode_state *huf;
	int j;

	huf = (struct hufdecode_state *)strm->private;
	j = lha_huf_next_c(8, huf->val.NP, huf->pt_len, huf->pt_table,
	    &huf->hw, strm);
	if (j != 0)
		j = (1 << (j - 1)) + lha_br_getbits(j - 1, strm);

	return (j);
}

static void
sta_huf_decode_prepare(struct lha_stream *strm)
{
	struct hufdecode_state *huf;

	huf = (struct hufdecode_state *)strm->private;
	lha_br_init(strm);
	lha_huf_init_work(&huf->hw);
	lha_huf_init_val(&huf->val, huf->ds.dicbit);
	huf->blocksize = 0;
	memset(huf->c_len, 0, sizeof(huf->c_len));
	memset(huf->c_table, 0, sizeof(huf->c_table));
	memset(huf->pt_len, 0, sizeof(huf->pt_len));
	memset(huf->pt_table, 0, sizeof(huf->pt_table));
}


struct lz5decode_state {
	struct decode_state	ds;
	int			matchpos;
	int			flag;
	int			flagcnt;
};

static void	lz5_decode_prepare(struct lha_stream *strm);
static int	lz5_decode_c(struct lha_stream *strm);
static int	lz5_decode_p(struct lha_stream *strm);

static int
lha_lz5_decode_new(struct decode_state **ds)
{

	*ds = malloc(sizeof(struct lz5decode_state));
	if (*ds == NULL)
		return (LHA_MEM_ERROR);

	lha_decode_register(*ds, NULL, lz5_decode_prepare,
	    lz5_decode_c, lz5_decode_p, NULL);

	return (LHA_OK);
}

static int
lz5_decode_c(struct lha_stream *strm)
{
	struct lz5decode_state *lz5;
	int c;

	lz5 = (struct lz5decode_state *)strm->private;
	if (lz5->flagcnt == 0) {
		lz5->flagcnt = 8;
		lz5->flag = lha_br_getbyte(strm);
		if (lz5->flag < 0)
			return -1;
	}
	lz5->flagcnt--;

	c = lha_br_getbyte(strm);
	if (c < 0)
		return -1;
	if ((lz5->flag & 1) == 0) {
		lz5->matchpos = c;
		c = lha_br_getbyte(strm);
		if (c < 0)
			return -1;
		lz5->matchpos += (c & 0xf0) << 4;
		c &= 0x0f;
		c += 0x100;
	}
	lz5->flag >>= 1;

	return (c);
}

static int
lz5_decode_p(struct lha_stream *strm)
{
	struct lz5decode_state *lz5;

	lz5 = (struct lz5decode_state *)strm->private;
	return ((lz5->ds.pos - lz5->matchpos - 19) & 0xfff);
}

static void
lz5_decode_prepare(struct lha_stream *strm)
{
	struct lz5decode_state *lz5;
	int i;
	int offset;

	lz5 = (struct lz5decode_state *)strm->private;
	lz5->flagcnt = 0;

	offset = 18;
	for (i = 0; i < 256; i++) {
		memset(lz5->ds.buffer + offset, i, 13);
		offset += 13;
	}
	for (i = 0; i < 256; i++)
		lz5->ds.buffer[offset++] = (unsigned char)i;
	for (i = 256; i > 0;)
		lz5->ds.buffer[offset++] = (unsigned char)(--i);
	memset(lz5->ds.buffer + offset, 0, 128);
	memset(lz5->ds.buffer + offset + 128, 0x20, 128 - 18);
}


struct lzsdecode_state {
	struct decode_state	ds;
	int			matchpos;
};

static int	lzs_decode_init(struct decode_state *ds, int reset);
static void	lzs_decode_prepare(struct lha_stream *strm);
static int	lzs_decode_c(struct lha_stream *strm);
static int	lzs_decode_p(struct lha_stream *strm);

static int
lha_lzs_decode_new(struct decode_state **ds)
{

	*ds = malloc(sizeof(struct lzsdecode_state));
	if (*ds == NULL)
		return (LHA_MEM_ERROR);

	lha_decode_register(*ds, lzs_decode_init, lzs_decode_prepare,
	    lzs_decode_c, lzs_decode_p, NULL);

	return (LHA_OK);
}

static int
lzs_decode_init(struct decode_state *ds, int reset)
{

	/* override a adjust */
	ds->adjust = UCHAR_MAX + 1 - 2;

	return (LHA_OK);
}

static int
lzs_decode_c(struct lha_stream *strm)
{
	struct lzsdecode_state *lzs;

	lzs = (struct lzsdecode_state *)strm->private;
	if (lha_br_getbits(1, strm) > 0)
		return (lha_br_getbits(8, strm));
	else {
		lzs->matchpos = lha_br_getbits(11, strm);
		return (lha_br_getbits(4, strm) + 0x100);
	}
}

static int
lzs_decode_p(struct lha_stream *strm)
{
	struct lzsdecode_state *lzs;

	lzs = (struct lzsdecode_state *)strm->private;
	return ((lzs->ds.pos - lzs->matchpos - 18) & 0x7ff);
}

static void
lzs_decode_prepare(struct lha_stream *strm)
{
	struct lzsdecode_state *lzs;

	lzs = (struct lzsdecode_state *)strm->private;
	lha_br_init(strm);
	lzs->matchpos = 0;
}


static int
lha_make_table(int nchar, unsigned char bitlen[], int tablebits,
    uint16_t table[], struct huf_work *hw)
{
	uint16_t count[17];
	uint16_t weight[17];
	uint16_t start[17];
	uint16_t *p;
	uint16_t *left, *right;
	uint i, k;
	uint avail, jutbits, len, mask, nextcode;
	uint16_t ch, total;

	memset(count, 0, sizeof(count));
	for (i = 0; i < (uint)nchar; i++) {
		if (bitlen[i] > 16)		/* CVE-2006-4335	    */
			return (LHA_DATA_ERROR);/* Bad LHA data(wrong table)*/
		count[bitlen[i]]++;
	}

	total = 0;
	for (i = 1; i <= 16; i++) {
		start[i] = total;
		total = start[i] + (count[i] << (16 - i));
	}
	if (total != 0)
		return (LHA_DATA_ERROR);	/* Bad LHA data(wrong table)*/

	jutbits = 16 - tablebits;
	for (i = 1; i <= (uint)tablebits; i++) {
		start[i] >>= jutbits;
		weight[i] = 1U << (tablebits - i);
	}
	for (;i <= 16; i++)
		weight[i] = 1U << (16 - i);

	i = (start[tablebits + 1] >> jutbits) & 0xffff;
	if (i != 0) {
		k = 1U << tablebits;
		if (k > 4096)
			k = 4096;
		if (i < k)
			memset(&table[i], 0, sizeof(table[0]) * (k - i));
	}

	left = hw->left;
	right = hw->right;
	avail = nchar;
	mask = 1U << (15 - tablebits);
	for (ch = 0; ch < nchar; ch++) {
		if ((len = bitlen[ch]) == 0)
			continue;
		nextcode = start[len] + weight[len];
		if (len <= tablebits) {
			if (nextcode > 4096)
				nextcode = 4096;
			for (i = start[len]; i < nextcode; i++)
				table[i] = ch;
		} else {
			k = start[len];
			if ((k >>jutbits) > 4096)/* CVE-2006-4337	    */
				return (LHA_DATA_ERROR);
						/* Bad LHA data(wrong table)*/
			p = &table[k >> jutbits];
			i = len - tablebits;
			while (i != 0) {
				if (*p == 0) {
					right[avail] = left[avail] = 0;
					*p = avail++;
				}
				if (k & mask)
					p = &right[*p];
				else
					p = &left[*p];
				k <<= 1;
				i--;
			}
			*p = ch;
		}
		start[len] = nextcode;
	}

	return (LHA_OK);
}


static const uint16_t crc16tbl[256] = {
	0x0000,0xC0C1,0xC181,0x0140,0xC301,0x03C0,0x0280,0xC241,
	0xC601,0x06C0,0x0780,0xC741,0x0500,0xC5C1,0xC481,0x0440,
	0xCC01,0x0CC0,0x0D80,0xCD41,0x0F00,0xCFC1,0xCE81,0x0E40,
	0x0A00,0xCAC1,0xCB81,0x0B40,0xC901,0x09C0,0x0880,0xC841,
	0xD801,0x18C0,0x1980,0xD941,0x1B00,0xDBC1,0xDA81,0x1A40,
	0x1E00,0xDEC1,0xDF81,0x1F40,0xDD01,0x1DC0,0x1C80,0xDC41,
	0x1400,0xD4C1,0xD581,0x1540,0xD701,0x17C0,0x1680,0xD641,
	0xD201,0x12C0,0x1380,0xD341,0x1100,0xD1C1,0xD081,0x1040,
	0xF001,0x30C0,0x3180,0xF141,0x3300,0xF3C1,0xF281,0x3240,
	0x3600,0xF6C1,0xF781,0x3740,0xF501,0x35C0,0x3480,0xF441,
	0x3C00,0xFCC1,0xFD81,0x3D40,0xFF01,0x3FC0,0x3E80,0xFE41,
	0xFA01,0x3AC0,0x3B80,0xFB41,0x3900,0xF9C1,0xF881,0x3840,
	0x2800,0xE8C1,0xE981,0x2940,0xEB01,0x2BC0,0x2A80,0xEA41,
	0xEE01,0x2EC0,0x2F80,0xEF41,0x2D00,0xEDC1,0xEC81,0x2C40,
	0xE401,0x24C0,0x2580,0xE541,0x2700,0xE7C1,0xE681,0x2640,
	0x2200,0xE2C1,0xE381,0x2340,0xE101,0x21C0,0x2080,0xE041,
	0xA001,0x60C0,0x6180,0xA141,0x6300,0xA3C1,0xA281,0x6240,
	0x6600,0xA6C1,0xA781,0x6740,0xA501,0x65C0,0x6480,0xA441,
	0x6C00,0xACC1,0xAD81,0x6D40,0xAF01,0x6FC0,0x6E80,0xAE41,
	0xAA01,0x6AC0,0x6B80,0xAB41,0x6900,0xA9C1,0xA881,0x6840,
	0x7800,0xB8C1,0xB981,0x7940,0xBB01,0x7BC0,0x7A80,0xBA41,
	0xBE01,0x7EC0,0x7F80,0xBF41,0x7D00,0xBDC1,0xBC81,0x7C40,
	0xB401,0x74C0,0x7580,0xB541,0x7700,0xB7C1,0xB681,0x7640,
	0x7200,0xB2C1,0xB381,0x7340,0xB101,0x71C0,0x7080,0xB041,
	0x5000,0x90C1,0x9181,0x5140,0x9301,0x53C0,0x5280,0x9241,
	0x9601,0x56C0,0x5780,0x9741,0x5500,0x95C1,0x9481,0x5440,
	0x9C01,0x5CC0,0x5D80,0x9D41,0x5F00,0x9FC1,0x9E81,0x5E40,
	0x5A00,0x9AC1,0x9B81,0x5B40,0x9901,0x59C0,0x5880,0x9841,
	0x8801,0x48C0,0x4980,0x8941,0x4B00,0x8BC1,0x8A81,0x4A40,
	0x4E00,0x8EC1,0x8F81,0x4F40,0x8D01,0x4DC0,0x4C80,0x8C41,
	0x4400,0x84C1,0x8581,0x4540,0x8701,0x47C0,0x4680,0x8641,
	0x8201,0x42C0,0x4380,0x8341,0x4100,0x81C1,0x8081,0x4040
};

uint16_t
__lha_crc16(uint16_t crc, const void *pp, size_t len)
{
	const unsigned char *buff = (const unsigned char *)pp;

	while (len-- > 0)
		crc = crc16tbl[(crc ^ (*buff++)) & 0xFF] ^ (crc >> CHAR_BIT);
	return (crc);
}

static void
lha_stream_init(struct lha_stream *strm)
{
	strm->next_in = NULL;
	strm->avail_in = 0;
	strm->total_in = 0;
	strm->next_out = NULL;
	strm->avail_out = 0;
	strm->total_out = 0;
}

static int
lha_getdicbit(int method)
{
	int dicbit;

	switch (method) {
	case LHA_METHOD_LZS:
		dicbit = 11;
		break;
	case LHA_METHOD_LZ5:
	case LHA_METHOD_LH1:
	case LHA_METHOD_LH4:
		dicbit = 12;
		break;
	case LHA_METHOD_LH2:
	case LHA_METHOD_LH3:
	case LHA_METHOD_LH5:
		dicbit = 13;
		break;
	case LHA_METHOD_LH6:
		dicbit = 15;
		break;
	case LHA_METHOD_LH7:
		dicbit = 16;
		break;
	default:
		dicbit = 13;
		break;
	}

	return (dicbit);
}

/*
 * @@encode compression
 */

#define HASH_SIZE	(1 << 15)
#define NEED_OPT	(0x100)

struct encode_state {
	int			 method;
        int     		 state;	/* status of encode             */

	unsigned char		*text;
	int			 remainder;
	uint			 pos;

	uint16_t		*tokens;
	struct {
		uint		 pos;
		int		 link;
	}			 hash[HASH_SIZE];
	uint			*prev;
	int			 matchlen;
	uint	  		 matchpos;

	size_t			 rcachesize;
	unsigned char		*rcache;
	size_t			 ravail;
	size_t			 rset;
	size_t			 rget;

	int			 dicbit;
	int			 dicsize;
	uint			 dicmask;

	int			 err;
	char			*errmsg;

	/* Bit writer	*/
	uint16_t		 subbitbuf;	/* sub-buffer of bit-writer */
	int			 bitcount;	/* bit counter		    */
#define OUTBUFSIZE	(16 * 1024 * 2)
	unsigned char		 wcache[OUTBUFSIZE];
	unsigned char		*wptr;
	size_t			 wavail;

	/* Encodefunctinos */
	int			 (*init)(struct encode_state *es, int reset);
	void			 (*start)(struct lha_stream *strm);
	void			 (*output)(uint16_t c, uint16_t p,
				     struct lha_stream *strm);
	void			 (*finish)(struct lha_stream *strm);
	int			 (*free)(struct encode_state *es);
};

static int	lha_encode_init_state(struct encode_state *es, int method,
		    int reset);
static int	lha_encode_free_state(struct encode_state *es);
static int	lha_lh5_encode_new(struct encode_state ** es, int method);
static void	putbits(unsigned char n, uint16_t x, struct lha_stream *strm);

static void	copy_in(struct lha_stream *strm);
static int	get_text(size_t offset, size_t len, struct lha_stream *strm);
static void	init_putbits(struct encode_state *es);
static int	copy_out(struct lha_stream *strm);

static void
make_tokens(struct encode_state *es, uint pos, int size,  int init)
{
	int end;
	uint16_t token;

	end = pos + size;

	if (init)
		token = ((es->text[pos] << 5) ^ es->text[pos + 1]);
	else
		token = es->tokens[pos-1];

	for (; pos < end; pos++) {
		es->tokens[pos] = token =
		    ((token << 5) ^ es->text[pos + 2]) & (HASH_SIZE - 1);
	}
}

inline static void
update_hashtable(struct encode_state *es)
{
	uint16_t token = es->tokens[es->pos];

	es->prev[es->pos & es->dicmask] = es->hash[token].pos;
	es->hash[token].pos = es->pos;
	es->hash[token].link++;
}

static void
longest_match(struct lha_stream *strm, int offset, int maxlen)
{   
	struct encode_state *es;
	uint16_t *tokens;
	int comp;
	int hpos;
	int rpos;	/* real position for which to compare with es->pos */
	int limit;	/* limit of following position */
	int link;
	uint16_t ctoken;
 
	es = (struct encode_state *)strm->private;
	comp = es->matchlen - 2;
	tokens = &es->tokens[es->pos];
	ctoken = tokens[comp];
	hpos = es->hash[tokens[offset]].pos;
	rpos = hpos - offset;
	link = es->hash[tokens[offset]].link;
	limit = es->pos - es->dicsize;

	while (rpos > limit) {
		uint16_t *aw = (uint16_t *)&es->text[rpos];
		uint16_t *bw = (uint16_t *)&es->text[es->pos];
    
		if (es->tokens[rpos + comp] == ctoken && *aw == *bw) {
			int len;	/* calculated matching length */

			for (len = 2; len < maxlen && *++aw == *++bw;)
				len += 2;
			if (len < maxlen) {
				unsigned char *a = (unsigned char *)aw;
				unsigned char *b = (unsigned char *)bw;
				if (*a == *b)
					len++;
			} else
				/* think of that the maxlen is odd number */
				len = maxlen;

			if (len > es->matchlen) {
				/* Update the longest matche data.	*/
				es->matchpos = es->pos - rpos;
				es->matchlen = len;
				if (len == maxlen)
					break;
				comp = len - 2;
				if (es->hash[ctoken = tokens[comp]].pos == 0)
					/* it's nothing to be matching data */
					break;
#if 0
				/*
				 *   This code will reduce a number of times of
				 *   loop, but ...
				 */
				if (offset < comp &&
				    link > es->hash[ctoken].link) {
					int orpos;

					offset = comp;
					hpos = es->hash[ctoken].pos;
					orpos = rpos;
					rpos = hpos - offset;
					link = es->hash[ctoken].link;
					while (rpos > orpos) {
						hpos = es->prev[
						    hpos & es->dicmask];
						rpos = hpos - offset;
						link--;
					}
					continue;
				}
#endif
			}
		}
		hpos = es->prev[hpos & es->dicmask];
		rpos = hpos - offset;
		link--;
	}
}

static void
find_match(struct lha_stream *strm, int minlen)
{   
	struct encode_state *es;
	int offset, maxlen;

	es = (struct encode_state *)strm->private;
    	es->matchpos = 0;
    	maxlen = (MAXMATCH > es->remainder) ? es->remainder : MAXMATCH;
	if (minlen < THRESHOLD)
		/* make sure a minimum length of matching data is not less than
		 * THRESHOLD
		 */
		minlen = THRESHOLD;
	if (maxlen < minlen) {
		/* it does not have enough data */
		es->matchlen = es->remainder;
		/* Exit this function. */
		return;
	} else
    		es->matchlen = minlen -1;

	/*
	 * Find a optimal position and maximum length of matching data to search
	 * the longest matching data, for speed up perfomance of longest_match().
	 */
    	offset = 0;
	for (;;) {
		int link, link2;

		link = es->hash[es->tokens[es->pos + offset]].link;
		if (link == 0) {
			/* it means no more matching data. */
			maxlen = offset + 2;
			offset = 0;
			break;
		}
		if (link < NEED_OPT) {
			link2 = es->hash[es->tokens[es->pos + offset+1]].link;
			if (link2 == 0)
				/* it means no more matching data. */
				maxlen = offset + 1 + 2;
			else if ((link >> 4) > link2)
				offset++;
			break;
		}
		if (++offset == maxlen - THRESHOLD) {
			/*
			 * All of the hash data have too many linking data.
			 * We have no best position.
			 */
			offset = 0;
			break;
		}
	}
	if (maxlen < minlen)
		/*
		 * Exit this function.
		 * Current data which is pointed by es->pos has nothing to find
		 * the matching data.
		 */
		return;


	/* Try to get the longest matching data. */
	for (;;) {
		longest_match(strm, offset, maxlen);
		if (offset == 0)
			/*
			 * A search position is not optimized.
			 * We have already had the longest matching data.
			 */
			break;
		if (es->matchlen >= offset + 3)
			/*
			 * A search position is optimized, and there is
			 * enough matching length(es->matchlen) for the
			 * longest matching data.
		 	 * ('3' is a data size which is needed to make hash
			 * data)
			 */
			break;
		/*
		 * Ensure that es->matchpos and es->matchlen are the
		 * longest matching data.
		 */
		maxlen = offset + 2;
		if (es->hash[es->tokens[es->pos + offset-1]].link < NEED_OPT)
			offset--;
		else
			offset = 0;
		/* Retry to get the longest matching data. */
	}
}

static void
feed_pos(struct lha_stream *strm)
{
	struct encode_state *es;
	int i, n;

	es = (struct encode_state *)strm->private;
	if (es->remainder <= 0)
		return;
	es->remainder--;
	if (++es->pos >= es->dicsize * 2) {
		/*
		 * Read a next encode data block if the current encode data
		 * block was comsumed.
		 */
		memmove(&es->text[0], &es->text[es->dicsize],
		    es->dicsize + MAXMATCH);
		n = get_text(es->dicsize + MAXMATCH, es->dicsize, strm);
		es->remainder += n;
		es->pos = es->dicsize;

		/* Convert positions that are included in hash table into
		 * an old position area that is less than es->dicsize. */
		for (i = 0; i < HASH_SIZE; i++) {
			int link, old, pos;

			if ((pos = es->hash[i].pos) > es->dicsize)
				es->hash[i].pos -= es->dicsize;
			else
				es->hash[i].pos = 0;
			link = 0;
			while (pos > es->dicsize) {
				link++;
				pos = es->prev[old = pos & es->dicmask];
				if (pos > es->dicsize)
					es->prev[old] -= es->dicsize;
				else
					es->prev[old] = 0;
			}
			es->hash[i].link = link;
		}
		memmove(&es->tokens[0], &es->tokens[es->dicsize],
		    (es->dicsize + MAXMATCH) * sizeof(es->tokens[0]));
		make_tokens(es, es->dicsize+MAXMATCH-3, n+3, 0);
	}
}

static void
lha_encode_cleanup_ptr(struct encode_state *es)
{
	es->text = NULL;
	es->prev = NULL;
	es->rcache = NULL;
	es->tokens = NULL;
}

static int
lha_encode_init_state(struct encode_state *es, int method, int reset)
{
	es->method = method;
	es->dicbit = lha_getdicbit(method);
	es->dicsize = 1U << es->dicbit;
	es->dicmask = es->dicsize - 1;

	es->state = 0;
	es->remainder = INT_MAX;
	es->matchlen = 0;
	es->rcachesize = es->dicsize * 2;
	es->ravail = es->rset = es->rget = 0;
	es->err = 0;
	es->errmsg = NULL;
	init_putbits(es);

	if (!reset) {
		lha_encode_cleanup_ptr(es);

		es->text = malloc(
		    (es->dicsize * 2 + MAXMATCH) * sizeof(*es->text));
		if (es->text == NULL)
			return (LHA_ERRNO);
		es->prev = malloc(es->dicsize * sizeof(*es->prev));
		if (es->prev == NULL) {
			lha_encode_free_state(es);
			return (LHA_ERRNO);
		}
		es->rcache = malloc(es->rcachesize * sizeof(*es->rcache));
		if (es->rcache == NULL) {
			lha_encode_free_state(es);
			return (LHA_ERRNO);
		}
		es->tokens = malloc(
		    (es->dicsize * 2 + MAXMATCH) * sizeof(*es->tokens));
		if (es->tokens == NULL) {
			lha_encode_free_state(es);
			return (LHA_ERRNO);
		}
	}
	memset(es->text, 0x20,
	    (es->dicsize * 2 + MAXMATCH) * sizeof(*es->text));
	memset(es->prev, 0, es->dicsize * sizeof(*es->prev));
	memset(es->hash, 0, sizeof(es->hash));

	return (LHA_OK);
}

static int
lha_encode_free_state(struct encode_state *es)
{
	if (es->text != NULL)
		free(es->text);
	if (es->prev != NULL)
		free(es->prev);
	if (es->rcache != NULL)
		free(es->rcache);
	if (es->tokens != NULL)
		free(es->tokens);

	lha_encode_cleanup_ptr(es);

	return (LHA_OK);
}

int
__lha_encodeInit(struct lha_stream *strm, int method)
{
	struct encode_state *es;
	int err;

	lha_stream_init(strm);

	switch (method) {
	case LHA_METHOD_LH5:
	case LHA_METHOD_LH6:
	case LHA_METHOD_LH7:
		err = lha_lh5_encode_new(&es, method);
		break;
	default:
		err = LHA_ERRNO;
		es = NULL;/* Disable compiling warning. */
		break;
	}
	if (err < 0)
		return (err);

	err = lha_encode_init_state(es, method, 0);
	if (err < 0) {
		free(es);
		return (err);
	}
	if (es->init != NULL) {
		err = es->init(es, 0);
		if (err < 0) {
			free(es);
			return (err);
		}
	}

	strm->private = es;

	return (LHA_OK);
}

int
__lha_encodeEnd(struct lha_stream *strm)
{
	struct encode_state *es;

	if (strm->private != NULL) {
		es = (struct encode_state *)strm->private;
		lha_encode_free_state(es);
		if (es->free != NULL)
			es->free(es);
		free(es);
		strm->private = NULL;
	}

	return (LHA_OK);
}

int
__lha_encodeReset(struct lha_stream *strm)
{
	struct encode_state *es;
	int err;

	lha_stream_init(strm);
	if (strm->private == NULL)
		return (LHA_ERRNO);
	es = (struct encode_state *)strm->private;
	err = lha_encode_init_state(es, es->method, 1);
	if (err < 0)
		return (err);
	if (es->init != NULL)
		err = es->init(es, 1);

	return (err);
}

static void
copy_in(struct lha_stream *strm)
{
	struct encode_state *es;
	size_t len, ll;

	es = (struct encode_state *)strm->private;
	len = es->rcachesize - es->ravail;
	if (len > strm->avail_in)
		len = strm->avail_in;
	while (len > 0) {
		if (es->rset + len > es->rcachesize)
			ll = es->rcachesize - es->rset;
		else
			ll = len;
		memcpy(&es->rcache[es->rset], strm->next_in, ll);
		es->ravail += ll;
		es->rset += ll;
		if (es->rset == es->rcachesize)
			es->rset = 0;
		strm->next_in += ll;
		strm->avail_in -= ll;
		strm->total_in += ll;
		len -= ll;
	}
}

static int
get_text(size_t offset, size_t len, struct lha_stream *strm)
{
	struct encode_state *es;
	unsigned char *buff;
	size_t ll, bytes;

	es = (struct encode_state *)strm->private;
	buff = es->text + offset;
	if (len > es->ravail)
		len = es->ravail;
	bytes = len;
	while (len > 0) {
		if (es->rget + len > es->rcachesize)
			ll = es->rcachesize - es->rget;
		else
			ll = len;
		memcpy(buff, &es->rcache[es->rget], ll);
		es->ravail -= ll;
		es->rget += ll;
		if (es->rget == es->rcachesize)
			es->rget = 0;
		buff += ll;
		len -= ll;
	}
	copy_in(strm);

	return (bytes);
}

int
__lha_encode(struct lha_stream *strm, int flush)
{
	struct encode_state *es;
	int lastmatchlen;
	uint lastmatchpos;

	es = (struct encode_state *)strm->private;

	if (strm->avail_out == 0) {
		es->err = LHA_BUF_ERROR;
		es->errmsg = "write space is empty!!";
		return (es->err);
	}
	/* if encoded datas are available, copy ones into the strm->next_out. */
	if (copy_out(strm) && strm->avail_out == 0)
		return (LHA_OK);

	if (es->state == -1)
		return (LHA_STREAM_END);

	copy_in(strm);
	es->err = LHA_OK;

	for (;;) {
		if (es->err != LHA_OK)
			break;
		if (flush != LHA_FINISH &&
		    es->ravail < es->dicsize + MAXMATCH)
			break;
		if (strm->avail_out == 0)
			break;
		if (es->remainder <= 0 && es->state == 1)
			break;

		switch (es->state) {
		case 0:
			es->start(strm);
			es->remainder = get_text(es->dicsize,
			    es->dicsize + MAXMATCH, strm);
			es->pos = es->dicsize;
			make_tokens(es, es->pos, es->remainder, 1);
			update_hashtable(es);

			es->matchlen = THRESHOLD -1;
			es->matchpos = 0;
			if (es->matchlen > es->remainder)
				es->matchlen = es->remainder;
			es->state = 1;
			break;

		case 1:
			lastmatchlen = es->matchlen;
			lastmatchpos = es->matchpos;
			feed_pos(strm);
			find_match(strm, lastmatchlen);
			update_hashtable(es);
			if (es->matchlen > lastmatchlen ||
			    lastmatchlen < THRESHOLD)
				es->output(es->text[es->pos - 1], 0, strm);
			else {
				es->output(lastmatchlen +
				    (UCHAR_MAX + 1 - THRESHOLD),
			    	    (lastmatchpos - 1) & es->dicmask,
		  		    strm);
				lastmatchlen--;
				while (--lastmatchlen > 0) {
					feed_pos(strm);
					update_hashtable(es);
				}
				es->state = 2;
			}
			break;

		case 2:
			feed_pos(strm);
			find_match(strm, THRESHOLD);
			update_hashtable(es);
			es->state = 1;
			break;
		}
	}

	if (flush == LHA_FINISH && es->remainder == 0) {
		es->finish(strm);
		es->state = -1;
		if (es->err != LHA_OK)
			return (es->err);
		if (es->wavail != 0)
			return (LHA_OK);
		else
			return (LHA_STREAM_END);
	}

	if (es->err != LHA_OK)
		return (es->err);
	return (LHA_OK);
}


static void
init_putbits(struct encode_state *es)
{

	es->bitcount = CHAR_BIT;
	es->subbitbuf = 0;
	es->wptr = es->wcache;
	es->wavail = 0;
}

static int
copy_out(struct lha_stream *strm)
{
	struct encode_state *es;
	size_t len;

	es = (struct encode_state *)strm->private;
	if ((len = es->wavail) == 0)
		return (0);	/* Encoded datas are nothing. */
	if (len > strm->avail_out)
		len = strm->avail_out;
	memcpy(strm->next_out, es->wptr - es->wavail, len);
	strm->next_out += len;
	strm->avail_out -= len;
	strm->total_out += len;
	es->wavail -= len;
	if (es->wavail == 0)
		es->wptr = es->wcache;

	return (1);
}

static void
write_byte(unsigned char byte, struct lha_stream *strm)
{
	struct encode_state *es;

	es = (struct encode_state *)strm->private;
	if (strm->avail_out > 0) {
		*strm->next_out++ = byte;
		strm->avail_out--;
		strm->total_out++;
	} else if (es->wavail < sizeof(es->wcache)) {
		*es->wptr++ = byte;
		es->wavail++;
	} else {
		es->err = LHA_BUF_ERROR;
		es->errmsg = "write space is empty!!";
	}
}

/* Write rightmost n bits of x */
static void
putbits(unsigned char n, uint16_t x, struct lha_stream *strm)
{
	struct encode_state *es;

	es = (struct encode_state *)strm->private;

	x &= 0xFFFF >> (16 - n);
	if (n < es->bitcount) {
		es->subbitbuf |= x << (es->bitcount -= n);
	} else {
		write_byte(es->subbitbuf |
		    (x >> (n -= es->bitcount)), strm);
		if (n < CHAR_BIT) {
			es->subbitbuf =
			    x << (es->bitcount = CHAR_BIT - n);
		} else {
			write_byte(x >> (n - CHAR_BIT), strm);
			es->subbitbuf =
			    x << (es->bitcount = 2 * CHAR_BIT - n);
		}
	}
}


struct hufencode_state {
	struct encode_state	 es;
	struct huf_work 	 hw;
	struct huf_val	 	 val;

	unsigned char 		 outbuf[OUTBUFSIZE];
	uint16_t		*c_freq;
	uint16_t		*p_freq;
	uint16_t		*t_freq;
	uint16_t		 cpos;
	uint16_t		 output_pos;
	uint16_t		 output_mask;
	unsigned char		 c_len[NC];
	uint16_t		 c_code[NC];
	unsigned char		 pt_len[NPT];
	uint16_t		 pt_code[NPT];
};

static int	sta_huf_encode_init(struct encode_state *es, int reset);
static void	sta_huf_encode_start(struct lha_stream *strm);
static void	sta_huf_encode_output(uint16_t c, uint16_t p,
		    struct lha_stream *strm);
static void	sta_huf_encode_finish(struct lha_stream *strm);
static int	sta_huf_encode_free(struct encode_state *es);

static const char ctblen[256] = {
	0,1,2,2,3,3,3,3,4,4,4,4,4,4,4,4,
	5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,5,
	6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,
	6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,6,
	7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
	7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
	7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
	7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,7,
	8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
	8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
	8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
	8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
	8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
	8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
	8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,
	8,8,8,8,8,8,8,8,8,8,8,8,8,8,8,8
};

static int
lha_lh5_encode_new(struct encode_state **es, int method)
{

	*es = malloc(sizeof(struct hufencode_state));
	if (*es == NULL)
		return (LHA_ERRNO);

	/* register encode functions */
	(*es)->init = sta_huf_encode_init;
	(*es)->start = sta_huf_encode_start;
	(*es)->output = sta_huf_encode_output;
	(*es)->finish = sta_huf_encode_finish;
	(*es)->free = sta_huf_encode_free;

	return (LHA_OK);
}

static int
sta_huf_encode_init(struct encode_state *es, int reset)
{
	struct hufencode_state *huf;

	huf = (struct hufencode_state *)es;
	lha_huf_init_work(&huf->hw);
	lha_huf_init_val(&huf->val, huf->es.dicbit);

	/* encode specific */
	if (!reset) {
		huf->c_freq = malloc((2 * NC -1) * sizeof(*huf->c_freq));
		if (huf->c_freq == NULL)
			return (LHA_ERRNO);
		huf->p_freq = malloc(
		    (2 * huf->val.NP -1) * sizeof(*huf->p_freq));
		if (huf->p_freq == NULL) {
			free(huf->c_freq);
			return (LHA_ERRNO);
		}
		huf->t_freq = malloc(
		    (2 * huf->val.NT -1) * sizeof(*huf->t_freq));
		if (huf->t_freq == NULL) {
			free(huf->c_freq);
			free(huf->p_freq);
			return (LHA_ERRNO);
		}
	}
	memset(huf->c_freq, 0, (2 * NC -1) * sizeof(*huf->c_freq));
	memset(huf->p_freq, 0, (2 * huf->val.NP -1) * sizeof(*huf->p_freq));
	memset(huf->t_freq, 0, (2 * huf->val.NT -1) * sizeof(*huf->t_freq));
	memset(huf->outbuf, 0, sizeof(huf->outbuf));
	memset(huf->c_code, 0, sizeof(huf->c_code));

	return (LHA_OK);
}

static int
sta_huf_encode_free(struct encode_state *es)
{
	struct hufencode_state *huf;

	huf = (struct hufencode_state *)es;
	free(huf->c_freq);
	free(huf->p_freq);
	free(huf->t_freq);

	return (LHA_OK);
}

static void
count_t_freq(struct lha_stream *strm)
{
	struct hufencode_state *huf;
	int16_t i, k, n, count;

	huf = (struct hufencode_state *)strm->private;

	memset(huf->t_freq, 0, sizeof(huf->t_freq[0]) * huf->val.NT);
	n = NC;
	while (n > 0 && huf->c_len[n - 1] == 0)
		n--;
	i = 0;
	while (i < n) {
		k = huf->c_len[i++];
		if (k == 0) {
			count = 1;
			while (i < n && huf->c_len[i] == 0) {
				i++;
				count++;
			}
			if (count <= 2)
				huf->t_freq[0] += count;
			else if (count <= 18)
				huf->t_freq[1]++;
			else if (count == 19) {
				huf->t_freq[0]++;
				huf->t_freq[1]++;
			} else
				huf->t_freq[2]++;
		} else
			huf->t_freq[k + 2]++;
	}
}

static void
write_pt_len(int16_t n, int16_t nbit, int16_t i_special, struct lha_stream *strm)
{
	struct hufencode_state *huf;
	int16_t i, k;

	huf = (struct hufencode_state *)strm->private;

	while (n > 0 && huf->pt_len[n - 1] == 0)
		n--;
	putbits(nbit, n, strm);
	i = 0;
	while (i < n) {
		k = huf->pt_len[i++];
		if (k <= 6)
			putbits(3, k, strm);
		else
			putbits(k - 3, 0xfffe, strm);
		if (i == i_special) {
			while (i < 6 && huf->pt_len[i] == 0)
				i++;
			putbits(2, i - 3, strm);
		}
	}
}

static void
write_c_len(struct lha_stream *strm)
{
	struct hufencode_state *huf;
	int16_t i, k, n, count;

	huf = (struct hufencode_state *)strm->private;
	n = NC;
	while (n > 0 && huf->c_len[n - 1] == 0)
		n--;
	putbits(CBIT, n, strm);
	i = 0;
	while (i < n) {
		k = huf->c_len[i++];
		if (k == 0) {
			count = 1;
			while (i < n && huf->c_len[i] == 0) {
				i++;
				count++;
			}
			if (count <= 2) {
				for (k = 0; k < count; k++)
					putbits(huf->pt_len[0],
					    huf->pt_code[0], strm);
			} else if (count <= 18) {
				putbits(huf->pt_len[1], huf->pt_code[1], strm);
				putbits(4, count - 3, strm);
			} else if (count == 19) {
				putbits(huf->pt_len[0], huf->pt_code[0], strm);
				putbits(huf->pt_len[1], huf->pt_code[1], strm);
				putbits(4, 15, strm);
			} else {
				putbits(huf->pt_len[2], huf->pt_code[2], strm);
				putbits(CBIT, count - 20, strm);
			}
		} else
			putbits(huf->pt_len[k + 2], huf->pt_code[k + 2], strm);
	}
}

static void
encode_c(int16_t c, struct lha_stream *strm)
{
	struct hufencode_state *huf;

	huf = (struct hufencode_state *)strm->private;
	putbits(huf->c_len[c], huf->c_code[c], strm);
}

static void
encode_p(uint16_t p, struct lha_stream *strm)
{
	struct hufencode_state *huf;
	uint16_t c;

	huf = (struct hufencode_state *)strm->private;
	if (p >= (1U << CHAR_BIT))
		c = ctblen[p >> CHAR_BIT] + 8;
	else
		c = ctblen[(unsigned char)p];
	putbits(huf->pt_len[c], huf->pt_code[c], strm);
	if (c > 1)
		putbits(c - 1, p, strm);
}

static void
send_block(struct lha_stream *strm)
{
	struct hufencode_state *huf;
	unsigned char flags;
	uint16_t i, k, root, pos, size;

	huf = (struct hufencode_state *)strm->private;
	flags = 0;
	root = lha_make_tree(NC, huf->c_freq, huf->c_len, huf->c_code,
	    &huf->hw);
	size = huf->c_freq[root];
	putbits(16, size, strm);
	if (root >= NC) {
		count_t_freq(strm);
		root = lha_make_tree(huf->val.NT, huf->t_freq, huf->pt_len,
		    huf->pt_code, &huf->hw);
		if (root >= huf->val.NT)
			write_pt_len(huf->val.NT, TBIT, 3, strm);
		else {
			putbits(TBIT, 0, strm);
			putbits(TBIT, root, strm);
		}
		write_c_len(strm);
	} else {
        	putbits(TBIT, 0, strm);
		putbits(TBIT, 0, strm);
		putbits(CBIT, 0, strm);
		putbits(CBIT, root, strm);
	}
	root = lha_make_tree(huf->val.NP, huf->p_freq, huf->pt_len,
	    huf->pt_code, &huf->hw);
	if (root >= huf->val.NP)
		write_pt_len(huf->val.NP, huf->val.PBIT, -1, strm);
	else {
		putbits(huf->val.PBIT, 0, strm);
		putbits(huf->val.PBIT, root, strm);
	}
	pos = 0;
	for (i = 0; i < size; i++) {
		if (i % CHAR_BIT == 0)
			flags = huf->outbuf[pos++];
		else
			flags <<= 1;
		if (flags & (1U << (CHAR_BIT - 1))) {
			encode_c(huf->outbuf[pos++] + (1U << CHAR_BIT), strm);
			k = huf->outbuf[pos++] << CHAR_BIT;
			k += huf->outbuf[pos++];
			encode_p(k, strm);
		} else
			encode_c(huf->outbuf[pos++], strm);
	}
	memset(huf->c_freq, 0, sizeof(huf->c_freq[0]) * NC);
	memset(huf->p_freq, 0, sizeof(huf->p_freq[0]) * huf->val.NP);
}

static void
sta_huf_encode_output(uint16_t c, uint16_t p, struct lha_stream *strm)
{
	struct hufencode_state *huf;

	huf = (struct hufencode_state *)strm->private;
	if ((huf->output_mask >>= 1) == 0) {
		huf->output_mask = 1U << (CHAR_BIT - 1);
		if (huf->output_pos >= OUTBUFSIZE - 3 * CHAR_BIT) {
			send_block(strm);
			huf->output_pos = 0;
		}
		huf->cpos = huf->output_pos++;
		huf->outbuf[huf->cpos] = 0;
	}
	huf->outbuf[huf->output_pos++] = (unsigned char) c;
	huf->c_freq[c]++;
	if (c >= (1U << CHAR_BIT)) {
		huf->outbuf[huf->cpos] |= huf->output_mask;
		huf->outbuf[huf->output_pos++] = (unsigned char)(p >> CHAR_BIT);
		huf->outbuf[huf->output_pos++] = (unsigned char) p;
		if (p >= (1U << CHAR_BIT))
			huf->p_freq[(int)ctblen[p >> CHAR_BIT] + 8]++;
		else
			huf->p_freq[(int)ctblen[(unsigned char)p]]++;
	}
}

static void
sta_huf_encode_start(struct lha_stream *strm)
{
	struct hufencode_state *huf;

	huf = (struct hufencode_state *)strm->private;
	huf->outbuf[0] = 0;
	memset(huf->c_freq, 0, sizeof(huf->c_freq[0]) * NC);
	memset(huf->p_freq, 0, sizeof(huf->p_freq[0]) * huf->val.NP);
	huf->output_pos = huf->output_mask = 0;
}

static void
sta_huf_encode_finish(struct lha_stream *strm)
{
	send_block(strm);
	putbits(CHAR_BIT - 1, 0, strm);  /* flush remaining bits */
}


struct tree {
	int		 nn;
	int16_t		 heap[NC + 1];
	uint16_t	*freq;
	uint16_t	*sortptr;
	uint16_t	 len_cnt[17];
	unsigned char	*len;
	uint16_t	*left;
	uint16_t	*right;
	int		 depth;
};

static void
count_len(int i, struct tree *tp)  /* call with i = root */
{
	if (i < tp->nn)
		tp->len_cnt[(tp->depth < 16) ? tp->depth : 16]++;
	else {
		tp->depth++;
		count_len(tp->left [i], tp);
		count_len(tp->right[i], tp);
		tp->depth--;
	}
}

static void
make_len(int root, struct tree *tp)
{
	int i, k;
	uint cum;

	for (i = 0; i <= 16; i++)
		tp->len_cnt[i] = 0;
	count_len(root, tp);
	cum = 0;
	for (i = 16; i > 0; i--)
		cum += tp->len_cnt[i] << (16 - i);
	while (cum != (1U << 16)) {
		tp->len_cnt[16]--;
		for (i = 15; i > 0; i--) {
			if (tp->len_cnt[i] != 0) {
				tp->len_cnt[i]--;
				tp->len_cnt[i+1] += 2;
				break;
			}
		}
		cum--;
	}
	for (i = 16; i > 0; i--) {
		k = tp->len_cnt[i];
		while (--k >= 0)
			tp->len[*tp->sortptr++] = i;
	}
}

/* priority queue; send i-th entry down heap */
static void
downheap(int i, int heapsize, struct tree *tp)
{
	int j, k;

	k = tp->heap[i];
	while ((j = 2 * i) <= heapsize) {
		if (j < heapsize &&
		    tp->freq[tp->heap[j]] > tp->freq[tp->heap[j + 1]])
		 	j++;
		if (tp->freq[k] <= tp->freq[tp->heap[j]]) break;
		tp->heap[i] = tp->heap[j];  i = j;
	}
	tp->heap[i] = k;
}

static void
make_code(int n, unsigned char len[], uint16_t code[], struct tree *tp)
{
	int    i;
	uint16_t start[18];

	start[1] = 0;
	for (i = 1; i <= 16; i++)
		start[i + 1] = (start[i] + tp->len_cnt[i]) << 1;
	for (i = 0; i < n; i++)
		code[i] = start[len[i]]++;
}

static int
lha_make_tree(int nparm, uint16_t freqparm[], unsigned char lenparm[],
    uint16_t codeparm[], struct huf_work *hw)
{
	struct tree treedat;
	struct tree *tp;
	int i, j, k, avail;
	int heapsize;

	tp = &treedat;
	tp->nn = nparm;  tp->freq = freqparm;  tp->len = lenparm;
	avail = tp->nn;  heapsize = 0;  tp->heap[1] = 0;
	tp->left = hw->left;
	tp->right =hw-> right;
	tp->depth = 0;

	for (i = 0; i < tp->nn; i++) {
		tp->len[i] = 0;
		if (tp->freq[i])
			tp->heap[++heapsize] = i;
	}
	if (heapsize < 2) {
		codeparm[tp->heap[1]] = 0;
		return (tp->heap[1]);
	}
	for (i = heapsize / 2; i >= 1; i--)
		downheap(i, heapsize, tp);  /* make priority queue */
	tp->sortptr = codeparm;
	do {  /* while queue has at least two entries */
		i = tp->heap[1];  /* take out least-freq entry */
		if (i < tp->nn)
			*tp->sortptr++ = i;
		tp->heap[1] = tp->heap[heapsize--];
		downheap(1, heapsize, tp);
		j = tp->heap[1];  /* next least-freq entry */
		if (j < tp->nn)
			*tp->sortptr++ = j;
		k = avail++;  /* generate new node */
		tp->freq[k] = tp->freq[i] + tp->freq[j];
		tp->heap[1] = k;
		downheap(1, heapsize, tp);  /* put into queue */
		hw->left[k] = i;
		hw->right[k] = j;
	} while (heapsize > 1);
	tp->sortptr = codeparm;
	make_len(k, tp);
	make_code(nparm, lenparm, codeparm, tp);
	return (k);  /* return root */
}


