/*-
 * Copyright (c) 2003-2011 Tim Kientzle
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

#include "archive_platform.h"
__FBSDID("$FreeBSD: head/lib/libarchive/archive_string.c 201095 2009-12-28 02:33:22Z kientzle $");

/*
 * Basic resizable string support, to simplify manipulating arbitrary-sized
 * strings while minimizing heap activity.
 *
 * In particular, the buffer used by a string object is only grown, it
 * never shrinks, so you can clear and reuse the same string object
 * without incurring additional memory allocations.
 */

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#ifdef HAVE_ICONV_H
#include <iconv.h>
#endif
#ifdef HAVE_LANGINFO_H
#include <langinfo.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_WCHAR_H
#include <wchar.h>
#endif
#if defined(_WIN32) && !defined(__CYGWIN__)
#include <windows.h>
#include <locale.h>
#endif

#include "archive_endian.h"
#include "archive_private.h"
#include "archive_string.h"


struct archive_string_conv {
	struct archive_string_conv	*next;
	char				*from_charset;
	char				*to_charset;
#if defined(_WIN32) && !defined(__CYGWIN__)
	UINT				 from_cp;
	UINT				 to_cp;
#endif
	/* Set 1 if from_charset and to_charset are the same. */
	int				 same;
	int				 flag;
#define SCONV_TO_CHARSET	1/* MBS is being converted to specified charset. */
#define SCONV_FROM_CHARSET	2/* MBS is being converted from specified charset. */
#define SCONV_BEST_EFFORT 	4/* Copy at least ASCII code. */
#define SCONV_WIN_CP	 	8/* Use Windows API for converting MBS. */
#define SCONV_UTF16BE	 	16/* Consideration to UTF-16BE; one side is
				   * 'char', ohter is like 'int16_t'. */

#if HAVE_ICONV
	iconv_t				 cd;
#endif
};

static struct archive_string_conv *find_sconv_object(struct archive *,
	const char *, const char *);
static void add_sconv_object(struct archive *, struct archive_string_conv *);
static struct archive_string_conv *create_sconv_object(const char *,
	const char *, unsigned, int);
static void free_sconv_object(struct archive_string_conv *);
static struct archive_string_conv *get_sconv_object(struct archive *,
	const char *, const char *, int);
#if defined(_WIN32) && !defined(__CYGWIN__)
static unsigned make_codepage_from_charset(const char *);
static unsigned get_current_codepage();
#endif
static int strncpy_from_utf16be(struct archive_string *, const void *, size_t,
    struct archive_string_conv *);
static int strncpy_to_utf16be(struct archive_string *, const void *, size_t,
    struct archive_string_conv *);
static int best_effort_strncat_in_locale(struct archive_string *, const void *,
    size_t, struct archive_string_conv *);

static struct archive_string *
archive_string_append(struct archive_string *as, const char *p, size_t s)
{
	if (archive_string_ensure(as, as->length + s + 1) == NULL)
		__archive_errx(1, "Out of memory");
	memcpy(as->s + as->length, p, s);
	as->length += s;
	as->s[as->length] = 0;
	return (as);
}

static struct archive_wstring *
archive_wstring_append(struct archive_wstring *as, const wchar_t *p, size_t s)
{
	if (archive_wstring_ensure(as, as->length + s + 1) == NULL)
		__archive_errx(1, "Out of memory");
	memcpy(as->s + as->length, p, s * sizeof(wchar_t));
	as->length += s;
	as->s[as->length] = 0;
	return (as);
}

void
archive_string_concat(struct archive_string *dest, struct archive_string *src)
{
	archive_string_append(dest, src->s, src->length);
}

void
archive_wstring_concat(struct archive_wstring *dest, struct archive_wstring *src)
{
	archive_wstring_append(dest, src->s, src->length);
}

void
archive_string_free(struct archive_string *as)
{
	as->length = 0;
	as->buffer_length = 0;
	free(as->s);
	as->s = NULL;
}

void
archive_wstring_free(struct archive_wstring *as)
{
	as->length = 0;
	as->buffer_length = 0;
	free(as->s);
	as->s = NULL;
}

struct archive_wstring *
archive_wstring_ensure(struct archive_wstring *as, size_t s)
{
	return (struct archive_wstring *)
		archive_string_ensure((struct archive_string *)as,
					s * sizeof(wchar_t));
}

/* Returns NULL on any allocation failure. */
struct archive_string *
archive_string_ensure(struct archive_string *as, size_t s)
{
	char *p;
	size_t new_length;

	/* If buffer is already big enough, don't reallocate. */
	if (as->s && (s <= as->buffer_length))
		return (as);

	/*
	 * Growing the buffer at least exponentially ensures that
	 * append operations are always linear in the number of
	 * characters appended.  Using a smaller growth rate for
	 * larger buffers reduces memory waste somewhat at the cost of
	 * a larger constant factor.
	 */
	if (as->buffer_length < 32)
		/* Start with a minimum 32-character buffer. */
		new_length = 32;
	else if (as->buffer_length < 8192)
		/* Buffers under 8k are doubled for speed. */
		new_length = as->buffer_length + as->buffer_length;
	else {
		/* Buffers 8k and over grow by at least 25% each time. */
		new_length = as->buffer_length + as->buffer_length / 4;
		/* Be safe: If size wraps, fail. */
		if (new_length < as->buffer_length) {
			/* On failure, wipe the string and return NULL. */
			archive_string_free(as);
			return (NULL);
		}
	}
	/*
	 * The computation above is a lower limit to how much we'll
	 * grow the buffer.  In any case, we have to grow it enough to
	 * hold the request.
	 */
	if (new_length < s)
		new_length = s;
	/* Now we can reallocate the buffer. */
	p = (char *)realloc(as->s, new_length);
	if (p == NULL) {
		/* On failure, wipe the string and return NULL. */
		archive_string_free(as);
		return (NULL);
	}

	as->s = p;
	as->buffer_length = new_length;
	return (as);
}

/*
 * TODO: See if there's a way to avoid scanning
 * the source string twice.  Then test to see
 * if it actually helps (remember that we're almost
 * always called with pretty short arguments, so
 * such an optimization might not help).
 */
struct archive_string *
archive_strncat(struct archive_string *as, const void *_p, size_t n)
{
	size_t s;
	const char *p, *pp;

	p = (const char *)_p;

	/* Like strlen(p), except won't examine positions beyond p[n]. */
	s = 0;
	pp = p;
	while (s < n && *pp) {
		pp++;
		s++;
	}
	return (archive_string_append(as, p, s));
}

struct archive_wstring *
archive_wstrncat(struct archive_wstring *as, const wchar_t *p, size_t n)
{
	size_t s;
	const wchar_t *pp;

	/* Like strlen(p), except won't examine positions beyond p[n]. */
	s = 0;
	pp = p;
	while (s < n && *pp) {
		pp++;
		s++;
	}
	return (archive_wstring_append(as, p, s));
}

struct archive_string *
archive_strcat(struct archive_string *as, const void *p)
{
	/* strcat is just strncat without an effective limit. 
	 * Assert that we'll never get called with a source
	 * string over 16MB.
	 * TODO: Review all uses of strcat in the source
	 * and try to replace them with strncat().
	 */
	return archive_strncat(as, p, 0x1000000);
}

struct archive_wstring *
archive_wstrcat(struct archive_wstring *as, const wchar_t *p)
{
	/* Ditto. */
	return archive_wstrncat(as, p, 0x1000000);
}

struct archive_string *
archive_strappend_char(struct archive_string *as, char c)
{
	return (archive_string_append(as, &c, 1));
}

struct archive_wstring *
archive_wstrappend_wchar(struct archive_wstring *as, wchar_t c)
{
	return (archive_wstring_append(as, &c, 1));
}

/*
 * Get the "current character set" name to use with iconv.
 * On FreeBSD, the empty character set name "" chooses
 * the correct character encoding for the current locale,
 * so this isn't necessary.
 * But iconv on Mac OS 10.6 doesn't seem to handle this correctly;
 * on that system, we have to explicitly call nl_langinfo()
 * to get the right name.  Not sure about other platforms.
 */
static const char *
default_iconv_charset(const char *charset) {
	if (charset != NULL && charset[0] != '\0')
		return charset;
#if HAVE_NL_LANGINFO
	return nl_langinfo(CODESET);
#else
	return "";
#endif
}

#if defined(_WIN32) && !defined(__CYGWIN__)

/*
 * Convert MBS to WCS.
 * Note: returns -1 if conversion fails.
 */
int
archive_wstring_append_from_mbs(struct archive *a,
    struct archive_wstring *dest, const char *p, size_t len)
{
	size_t r;
	/*
	 * No single byte will be more than one wide character,
	 * so this length estimate will always be big enough.
	 */
	size_t wcs_length = len;
	if (NULL == archive_wstring_ensure(dest, dest->length + wcs_length + 1))
		__archive_errx(1,
		    "No memory for archive_wstring_append_from_mbs()");

	r = MultiByteToWideChar(get_current_codepage(), 0,
	    p, (int)len, dest->s + dest->length, (int)wcs_length);
	if (r > 0) {
		dest->length += r;
		dest->s[dest->length] = 0;
		return (0);
	}
	return (-1);
}

#else

/*
 * Convert MBS to WCS.
 * Note: returns -1 if conversion fails.
 */
int
archive_wstring_append_from_mbs(struct archive *a,
    struct archive_wstring *dest, const char *p, size_t len)
{
	size_t r;
	/*
	 * No single byte will be more than one wide character,
	 * so this length estimate will always be big enough.
	 */
	size_t wcs_length = len;
	size_t mbs_length = len;
	const char *mbs = p;
	wchar_t *wcs;
#if HAVE_MBRTOWC || HAVE_MBSNRTOWCS
	mbstate_t shift_state;

	memset(&shift_state, 0, sizeof(shift_state));
#endif
	if (NULL == archive_wstring_ensure(dest, dest->length + wcs_length + 1))
		__archive_errx(1,
		    "No memory for archive_wstring_append_from_mbs()");
	wcs = dest->s + dest->length;
#if HAVE_MBSNRTOWCS
	r = mbsnrtowcs(wcs, &mbs, mbs_length, wcs_length, &shift_state);
	if (r != (size_t)-1) {
		dest->length += r;
		dest->s[dest->length] = L'\0';
		return (0);
	}
	return (-1);
#else /* HAVE_MBSNRTOWCS */
	/*
	 * We cannot use mbsrtowcs/mbstowcs here because those may convert
	 * extra MBS when strlen(p) > len and one wide character consis of
	 * multi bytes.
	 */
	while (wcs_length > 0 && *mbs && mbs_length > 0) {
#if HAVE_MBRTOWC
		r = mbrtowc(wcs, mbs, wcs_length, &shift_state);
#else
		r = mbtowc(wcs, mbs, wcs_length);
#endif
		if (r == (size_t)-1 || r == (size_t)-2) {
			dest->s[dest->length] = L'\0';
			return (-1);
		}
		if (r == 0 || r > mbs_length)
			break;
		wcs++;
		wcs_length--;
		mbs += r;
		mbs_length -= r;
	}
	dest->length = wcs - dest->s;
	dest->s[dest->length] = L'\0';
	return (0);
#endif /* HAVE_MBSNRTOWCS */
}

#endif

#if defined(_WIN32) && !defined(__CYGWIN__)

/*
 * WCS ==> MBS.
 * Note: returns -1 if conversion fails.
 *
 * Win32 builds use WideCharToMultiByte from the Windows API.
 * (Maybe Cygwin should too?  WideCharToMultiByte will know a
 * lot more about local character encodings than the wcrtomb()
 * wrapper is going to know.)
 */
int
archive_string_append_from_unicode_to_mbs(struct archive *a,
    struct archive_string *as, const wchar_t *w, size_t len)
{
	char *p;
	int l;
	BOOL useDefaultChar = FALSE;

	/* TODO: XXX use codepage preference from a XXX */
	(void)a; /* UNUSED */


	l = len * 4 + 4;
	p = malloc(l);
	if (p == NULL)
		__archive_errx(1, "Out of memory");
	/* To check a useDefaultChar is to simulate error handling of
	 * the my_wcstombs() which is running on non Windows system with
	 * wctomb().
	 * And to set NULL for last argument is necessary when a codepage
	 * is not current locale.
	 */
	l = WideCharToMultiByte(get_current_codepage(), 0,
	    w, len, p, l, NULL, &useDefaultChar);
	if (l == 0) {
		free(p);
		return (-1);
	}
	archive_string_append(as, p, l);
	free(p);
	return (0);
}

#elif defined(HAVE_WCTOMB) || defined(HAVE_WCRTOMB)

/*
 * Translates a wide character string into current locale character set
 * and appends to the archive_string.  Note: returns -1 if conversion
 * fails.
 */
int
archive_string_append_from_unicode_to_mbs(struct archive *a,
    struct archive_string *as, const wchar_t *w, size_t len)
{
	/* We cannot use the standard wcstombs() here because it
	 * cannot tell us how big the output buffer should be.  So
	 * I've built a loop around wcrtomb() or wctomb() that
	 * converts a character at a time and resizes the string as
	 * needed.  We prefer wcrtomb() when it's available because
	 * it's thread-safe. */
	int n;
	char *p;
	char buff[256];
#if HAVE_WCRTOMB
	mbstate_t shift_state;

	memset(&shift_state, 0, sizeof(shift_state));
#else
	/* Clear the shift state before starting. */
	wctomb(NULL, L'\0');
#endif

	/*
	 * Convert one wide char at a time into 'buff', whenever that
	 * fills, append it to the string.
	 */
	p = buff;
	while (*w != L'\0') {
		/* Flush the buffer when we have <=16 bytes free. */
		/* (No encoding has a single character >16 bytes.) */
		if ((size_t)(p - buff) >= (size_t)(sizeof(buff) - MB_CUR_MAX)) {
			*p = '\0';
			archive_strcat(as, buff);
			p = buff;
		}
#if HAVE_WCRTOMB
		n = wcrtomb(p, *w++, &shift_state);
#else
		n = wctomb(p, *w++);
#endif
		if (n == -1)
			return (-1);
		p += n;
	}
	*p = '\0';
	archive_strcat(as, buff);
	return (0);
}

#else /* HAVE_WCTOMB || HAVE_WCRTOMB */

/*
 * TODO: Test if __STDC_ISO_10646__ is defined.
 * Non-Windows uses ISO C wcrtomb() or wctomb() to perform the conversion
 * one character at a time.  If a non-Windows platform doesn't have
 * either of these, fall back to the built-in UTF8 conversion.
 */
int
archive_string_append_from_unicode_to_mbs(struct archive *a,
    struct archive_string *as, const wchar_t *w, size_t len)
{
	return (-1);
}

#endif /* HAVE_WCTOMB || HAVE_WCRTOMB */


static struct archive_string_conv *
find_sconv_object(struct archive *a, const char *fc, const char *tc)
{
	struct archive_string_conv *sc; 

	if (a == NULL)
		return (NULL);

	for (sc = a->sconv; sc != NULL; sc = sc->next) {
		if (strcmp(sc->from_charset, fc) == 0 &&
		    strcmp(sc->to_charset, tc) == 0)
			break;
	}
	return (sc);
}

static void
add_sconv_object(struct archive *a, struct archive_string_conv *sc)
{
	struct archive_string_conv **psc; 

	/* Add a new sconv to sconv list. */
	psc = &(a->sconv);
	while (*psc != NULL)
		psc = &((*psc)->next);
	*psc = sc;
}

static struct archive_string_conv *
create_sconv_object(const char *fc, const char *tc,
    unsigned current_codepage, int flag)
{
	struct archive_string_conv *sc; 

	sc = malloc(sizeof(*sc));
	if (sc == NULL)
		__archive_errx(1, "No memory for charset conversion object");
	sc->next = NULL;
	sc->from_charset = strdup(fc);
	if (sc->from_charset == NULL)
		__archive_errx(1, "No memory for charset conversion object");
	sc->to_charset = strdup(tc);
	if (sc->to_charset == NULL)
		__archive_errx(1, "No memory for charset conversion object");
	sc->same = (strcmp(fc, tc) == 0)?1:0;
#if HAVE_ICONV
	sc->cd = iconv_open(tc, fc);
#endif
	sc->flag = flag;
#if defined(_WIN32) && !defined(__CYGWIN__)
	if (flag & SCONV_TO_CHARSET) {
		sc->from_cp = current_codepage;
		sc->to_cp = make_codepage_from_charset(tc);
	} else if (flag & SCONV_FROM_CHARSET) {
		sc->to_cp = current_codepage;
		sc->from_cp = make_codepage_from_charset(fc);
	}
#endif

	return (sc);
}

static void
free_sconv_object(struct archive_string_conv *sc)
{
	free(sc->from_charset);
	free(sc->to_charset);
#if HAVE_ICONV
	if (sc->cd != (iconv_t)-1)
		iconv_close(sc->cd);
#endif
	free(sc);
}

#if defined(_WIN32) && !defined(__CYGWIN__)
static unsigned
my_atoi(const char *p)
{
	unsigned cp;

	cp = 0;
	while (*p) {
		if (*p >= '0' && *p <= '9')
			cp = cp * 10 + (*p - '0');
		else
			return (-1);
		p++;
	}
	return (cp);
}

#define CP_UTF16LE	1200
#define CP_UTF16BE	1201

/*
 * Translate Charset into CodePage.
 * Return -1 if failed.
 *
 * Note: This translation code may be insufficient.
 */
static unsigned
make_codepage_from_charset(const char *charset)
{
	char *cs = strdup(charset);
	char *p;
	unsigned cp;

	p = cs;
	while (*p) {
		if (*p >= 'a' && *p <= 'z')
			*p -= 'a' - 'A';
		p++;
	}
	cp = -1;
	switch (*cs) {
	case 'A':
		if (strcmp(cs, "ASCII") == 0)
			cp = 1252;
		break;
	case 'B':
		if (strcmp(cs, "BIG5") == 0)
			cp = 950;
		break;
	case 'C':
		if (cs[1] == 'P' && cs[2] >= '0' && cs[2] <= '9') {
			cp = my_atoi(cs + 2);
			switch (cp) {
			case 367:
			case 819:
				cp = 1252;
				break;
			}
		} else if (strcmp(cs, "CP_ACP") == 0)
			cp = GetACP();
		else if (strcmp(cs, "CP_OEMCP") == 0)
			cp = GetOEMCP();
		break;
	case 'E':
		if (strcmp(cs, "EUCJP") == 0)
			cp = 51932;
		else if (strcmp(cs, "EUCCN") == 0)
			cp = 51936;
		else if (strcmp(cs, "EUCKR") == 0)
			cp = 949;
		break;
	case 'G':
		if (strcmp(cs, "GB2312") == 0)
			cp = 936;
		break;
	case 'I':
		if (cs[1] == 'B' && cs[2] == 'M' &&
		    cs[3] >= '0' && cs[3] <= '9') {
			cp = my_atoi(cs + 3);
			switch (cp) {
			case 367:
			case 819:
				cp = 1252;
				break;
			}
		} else if (strncmp(cs, "ISO8859-", 8) == 0) {
			if (cs[8] == '1' && cs[9] == '\0')
				cp = 1252;
			else if (cs[8] == '2' && cs[9] == '\0')
				cp = 28592;
			else if (cs[8] == '8' && cs[9] == '\0')
				cp = 1255;
		} else if (strncmp(cs, "ISO_8859-", 9) == 0) {
			if (cs[9] == '1' && cs[10] == '\0')
				cp = 1252;
			else if (cs[9] == '2' && cs[10] == '\0')
				cp = 28592;
			else if (cs[9] == '8' && cs[10] == '\0')
				cp = 1255;
		}
		break;
	case 'L':
		if (strcmp(cs, "LATIN1") == 0)
			cp = 1252;
		else if (strcmp(cs, "LATIN2") == 0)
			cp = 28592;
		break;
	case 'S':
		if (strcmp(cs, "SHIFT_JIS") == 0 ||
		    strcmp(cs, "SHIFT-JIS") == 0 ||
		    strcmp(cs, "SJIS") == 0)
			cp = 932;
		break;
	case 'U':
		if (strcmp(cs, "US") == 0)
			cp = 1252;
		else if (strcmp(cs, "US-ASCII") == 0)
			cp = 1252;
		else if (strcmp(cs, "UTF-8") == 0)
			cp = CP_UTF8;
		else if (strcmp(cs, "UTF-16") == 0 ||
		    strcmp(cs, "UTF-16LE") == 0)
			cp = CP_UTF16LE;
		else if (strcmp(cs, "UTF-16BE") == 0)
			cp = CP_UTF16BE;
		break;
	case 'W':
		if (strncmp(cs, "WINDOWS-", 8) == 0) {
			cp = my_atoi(cs + 8);
			if (cp != 874 && (cp < 1250 || cp > 1258))
				cp = -1;/* This may invalid code. */
		}
		break;
	}

	free(cs);
	return (cp);
}

/*
 * Return the current codepage.
 */
static unsigned
get_current_codepage()
{
	unsigned codepage;

	_locale_t locale = _get_current_locale();
	codepage = locale->locinfo->lc_codepage;
	_free_locale(locale);
	return (codepage);
}
#endif /* defined(_WIN32) && !defined(__CYGWIN__) */

static struct archive_string_conv *
get_sconv_object(struct archive *a, const char *fc, const char *tc, int flag)
{
	struct archive_string_conv *sc;
	unsigned current_codepage;

	sc = find_sconv_object(a, fc, tc);
	if (sc != NULL)
		return (sc);

	if (a == NULL)
#if defined(_WIN32) && !defined(__CYGWIN__)
		current_codepage = get_current_codepage();
#else
		current_codepage = -1;
#endif
	else
		current_codepage = a->current_codepage;
	sc = create_sconv_object(fc, tc, current_codepage, flag);
#if HAVE_ICONV
	if (sc->cd == (iconv_t)-1 && (flag & SCONV_BEST_EFFORT) == 0) {
		free_sconv_object(sc);
		archive_set_error(a, ARCHIVE_ERRNO_MISC,
		    "iconv_open failed : Cannot convert "
		    "string to %s", tc);
		return (NULL);
	} else if (a != NULL)
		add_sconv_object(a, sc);
#else /* HAVE_ICONV */
#if defined(_WIN32) && !defined(__CYGWIN__)
	/*
	 * Windows platform can convert a string in current locale from/to
	 * UTF-8 and UTF-16BE.
	 */
	if (flag & SCONV_TO_CHARSET) {
		if (sc->to_cp == CP_UTF16BE) {
			sc->flag |= SCONV_UTF16BE;
			if (a != NULL)
				add_sconv_object(a, sc);
			return (sc);
		}
		if (sc->from_cp == sc->to_cp)
			sc->same = 1;
		else if (IsValidCodePage(sc->to_cp)) {
			sc->flag |= SCONV_WIN_CP;
			if (a != NULL)
				add_sconv_object(a, sc);
			return (sc);
		}
	} else if (flag & SCONV_FROM_CHARSET) {
		if (sc->from_cp == CP_UTF16BE) {
			sc->flag |= SCONV_UTF16BE;
			if (a != NULL)
				add_sconv_object(a, sc);
			return (sc);
		}
		if (sc->to_cp == sc->from_cp)
			sc->same = 1;
		else if (IsValidCodePage(sc->from_cp)) {
			sc->flag |= SCONV_WIN_CP;
			if (a != NULL)
				add_sconv_object(a, sc);
			return (sc);
		}
	}
#endif
	if (!sc->same && (flag & SCONV_BEST_EFFORT) == 0) {
		free_sconv_object(sc);
		archive_set_error(a, ARCHIVE_ERRNO_MISC,
		    "A character-set conversion not fully supported "
		    "on this platform");
		return (NULL);
	} else if (a != NULL)
		add_sconv_object(a, sc);
#endif /* HAVE_ICONV */

	if (((flag & SCONV_TO_CHARSET) != 0 && strcmp(tc, "UTF-16BE") == 0) ||
	    ((flag & SCONV_FROM_CHARSET) != 0 && strcmp(fc, "UTF-16BE") == 0))
		sc->flag |= SCONV_UTF16BE;

	return (sc);
}

static const char *
get_current_charset(struct archive *a)
{
	const char *cur_charset;

	if (a == NULL)
		cur_charset = default_iconv_charset("");
	else {
		cur_charset = default_iconv_charset(a->current_code);
		if (a->current_code == NULL) {
			a->current_code = strdup(cur_charset);
#if defined(_WIN32) && !defined(__CYGWIN__)
			a->current_codepage = get_current_codepage();
#endif
		}
	}
	return (cur_charset);
}

/*
 * Make and Return a string conversion object.
 * Return NULL if the platform does not support the specified conversion
 * and best_effort is 0.
 * If best_effort is set, A string conversion object must be returned
 * but the conversion might fail when non-ASCII code is found.
 */
struct archive_string_conv *
archive_string_conversion_to_charset(struct archive *a, const char *charset,
    int best_effort)
{
	int flag = SCONV_TO_CHARSET;

	if (best_effort)
		flag |= SCONV_BEST_EFFORT;
	return (get_sconv_object(a, get_current_charset(a), charset, flag));
}

struct archive_string_conv *
archive_string_conversion_from_charset(struct archive *a, const char *charset,
    int best_effort)
{
	int flag = SCONV_FROM_CHARSET;

	if (best_effort)
		flag |= SCONV_BEST_EFFORT;
	return (get_sconv_object(a, charset, get_current_charset(a), flag));
}

/*
 * Dispose of all character conversion objects in the archive object.
 */
void
archive_string_conversion_free(struct archive *a)
{
	struct archive_string_conv *sc; 
	struct archive_string_conv *sc_next; 

	for (sc = a->sconv; sc != NULL; sc = sc_next) {
		sc_next = sc->next;
		free_sconv_object(sc);
	}
	a->sconv = NULL;
	free(a->current_code);
	a->current_code = NULL;
}

/*
 * Return a conversion charset name.
 */
const char *
archive_string_conversion_charset_name(struct archive_string_conv *sc)
{
	if (sc->flag & SCONV_TO_CHARSET)
		return (sc->to_charset);
	else
		return (sc->from_charset);
}

/*
 *
 * Copy one archive_string to another in locale conversion.
 *
 *	archive_strncpy_in_locale();
 *	archive_strcpy_in_locale();
 *
 */

static size_t
la_strnlen(const void *_p, size_t n)
{
	size_t s;
	const char *p, *pp;

	if (_p == NULL)
		return (0);
	p = (const char *)_p;

	/* Like strlen(p), except won't examine positions beyond p[n]. */
	s = 0;
	pp = p;
	while (s < n && *pp) {
		pp++;
		s++;
	}
	return (s);
}

int
archive_strncpy_in_locale(struct archive_string *as, const void *_p, size_t n,
    struct archive_string_conv *sc)
{
	as->length = 0;
	if (sc != NULL && (sc->flag & SCONV_UTF16BE)) {
		if (sc->flag & SCONV_TO_CHARSET)
			return (strncpy_to_utf16be(as, _p, n, sc));
		else
			return (strncpy_from_utf16be(as, _p, n, sc));
	}
	return (archive_strncat_in_locale(as, _p, n, sc));
}


#if HAVE_ICONV

/*
 * Return -1 if conversion failes.
 */
int
archive_strncat_in_locale(struct archive_string *as, const void *_p, size_t n,
    struct archive_string_conv *sc)
{
	ICONV_CONST char *inp;
	size_t remaining;
	iconv_t cd;
	const char *src = _p;
	char *outp;
	size_t avail, length;
	int return_value = 0; /* success */

	length = la_strnlen(_p, n);
	/* If sc is NULL, we just make a copy without conversion. */
	if (sc == NULL) {
		archive_string_append(as, src, length);
		return (0);
	}

	archive_string_ensure(as, as->length + length*2+1);

	cd = sc->cd;
	if (cd == (iconv_t)-1)
		return (best_effort_strncat_in_locale(as, _p, n, sc));

	inp = (char *)(uintptr_t)src;
	remaining = length;
	outp = as->s + as->length;
	avail = as->buffer_length -1;
	while (remaining > 0) {
		size_t result = iconv(cd, &inp, &remaining, &outp, &avail);

		if (result != (size_t)-1) {
			*outp = '\0';
			as->length = outp - as->s;
			break; /* Conversion completed. */
		} else if (errno == EILSEQ || errno == EINVAL) {
			/* Skip the illegal input bytes. */
			*outp++ = '?';
			avail--;
			inp++;
			remaining--;
			return_value = -1; /* failure */
		} else {
			/* E2BIG no output buffer,
			 * Increase an output buffer.  */
			as->length = outp - as->s;
			archive_string_ensure(as, as->buffer_length * 2);
			outp = as->s + as->length;
			avail = as->buffer_length - as->length -1;
		}
	}
	return (return_value);
}

#else /* HAVE_ICONV */

/*
 * Basically returns -1 because we cannot make a conversion of charset.
 * Returns 0 if sc is NULL.
 */
int
archive_strncat_in_locale(struct archive_string *as, const void *_p, size_t n,
    struct archive_string_conv *sc)
{
	return (best_effort_strncat_in_locale(as, _p, n, sc));
}

#endif /* HAVE_ICONV */


#if defined(_WIN32) && !defined(__CYGWIN__)

/*
 * Convert a UTF-8 string from/to current locale and copy the result.
 * Return -1 if conversion failes.
 */
static int
strncat_in_codepage(struct archive_string *as,
    const char *s, size_t length, struct archive_string_conv *sc)
{
	int count, wslen;
	wchar_t *ws;
	BOOL defchar, *dp;
	UINT from_cp, to_cp;
	DWORD mbflag;

	if (s == NULL || length == 0) {
		/* We must allocate memory even if there is no data.
		 * It simulates archive_string_append behavior. */
		if (archive_string_ensure(as, as->length + 1) == NULL)
			__archive_errx(1, "Out of memory");
		as->s[as->length] = 0;
		return (0);
	}

	from_cp = sc->from_cp;
	to_cp = sc->to_cp;
	if (sc->flag & SCONV_FROM_CHARSET)
		mbflag = 0;
	else
		mbflag = MB_PRECOMPOSED;

	count = MultiByteToWideChar(from_cp,
	    mbflag, s, length, NULL, 0);
	if (count == 0) {
		archive_string_append(as, s, length);
		return (-1);
	}
	ws = malloc(sizeof(*ws) * (count+1));
	if (ws == NULL)
		__archive_errx(0, "No memory");
	count = MultiByteToWideChar(from_cp,
	    mbflag, s, length, ws, count);
	ws[count] = L'\0';
	wslen = count;

	count = WideCharToMultiByte(to_cp, 0, ws, wslen,
	    NULL, 0, NULL, NULL);
	if (count == 0) {
		free(ws);
		archive_string_append(as, s, length);
		return (-1);
	}
	defchar = 0;
	if (to_cp == CP_UTF8)
		dp = NULL;
	else
		dp = &defchar;
	archive_string_ensure(as, as->length + count +1);
	count = WideCharToMultiByte(to_cp, 0, ws, wslen,
	    as->s + as->length, count, NULL, dp);
	as->length += count;
	as->s[as->length] = '\0';
	free(ws);
	return (defchar?-1:0);
}

/*
 * Test whether MBS ==> WCS is okay.
 */
static int
invalid_mbs(const void *_p, size_t n, struct archive_string_conv *sc)
{
	const char *p = (const char *)_p;
	unsigned codepage;
	DWORD mbflag = MB_ERR_INVALID_CHARS;

	if (sc->flag & SCONV_FROM_CHARSET)
		codepage = sc->to_cp;
	else
		codepage = sc->from_cp;
	if (codepage != CP_UTF8)
		mbflag |= MB_PRECOMPOSED;

	if (MultiByteToWideChar(codepage, mbflag, p, n, NULL, 0) == 0)
		return (-1); /* Invalid */
	return (0); /* Okay */
}

#else

/*
 * Test whether MBS ==> WCS is okay.
 */
static int
invalid_mbs(const void *_p, size_t n, struct archive_string_conv *sc)
{
	const char *p = (const char *)_p;
	size_t r;

	(void)sc; /* UNUSED */
#if HAVE_MBRTOWC
	mbstate_t shift_state;

	memset(&shift_state, 0, sizeof(shift_state));
#else
	/* Clear the shift state before starting. */
	mbtowc(NULL, NULL, 0);
#endif
	while (n) {
		wchar_t wc;

#if HAVE_MBRTOWC
		r = mbrtowc(&wc, p, n, &shift_state);
#else
		r = mbtowc(&wc, p, n);
#endif
		if (r == (size_t)-1 || r == (size_t)-2)
			return (-1);/* Invalid. */
		if (r == 0)
			break;
		p += r;
		n -= r;
	}
	return (0); /* All Okey. */
}

#endif /* defined(_WIN32) && !defined(__CYGWIN__) */

/*
 * Test that MBS consists of ASCII code only.
 */
static int
is_all_ascii_code(struct archive_string *as)
{
	size_t i;

	for (i = 0; i < as->length; i++)
		if (((unsigned char)as->s[i]) > 0x7f)
			return (0);
	/* It seems the string we have checked is all ASCII code. */
	return (1);
}

/*
 * Basically returns -1 because we cannot make a conversion of charset.
 * Returns 0 if sc is NULL.
 */
static int
best_effort_strncat_in_locale(struct archive_string *as, const void *_p, size_t n,
    struct archive_string_conv *sc)
{
	size_t length = la_strnlen(_p, n);

#if defined(_WIN32) && !defined(__CYGWIN__)
	if (sc != NULL && (sc->flag & SCONV_WIN_CP) != 0)
		return (strncat_in_codepage(as, _p, length, sc));
#endif
	archive_string_append(as, _p, length);
	/* If charset is NULL, just make a copy, so return 0 as success. */
	if (sc == NULL || (sc->same && invalid_mbs(_p, n, sc) == 0))
		return (0);
	if (is_all_ascii_code(as))
		return (0);
	return (-1);
}



/*
 * Conversion functions between local locale MBS and UTF-16BE.
 *   strncpy_from_utf16be() : UTF-16BE --> MBS
 *   strncpy_to_utf16be()   : MBS --> UTF16BE
 */
#if defined(_WIN32) && !defined(__CYGWIN__)

/*
 * Convert a UTF-16BE string to current locale and copy the result.
 * Return -1 if conversion failes.
 */
static int
strncpy_from_utf16be(struct archive_string *as, const void *_p, size_t bytes,
    struct archive_string_conv *sc)
{
	const char *utf16 = (const char *)_p;
	int ll;
	BOOL defchar;
	char *mbs;
	size_t mbs_size;
	int ret = 0;

	archive_string_empty(as);
	bytes &= ~1;
	archive_string_ensure(as, bytes+1);
	mbs = as->s;
	mbs_size = as->buffer_length-1;
	while (bytes) {
		uint16_t val = archive_be16dec(utf16);
		ll = WideCharToMultiByte(sc->to_cp, 0,
		    (LPCWSTR)&val, 1, mbs, mbs_size,
			NULL, &defchar);
		if (ll == 0) {
			*mbs = '\0';
			return (-1);
		} else if (defchar)
			ret = -1;
		as->length += ll;
		mbs += ll;
		mbs_size -= ll;
		bytes -= 2;
		utf16 += 2;
	}
	*mbs = '\0';
	return (ret);
}

static int
is_big_endian()
{
	uint16_t d = 1;

	return (archive_be16dec(&d) == 1);
}

/*
 * Convert a current locale string to UTF-16BE and copy the result.
 * Return -1 if conversion failes.
 */
static int
strncpy_to_utf16be(struct archive_string *a16be, const void *_p, size_t length,
    struct archive_string_conv *sc)
{
	const char *s = (const char *)_p;
	size_t count;

	archive_string_ensure(a16be, (length + 1) * 2);
	archive_string_empty(a16be);
	do {
		count = MultiByteToWideChar(sc->from_cp,
		    MB_PRECOMPOSED, s, length,
		    (LPWSTR)a16be->s, (int)a16be->buffer_length - 2);
		if (count == 0 &&
		    GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
			/* Need more buffer for UTF-16 string */
			count = MultiByteToWideChar(sc->from_cp,
			    MB_PRECOMPOSED, s, length, NULL, 0);
			archive_string_ensure(a16be, (count +1) * 2);
			continue;
		}
		if (count == 0)
			return (-1);
	} while (0);
	a16be->length = count * 2;
	a16be->s[a16be->length] = 0;
	a16be->s[a16be->length+1] = 0;

	if (!is_big_endian()) {
		char *s = a16be->s;
		size_t l = a16be->length;
		while (l > 0) {
			uint16_t v = archive_le16dec(s);
			archive_be16enc(s, v);
			s += 2;
			l -= 2;
		}
	}
	return (0);
}

#elif HAVE_ICONV

/*
 * Convert a UTF-16BE string to current locale and copy the result.
 * Return -1 if conversion failes.
 */
static int
strncpy_from_utf16be(struct archive_string *as, const void *_p, size_t bytes,
    struct archive_string_conv *sc)
{
	ICONV_CONST char *inp;
	const char *utf16 = (const char *)_p;
	size_t remaining;
	iconv_t cd;
	char *outp;
	size_t avail, outbase;
	int return_value = 0; /* success */

	archive_string_empty(as);

	bytes &= ~1;
	archive_string_ensure(as, bytes+1);

	cd = sc->cd;
	inp = (char *)(uintptr_t)utf16;
	remaining = bytes;
	outp = as->s;
	avail = outbase = bytes;
	while (remaining > 0) {
		size_t result = iconv(cd, &inp, &remaining, &outp, &avail);

		if (result != (size_t)-1) {
			*outp = '\0';
			as->length = outbase - avail;
			break; /* Conversion completed. */
		} else if (errno == EILSEQ || errno == EINVAL) {
			/* Skip the illegal input bytes. */
			*outp++ = '?';
			avail --;
			inp += 2;
			remaining -= 2;
			return_value = -1; /* failure */
		} else {
			/* E2BIG no output buffer,
			 * Increase an output buffer.  */
			as->length = outbase - avail;
			outbase *= 2;
			archive_string_ensure(as, outbase+1);
			outp = as->s + as->length;
			avail = outbase - as->length;
		}
	}
	return (return_value);
}

/*
 * Convert a current locale string to UTF-16BE and copy the result.
 * Return -1 if conversion failes.
 */
static int
strncpy_to_utf16be(struct archive_string *a16be, const void *_p,
    size_t length, struct archive_string_conv *sc)
{
	ICONV_CONST char *inp;
	const char *src = (const char *)_p;
	size_t remaining;
	iconv_t cd;
	char *outp;
	size_t avail, outbase;
	int return_value = 0; /* success */

	archive_string_empty(a16be);

	archive_string_ensure(a16be, (length+1)*2);

	cd = sc->cd;
	inp = (char *)(uintptr_t)src;
	remaining = length;
	outp = a16be->s;
	avail = outbase = length * 2;
	while (remaining > 0) {
		size_t result = iconv(cd, &inp, &remaining, &outp, &avail);

		if (result != (size_t)-1) {
			outp[0] = 0; outp[1] = 0;
			a16be->length = outbase - avail;
			break; /* Conversion completed. */
		} else if (errno == EILSEQ || errno == EINVAL) {
			/* Skip the illegal input bytes. */
			*outp++ = 0; *outp++ = '?';
			avail -= 2;
			inp ++;
			remaining --;
			return_value = -1; /* failure */
		} else {
			/* E2BIG no output buffer,
			 * Increase an output buffer.  */
			a16be->length = outbase - avail;
			outbase *= 2;
			archive_string_ensure(a16be, outbase+2);
			outp = a16be->s + a16be->length;
			avail = outbase - a16be->length;
		}
	}
	return (return_value);
}

#else

/*
 * In case the platform does not have iconv nor other character-set
 * conversion functions, We cannot handle UTF-16BE character-set,
 * but there is a chance if a string consists just ASCII code or
 * a current locale is UTF-8.
 *
 */

/*
 * UTF-16BE to UTF-8.
 * Note: returns non-zero if conversion fails, but still leaves a best-effort
 * conversion in the argument as.
 */
static int
string_append_from_utf16be_to_utf8(struct archive_string *as,
    const char *utf16be, size_t bytes)
{
	char *p, *end;
	unsigned uc;
	size_t base_size;
	int return_val = 0; /* success */

	bytes &= ~1;
	archive_string_ensure(as, bytes+1);
	base_size = as->buffer_length;
	p = as->s + as->length;
	end = as->s + as->buffer_length -1;
	while (bytes >= 2) {
		/* Expand the buffer when we have <4 bytes free. */
		if (end - p < 4) {
			size_t l = p - as->s;
			base_size *= 2;
			archive_string_ensure(as, base_size);
			p = as->s + l;
			end = as->s + as->buffer_length -1;
		}

		uc = archive_be16dec(utf16be);
		utf16be += 2; bytes -=2;
		
		/* If this is a surrogate pair, assemble the full code point.*/
		if (uc >= 0xD800 && uc <= 0xDBff) {
			if (bytes < 2) {
				/* Wrong sequence. */
				*p++ = '?';
				return_val = -1;
				break;
			}
			unsigned utf16_next = archive_be16dec(utf16be);
			if (utf16_next >= 0xDC00 && utf16_next <= 0xDFFF) {
				uc -= 0xD800;
				uc *= 0x400;
				uc += (utf16_next - 0xDC00);
				uc += 0x10000;
				utf16be += 2; bytes -=2;
			}
		}
		/* Translate code point to UTF8 */
		if (uc <= 0x7f) {
			*p++ = (char)uc;
		} else if (uc <= 0x7ff) {
			*p++ = 0xc0 | ((uc >> 6) & 0x1f);
			*p++ = 0x80 | (uc & 0x3f);
		} else if (uc <= 0xffff) {
			*p++ = 0xe0 | ((uc >> 12) & 0x0f);
			*p++ = 0x80 | ((uc >> 6) & 0x3f);
			*p++ = 0x80 | (uc & 0x3f);
		} else if (uc <= 0x1fffff) {
			*p++ = 0xf0 | ((uc >> 18) & 0x07);
			*p++ = 0x80 | ((uc >> 12) & 0x3f);
			*p++ = 0x80 | ((uc >> 6) & 0x3f);
			*p++ = 0x80 | (uc & 0x3f);
		} else {
			/* Unicode has no codes larger than 0x1fffff. */
			/* TODO: use \uXXXX escape here instead of ? */
			*p++ = '?';
			return_val = -1;
		}
	}
	as->length = p - as->s;
	*p = '\0';
	return (return_val);
}

/*
 * Utility to convert a single UTF-8 sequence.
 */
static int
utf8_to_unicode(int *pwc, const char *s, size_t n)
{
        int ch;

        /*
	 * Decode 1-4 bytes depending on the value of the first byte.
	 */
        ch = (unsigned char)*s;
	if (ch == 0) {
		return (0); /* Standard:  return 0 for end-of-string. */
	}
	if ((ch & 0x80) == 0) {
                *pwc = ch & 0x7f;
		return (1);
        }
	if ((ch & 0xe0) == 0xc0) {
		if (n < 2)
			return (-1);
		if ((s[1] & 0xc0) != 0x80) return (-1);
                *pwc = ((ch & 0x1f) << 6) | (s[1] & 0x3f);
		return (2);
        }
	if ((ch & 0xf0) == 0xe0) {
		if (n < 3)
			return (-1);
		if ((s[1] & 0xc0) != 0x80) return (-1);
		if ((s[2] & 0xc0) != 0x80) return (-1);
                *pwc = ((ch & 0x0f) << 12)
		    | ((s[1] & 0x3f) << 6)
		    | (s[2] & 0x3f);
		return (3);
        }
	if ((ch & 0xf8) == 0xf0) {
		if (n < 4)
			return (-1);
		if ((s[1] & 0xc0) != 0x80) return (-1);
		if ((s[2] & 0xc0) != 0x80) return (-1);
		if ((s[3] & 0xc0) != 0x80) return (-1);
                *pwc = ((ch & 0x07) << 18)
		    | ((s[1] & 0x3f) << 12)
		    | ((s[2] & 0x3f) << 6)
		    | (s[3] & 0x3f);
		return (4);
        }
	/* Invalid first byte. */
	return (-1);
}

/*
 * Return a UTF-16BE string by converting this archive_string from UTF-8.
 * Returns 0 on success, non-zero if conversion fails.
 */
static int
string_append_from_utf8_to_utf16be(struct archive_string *as,
    const char *p, size_t len)
{
	char *s, *end;
	size_t base_size;
	int wc, wc2;/* Must be large enough for a 21-bit Unicode code point. */
	int n;
	int return_val = 0; /* success */

	archive_string_ensure(as, (len+1)*2);
	base_size = as->buffer_length;
	s = as->s + as->length;
	end = as->s + as->buffer_length -2;
	while (len > 0) {
		/* Expand the buffer when we have <4 bytes free. */
		if (end - s < 4) {
			size_t l = p - as->s;
			base_size *= 2;
			archive_string_ensure(as, base_size);
			s = as->s + l;
			end = as->s + as->buffer_length -2;
		}
		n = utf8_to_unicode(&wc, p, len);
		if (n == 0)
			break;
		if (n < 0) {
			return (-1);
		}
		p += n;
		len -= n;
		if (wc >= 0xDC00 && wc <= 0xDBFF) {
			/* This is a leading surrogate; some idiot
			 * has translated UTF16 to UTF8 without combining
			 * surrogates; rebuild the full code point before
			 * continuing. */
			n = utf8_to_unicode(&wc2, p, len);
			if (n < 0) {
				return_val = -1;
				break;
			}
			if (n == 0) /* Ignore the leading surrogate */
				break;
			if (wc2 < 0xDC00 || wc2 > 0xDFFF) {
				/* If the second character isn't a
				 * trailing surrogate, then someone
				 * has really screwed up and this is
				 * invalid. */
				return_val = -1;
				break;
			} else {
				p += n;
				len -= n;
				wc -= 0xD800;
				wc *= 0x400;
				wc += wc2 - 0xDC00;
				wc += 0x10000;
			}
		}
		if (wc > 0xffff) {
			/* We have a code point that won't fit into a
			 * wchar_t; convert it to a surrogate pair. */
			wc -= 0x10000;
			archive_be16enc(s, ((wc >> 10) & 0x3ff) + 0xD800);
			archive_be16enc(s+2, (wc & 0x3ff) + 0xDC00);
			s += 4;
		} else {
			archive_be16enc(s, wc);
			s += 2;
		}
	}
	as->length = s - as->s;
	*s++ = 0; *s = 0;
	return (return_val);
}

/*
 * Convert a UTF-16BE string to current locale and copy the result.
 * Return -1 if conversion failes.
 */
static int
strncpy_from_utf16be(struct archive_string *as, const void *_p, size_t bytes,
    struct archive_string_conv *sc)
{
	const char *utf16 = (const char *)_p;
	char *mbs;
	int ret;

	archive_string_empty(as);

	/*
	 * If the current locale is UTF-8, we can translate a UTF-16BE
	 * string into a UTF-8 string.
	 */
	if (strcmp(sc->to_charset, "UTF-8") == 0)
		return (string_append_from_utf16be_to_utf8(as, utf16, bytes));

	/*
	 * Other case, we should do the best effort.
	 * If all character are ASCII(<0x7f), we can convert it.
	 * if not , we set a alternative character and return -1.
	 */
	ret = 0;
	bytes &= ~1;
	archive_string_ensure(as, bytes+1);
	mbs = as->s;
	while (bytes) {
		uint16_t val = archive_be16dec(utf16);
		if (val >= 0x80) {
			/* We cannot handle it. */
			*mbs++ = '?';
			ret =  -1;
		} else
			*mbs++ = (char)val;
		as->length ++;
		bytes -= 2;
		utf16 += 2;
	}
	*mbs = '\0';
	return (ret);
}

/*
 * Convert a current locale string to UTF-16BE and copy the result.
 * Return -1 if conversion failes.
 */
static int
strncpy_to_utf16be(struct archive_string *a16be, const void *_p, size_t length,
    struct archive_string_conv *sc)
{
	const char *s = (const char *)_p;
	char *utf16;
	size_t remaining;
	int ret;

	archive_string_empty(a16be);

	/*
	 * If the current locale is UTF-8, we can translate a UTF-8
	 * string into a UTF-16BE string.
	 */
	if (strcmp(sc->from_charset, "UTF-8") == 0)
		return (string_append_from_utf8_to_utf16be(a16be, s, length));

	/*
	 * Other case, we should do the best effort.
	 * If all character are ASCII(<0x7f), we can convert it.
	 * if not , we set a alternative character and return -1.
	 */
	ret = 0;
	remaining = length;
	archive_string_ensure(a16be, (length + 1) * 2);
	utf16 = a16be->s;
	while (remaining--) {
		if (*(unsigned char *)s >= 0x80) {
			/* We cannot handle it. */
			*utf16++ = 0;
			*utf16++ = '?';
			ret = -1;
		} else {
			*utf16++ = 0;
			*utf16++ = *s++;
		}
		a16be->length += 2;
	}
	a16be->s[a16be->length] = 0;
	a16be->s[a16be->length+1] = 0;
	return (ret);
}

#endif


/*
 * Multistring operations.
 */

void
archive_mstring_clean(struct archive_mstring *aes)
{
	archive_wstring_free(&(aes->aes_wcs));
	archive_string_free(&(aes->aes_mbs));
	archive_string_free(&(aes->aes_utf8));
	aes->aes_set = 0;
}

void
archive_mstring_copy(struct archive_mstring *dest, struct archive_mstring *src)
{
	dest->aes_set = src->aes_set;
	archive_string_copy(&(dest->aes_mbs), &(src->aes_mbs));
	archive_string_copy(&(dest->aes_utf8), &(src->aes_utf8));
	archive_wstring_copy(&(dest->aes_wcs), &(src->aes_wcs));
}

const char *
archive_mstring_get_utf8(struct archive *a, struct archive_mstring *aes)
{
	struct archive_string_conv *sc;
	int r;

	/* If we already have a UTF8 form, return that immediately. */
	if (aes->aes_set & AES_SET_UTF8)
		return (aes->aes_utf8.s);

	if (aes->aes_set & AES_SET_MBS) {
		sc = archive_string_conversion_to_charset(a, "UTF-8", 1);
		r = archive_strncpy_in_locale(&(aes->aes_mbs), aes->aes_mbs.s,
		    aes->aes_mbs.length, sc);
		if (a == NULL)
			free_sconv_object(sc);
		if (r == 0) {
			aes->aes_set |= AES_SET_UTF8;
			return (aes->aes_utf8.s);
		}
	}
	return (NULL);
}

const char *
archive_mstring_get_mbs(struct archive *a, struct archive_mstring *aes)
{
	struct archive_string_conv *sc;
	int r;

	/* If we already have an MBS form, return that immediately. */
	if (aes->aes_set & AES_SET_MBS)
		return (aes->aes_mbs.s);
	/* If there's a WCS form, try converting with the native locale. */
	if ((aes->aes_set & AES_SET_WCS)
	    && archive_string_append_from_unicode_to_mbs(a, &(aes->aes_mbs),
			aes->aes_wcs.s, aes->aes_wcs.length) == 0) {
		aes->aes_set |= AES_SET_MBS;
		return (aes->aes_mbs.s);
	}
	/* If there's a UTF-8 form, try converting with the native locale. */
	if (aes->aes_set & AES_SET_UTF8) {
		sc = archive_string_conversion_from_charset(a, "UTF-8", 1);
		r = archive_strncpy_in_locale(&(aes->aes_mbs),
			aes->aes_utf8.s, aes->aes_utf8.length, sc);
		if (a == NULL)
			free_sconv_object(sc);
		if (r == 0) {
			aes->aes_set |= AES_SET_UTF8;
			return (aes->aes_utf8.s);
		}
	}
	return (NULL);
}

const wchar_t *
archive_mstring_get_wcs(struct archive *a, struct archive_mstring *aes)
{
	/* Return WCS form if we already have it. */
	if (aes->aes_set & AES_SET_WCS)
		return (aes->aes_wcs.s);
	/* Try converting MBS to WCS using native locale. */
	if ((aes->aes_set & AES_SET_MBS)
	    && 0 == archive_wstring_append_from_mbs(a, &(aes->aes_wcs),
			aes->aes_mbs.s, aes->aes_mbs.length)) {
		aes->aes_set |= AES_SET_WCS;
		return (aes->aes_wcs.s);
	}
	return (NULL);
}

int
archive_mstring_copy_mbs(struct archive_mstring *aes, const char *mbs)
{
	if (mbs == NULL) {
		aes->aes_set = 0;
		return (0);
	}
	return (archive_mstring_copy_mbs_len(aes, mbs, strlen(mbs)));
}

int
archive_mstring_copy_mbs_len(struct archive_mstring *aes, const char *mbs,
    size_t len)
{
	if (mbs == NULL) {
		aes->aes_set = 0;
		return (0);
	}
	aes->aes_set = AES_SET_MBS; /* Only MBS form is set now. */
	archive_strncpy(&(aes->aes_mbs), mbs, len);
	archive_string_empty(&(aes->aes_utf8));
	archive_wstring_empty(&(aes->aes_wcs));
	return (0);
}

int
archive_mstring_copy_wcs(struct archive_mstring *aes, const wchar_t *wcs)
{
	return archive_mstring_copy_wcs_len(aes, wcs, wcs == NULL ? 0 : wcslen(wcs));
}

int
archive_mstring_copy_wcs_len(struct archive_mstring *aes, const wchar_t *wcs,
    size_t len)
{
	if (wcs == NULL) {
		aes->aes_set = 0;
	}
	aes->aes_set = AES_SET_WCS; /* Only WCS form set. */
	archive_string_empty(&(aes->aes_mbs));
	archive_string_empty(&(aes->aes_utf8));
	archive_wstrncpy(&(aes->aes_wcs), wcs, len);
	return (0);
}

/*
 * The 'update' form tries to proactively update all forms of
 * this string (WCS and MBS) and returns an error if any of
 * them fail.  This is used by the 'pax' handler, for instance,
 * to detect and report character-conversion failures early while
 * still allowing clients to get potentially useful values from
 * the more tolerant lazy conversions.  (get_mbs and get_wcs will
 * strive to give the user something useful, so you can get hopefully
 * usable values even if some of the character conversions are failing.)
 */
/* TODO: Reverse the return values here so that zero is success. */
int
archive_mstring_update_utf8(struct archive *a, struct archive_mstring *aes,
    const char *utf8)
{
	struct archive_string_conv *sc;
	int r;

	if (utf8 == NULL) {
		aes->aes_set = 0;
		return (1); /* Succeeded in clearing everything. */
	}

	/* Save the UTF8 string. */
	archive_strcpy(&(aes->aes_utf8), utf8);

	/* Empty the mbs and wcs strings. */
	archive_string_empty(&(aes->aes_mbs));
	archive_wstring_empty(&(aes->aes_wcs));

	aes->aes_set = AES_SET_UTF8;	/* Only UTF8 is set now. */

	/* Try converting UTF-8 to MBS, return false on failure. */
	sc = archive_string_conversion_from_charset(a, "UTF-8", 1);
	r = archive_strcpy_in_locale(&(aes->aes_mbs), utf8, sc);
	if (a == NULL)
		free_sconv_object(sc);
	if (r != 0)
		return (0);
	aes->aes_set = AES_SET_UTF8 | AES_SET_MBS; /* Both UTF8 and MBS set. */

	/* Try converting MBS to WCS, return false on failure. */
	if (archive_wstring_append_from_mbs(a, &(aes->aes_wcs), aes->aes_mbs.s,
	    aes->aes_utf8.length))
		return (0);
	aes->aes_set = AES_SET_UTF8 | AES_SET_WCS | AES_SET_MBS;

	/* All conversions succeeded. */
	return (1);
}
