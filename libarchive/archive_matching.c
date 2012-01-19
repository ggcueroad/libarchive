/*-
 * Copyright (c) 2003-2007 Tim Kientzle
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
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif

#include "archive.h"
#include "archive_private.h"
#include "archive_entry.h"
#include "archive_pathmatch.h"
#include "archive_rb.h"
#include "archive_string.h"

struct match {
	struct match		*next;
	int			 matches;
	struct archive_mstring	 pattern;
};

struct match_list {
	struct match		*first;
	struct match		**last;
	int			 count;
	int			 unmatched_count;
	struct match		*unmatched_next;
	int			 unmatched_eof;
};

struct newer_file {
	struct archive_rb_node	 node;
	struct newer_file	*next;
	struct archive_mstring	 pathname;
	time_t			 mtime_sec;
	long			 mtime_nsec;
};

struct newer_file_list {
	struct newer_file	*first;
	struct newer_file	**last;
	int			 count;
};

struct id_array {
	size_t			 size;/* Allocated size */
	size_t			 count;
	int64_t			*ids;
};

#define PATTERN_IS_SET		1
#define TIME_IS_SET		2
#define ID_IS_SET		4

struct archive_matching {
	struct archive		 archive;

	/* exclusion/inclusion set flag. */
	int			 setflag;

	/*
	 * Matching filename patterns.
	 */
	struct match_list	 exclusions;
	struct match_list	 inclusions;

	/*
	 * Matching time stamps.
	 */
	int			 newer_mtime_filter;
	time_t			 newer_mtime_sec;
	long			 newer_mtime_nsec;
	int			 newer_ctime_filter;
	time_t			 newer_ctime_sec;
	long			 newer_ctime_nsec;
	int			 older_mtime_filter;
	time_t			 older_mtime_sec;
	long			 older_mtime_nsec;
	int			 older_ctime_filter;
	time_t			 older_ctime_sec;
	long			 older_ctime_nsec;
	/*
	 * Matching time stamps with its filename.
	 */
	struct archive_rb_tree	 newer_tree;
	struct newer_file_list 	 newer_list;

	/*
	 * Matching file owners.
	 */
	struct id_array 	 inclusion_uids;
	struct id_array 	 inclusion_gids;
	struct match_list	 inclusion_unames;
	struct match_list	 inclusion_gnames;
};

static int	add_newer_mtime_pathname(struct archive_matching *, int,
		    const void *, time_t sec, long nsec);
static int	add_owner_id(struct archive_matching *, struct id_array *,
		    int64_t);
static int	add_owner_name(struct archive_matching *, struct match_list *,
		    int, const void *);
static int	add_pattern_mbs(struct archive_matching *, struct match_list *,
		    const char *);
static int	add_pattern_wcs(struct archive_matching *, struct match_list *,
		    const wchar_t *);
static int	cmp_key_mbs(const struct archive_rb_node *, const void *);
static int	cmp_key_wcs(const struct archive_rb_node *, const void *);
static int	cmp_node_mbs(const struct archive_rb_node *,
		    const struct archive_rb_node *);
static int	cmp_node_wcs(const struct archive_rb_node *,
		    const struct archive_rb_node *);
static int	error_nomem(struct archive_matching *);
static int	get_filetime_mbs(struct archive_matching *, const char *,
		    int, time_t *, long *);
static int	get_filetime_wcs(struct archive_matching *, const wchar_t *,
		    int, time_t *, long *);
static void	match_list_add(struct match_list *, struct match *);
static void	match_list_free(struct match_list *);
static void	match_list_init(struct match_list *);
static int	match_list_unmatched_inclusions_next(struct archive_matching *,
		    struct match_list *, int, const void **);
static int	match_owner_id(struct id_array *, int64_t);
#if !defined(_WIN32) || defined(__CYGWIN__)
static int	match_owner_name_mbs(struct archive_matching *,
		    struct match_list *, const char *);
#else
static int	match_owner_name_wcs(struct archive_matching *,
		    struct match_list *, const wchar_t *);
#endif
static int	match_path_exclusion(struct archive_matching *,
		    struct match *, int, const void *);
static int	match_path_inclusion(struct archive_matching *,
		    struct match *, int, const void *);
static void	newer_file_list_add(struct newer_file_list *,
		    struct newer_file *);
static void	newer_file_list_free(struct newer_file_list *);
static void	newer_file_list_init(struct newer_file_list *);
static int	owner_excluded(struct archive_matching *,
		    struct archive_entry *);
static int	path_excluded(struct archive_matching *, int, const void *);
static int	time_excluded(struct archive_matching *,
		    struct archive_entry *);

static const struct archive_rb_tree_ops rb_ops_mbs = {
	cmp_node_mbs, cmp_key_mbs
};

static const struct archive_rb_tree_ops rb_ops_wcs = {
	cmp_node_wcs, cmp_key_wcs
};

/*
 * The matching logic here needs to be re-thought.  I started out to
 * try to mimic gtar's matching logic, but it's not entirely
 * consistent.  In particular 'tar -t' and 'tar -x' interpret patterns
 * on the command line as anchored, but --exclude doesn't.
 */

static int
error_nomem(struct archive_matching *a)
{
	archive_set_error(&(a->archive), ENOMEM, "No memory");
	a->archive.state = ARCHIVE_STATE_FATAL;
	return (ARCHIVE_FATAL);
}

struct archive *
archive_matching_new(void)
{
	struct archive_matching *a;

	a = (struct archive_matching *)calloc(1, sizeof(*a));
	if (a == NULL)
		return (NULL);
	a->archive.magic = ARCHIVE_MATCHING_MAGIC;
	a->archive.state = ARCHIVE_STATE_NEW;
	match_list_init(&(a->inclusions));
	match_list_init(&(a->exclusions));
	__archive_rb_tree_init(&(a->newer_tree), &rb_ops_mbs);
	newer_file_list_init(&(a->newer_list));
	match_list_init(&(a->inclusion_unames));
	match_list_init(&(a->inclusion_gnames));
	return (&(a->archive));
}

int
archive_matching_free(struct archive *_a)
{
	struct archive_matching *a;

	if (_a == NULL)
		return (ARCHIVE_OK);
	archive_check_magic(_a, ARCHIVE_MATCHING_MAGIC,
	    ARCHIVE_STATE_ANY | ARCHIVE_STATE_FATAL, "archive_matching_free");
	a = (struct archive_matching *)_a;
	match_list_free(&(a->inclusions));
	match_list_free(&(a->exclusions));
	newer_file_list_free(&(a->newer_list));
	free(a->inclusion_uids.ids);
	free(a->inclusion_gids.ids);
	match_list_free(&(a->inclusion_unames));
	match_list_free(&(a->inclusion_gnames));
	free(a);
	return (ARCHIVE_OK);
}

/*
 * Convenience function to perform all exclusion tests.
 *
 * Returns 1 if archive entry is excluded.
 * Returns 0 if archive entry is not excluded.
 * Returns <0 if something error happened.
 */
int
archive_matching_excluded(struct archive *_a, struct archive_entry *entry)
{
	struct archive_matching *a;
	int r;

	archive_check_magic(_a, ARCHIVE_MATCHING_MAGIC,
	    ARCHIVE_STATE_NEW, "archive_matching_excluded_ae");

	a = (struct archive_matching *)_a;
	if (entry == NULL) {
		archive_set_error(&(a->archive), EINVAL, "entry is NULL");
		return (ARCHIVE_FAILED);
	}

	r = 0;
	if (a->setflag & PATTERN_IS_SET) {
#if defined(_WIN32) && !defined(__CYGWIN__)
		r = path_excluded(a, 0, archive_entry_pathname_w(entry));
#else
		r = path_excluded(a, 1, archive_entry_pathname(entry));
#endif
		if (r != 0)
			return (r);
	}

	if (a->setflag & TIME_IS_SET) {
		r = time_excluded(a, entry);
		if (r != 0)
			return (r);
	}

	if (a->setflag & ID_IS_SET)
		r = owner_excluded(a, entry);
	return (r);
}

/*
 * Utility functions to manage exclusion/inclusion patterns
 */

int
archive_matching_exclude_pattern(struct archive *_a, const char *pattern)
{
	struct archive_matching *a;
	int r;

	archive_check_magic(_a, ARCHIVE_MATCHING_MAGIC,
	    ARCHIVE_STATE_NEW, "archive_matching_exclude_pattern");
	a = (struct archive_matching *)_a;

	if (pattern == NULL || *pattern == '\0') {
		archive_set_error(&(a->archive), EINVAL, "pattern is empty");
		return (ARCHIVE_FAILED);
	}
	if ((r = add_pattern_mbs(a, &(a->exclusions), pattern)) != ARCHIVE_OK)
		return (r);
	return (ARCHIVE_OK);
}

int
archive_matching_exclude_pattern_w(struct archive *_a, const wchar_t *pattern)
{
	struct archive_matching *a;
	int r;

	archive_check_magic(_a, ARCHIVE_MATCHING_MAGIC,
	    ARCHIVE_STATE_NEW, "archive_matching_exclude_pattern_w");
	a = (struct archive_matching *)_a;

	if (pattern == NULL || *pattern == L'\0') {
		archive_set_error(&(a->archive), EINVAL, "pattern is empty");
		return (ARCHIVE_FAILED);
	}
	if ((r = add_pattern_wcs(a, &(a->exclusions), pattern)) != ARCHIVE_OK)
		return (r);
	return (ARCHIVE_OK);
}

int
archive_matching_include_pattern(struct archive *_a, const char *pattern)
{
	struct archive_matching *a;
	int r;

	archive_check_magic(_a, ARCHIVE_MATCHING_MAGIC,
	    ARCHIVE_STATE_NEW, "archive_matching_include_pattern");
	a = (struct archive_matching *)_a;

	if (pattern == NULL || *pattern == '\0') {
		archive_set_error(&(a->archive), EINVAL, "pattern is empty");
		return (ARCHIVE_FAILED);
	}
	if ((r = add_pattern_mbs(a, &(a->inclusions), pattern)) != ARCHIVE_OK)
		return (r);
	return (ARCHIVE_OK);
}

int
archive_matching_include_pattern_w(struct archive *_a, const wchar_t *pattern)
{
	struct archive_matching *a;
	int r;

	archive_check_magic(_a, ARCHIVE_MATCHING_MAGIC,
	    ARCHIVE_STATE_NEW, "archive_matching_include_pattern_w");
	a = (struct archive_matching *)_a;

	if (pattern == NULL || *pattern == L'\0') {
		archive_set_error(&(a->archive), EINVAL, "pattern is empty");
		return (ARCHIVE_FAILED);
	}
	if ((r = add_pattern_wcs(a, &(a->inclusions), pattern)) != ARCHIVE_OK)
		return (r);
	return (ARCHIVE_OK);
}

/*
 * Test functions for pathname patterns.
 *
 * Returns 1 if archive entry is excluded.
 * Returns 0 if archive entry is not excluded.
 * Returns <0 if something error happened.
 */
int
archive_matching_path_excluded(struct archive *_a,
    struct archive_entry *entry)
{
	struct archive_matching *a;

	archive_check_magic(_a, ARCHIVE_MATCHING_MAGIC,
	    ARCHIVE_STATE_NEW, "archive_matching_path_excluded");

	a = (struct archive_matching *)_a;
	if (entry == NULL) {
		archive_set_error(&(a->archive), EINVAL, "entry is NULL");
		return (ARCHIVE_FAILED);
	}

	/* If we don't have exclusion/inclusion pattern set at all,
	 * the entry is always not excluded. */
	if ((a->setflag & PATTERN_IS_SET) == 0)
		return (0);
#if defined(_WIN32) && !defined(__CYGWIN__)
	return (path_excluded(a, 0, archive_entry_pathname_w(entry)));
#else
	return (path_excluded(a, 1, archive_entry_pathname(entry)));
#endif
}

/*
 * Utilty functions to get statistic information for inclusion patterns.
 */
int
archive_matching_path_unmatched_inclusions(struct archive *_a)
{
	struct archive_matching *a;

	archive_check_magic(_a, ARCHIVE_MATCHING_MAGIC,
	    ARCHIVE_STATE_NEW, "archive_matching_unmatched_inclusions");
	a = (struct archive_matching *)_a;

	return (a->inclusions.unmatched_count);
}

int
archive_matching_path_unmatched_inclusions_next(struct archive *_a,
    const char **_p)
{
	struct archive_matching *a;
	const void *v;
	int r;

	archive_check_magic(_a, ARCHIVE_MATCHING_MAGIC,
	    ARCHIVE_STATE_NEW, "archive_matching_unmatched_inclusions_next");
	a = (struct archive_matching *)_a;

	r = match_list_unmatched_inclusions_next(a, &(a->inclusions), 1, &v);
	*_p = (const char *)v;
	return (r);
}

int
archive_matching_path_unmatched_inclusions_next_w(struct archive *_a,
    const wchar_t **_p)
{
	struct archive_matching *a;
	const void *v;
	int r;

	archive_check_magic(_a, ARCHIVE_MATCHING_MAGIC,
	    ARCHIVE_STATE_NEW, "archive_matching_unmatched_inclusions_next_w");
	a = (struct archive_matching *)_a;

	r = match_list_unmatched_inclusions_next(a, &(a->inclusions), 0, &v);
	*_p = (const wchar_t *)v;
	return (r);
}

static int
add_pattern_mbs(struct archive_matching *a, struct match_list *list,
    const char *pattern)
{
	struct match *match;
	size_t len;

	match = calloc(1, sizeof(*match));
	if (match == NULL)
		return (error_nomem(a));
	/* Both "foo/" and "foo" should match "foo/bar". */
	len = strlen(pattern);
	if (len && pattern[len - 1] == '/')
		--len;
	archive_mstring_copy_mbs_len(&(match->pattern), pattern, len);
	match_list_add(list, match);
	a->setflag |= PATTERN_IS_SET;
	return (ARCHIVE_OK);
}

static int
add_pattern_wcs(struct archive_matching *a, struct match_list *list,
    const wchar_t *pattern)
{
	struct match *match;
	size_t len;

	match = calloc(1, sizeof(*match));
	if (match == NULL)
		return (error_nomem(a));
	/* Both "foo/" and "foo" should match "foo/bar". */
	len = wcslen(pattern);
	if (len && pattern[len - 1] == L'/')
		--len;
	archive_mstring_copy_wcs_len(&(match->pattern), pattern, len);
	match_list_add(list, match);
	a->setflag |= PATTERN_IS_SET;
	return (ARCHIVE_OK);
}

static int
path_excluded(struct archive_matching *a, int mbs, const void *pathname)
{
	struct match *match;
	struct match *matched;
	int r;

	if (a == NULL)
		return (0);

	/* Mark off any unmatched inclusions. */
	/* In particular, if a filename does appear in the archive and
	 * is explicitly included and excluded, then we don't report
	 * it as missing even though we don't extract it.
	 */
	matched = NULL;
	for (match = a->inclusions.first; match != NULL;
	    match = match->next){
		if (match->matches == 0
		    && (r = match_path_inclusion(a, match, mbs, pathname))) {
			if (r < 0)
				return (r);
			a->inclusions.unmatched_count--;
			match->matches++;
			matched = match;
		}
	}

	/* Exclusions take priority */
	for (match = a->exclusions.first; match != NULL;
	    match = match->next){
		r = match_path_exclusion(a, match, mbs, pathname);
		if (r)
			return (r);
	}

	/* It's not excluded and we found an inclusion above, so it's
	 * included. */
	if (matched != NULL)
		return (0);


	/* We didn't find an unmatched inclusion, check the remaining ones. */
	for (match = a->inclusions.first; match != NULL;
	    match = match->next){
		/* We looked at previously-unmatched inclusions already. */
		if (match->matches > 0
		    && (r = match_path_inclusion(a, match, mbs, pathname))) {
			if (r < 0)
				return (r);
			match->matches++;
			return (0);
		}
	}

	/* If there were inclusions, default is to exclude. */
	if (a->inclusions.first != NULL)
	    return (1);

	/* No explicit inclusions, default is to match. */
	return (0);
}

/*
 * This is a little odd, but it matches the default behavior of
 * gtar.  In particular, 'a*b' will match 'foo/a1111/222b/bar'
 *
 */
static int
match_path_exclusion(struct archive_matching *a, struct match *m,
    int mbs, const void *pn)
{
	int flag = PATHMATCH_NO_ANCHOR_START | PATHMATCH_NO_ANCHOR_END;
	int r;

	if (mbs) {
		const char *p;
		r = archive_mstring_get_mbs(&(a->archive), &(m->pattern), &p);
		if (r == 0)
			return (archive_pathmatch(p, (const char *)pn, flag));
	} else {
		const wchar_t *p;
		r = archive_mstring_get_wcs(&(a->archive), &(m->pattern), &p);
		if (r == 0)
			return (archive_pathmatch_w(p, (const wchar_t *)pn,
				flag));
	}
	if (errno == ENOMEM)
		return (error_nomem(a));
	return (0);
}

/*
 * Again, mimic gtar:  inclusions are always anchored (have to match
 * the beginning of the path) even though exclusions are not anchored.
 */
static int
match_path_inclusion(struct archive_matching *a, struct match *m,
    int mbs, const void *pn)
{
	int flag = PATHMATCH_NO_ANCHOR_END;
	int r;

	if (mbs) {
		const char *p;
		r = archive_mstring_get_mbs(&(a->archive), &(m->pattern), &p);
		if (r == 0)
			return (archive_pathmatch(p, (const char *)pn, flag));
	} else {
		const wchar_t *p;
		r = archive_mstring_get_wcs(&(a->archive), &(m->pattern), &p);
		if (r == 0)
			return (archive_pathmatch_w(p, (const wchar_t *)pn,
				flag));
	}
	if (errno == ENOMEM)
		return (error_nomem(a));
	return (0);
}

static void
match_list_init(struct match_list *list)
{
	list->first = NULL;
	list->last = &(list->first);
	list->count = 0;
}

static void
match_list_free(struct match_list *list)
{
	struct match *p, *q;

	for (p = list->first; p != NULL; ) {
		q = p;
		p = p->next;
		archive_mstring_clean(&(q->pattern));
		free(q);
	}
}

static void
match_list_add(struct match_list *list, struct match *m)
{
	*list->last = m;
	list->last = &(m->next);
	list->count++;
	list->unmatched_count++;
}

static int
match_list_unmatched_inclusions_next(struct archive_matching *a,
    struct match_list *list, int mbs, const void **vp)
{
	struct match *m;

	*vp = NULL;
	if (list->unmatched_eof) {
		list->unmatched_eof = 0;
		return (ARCHIVE_EOF);
	}
	if (list->unmatched_next == NULL) {
		if (list->unmatched_count == 0)
			return (ARCHIVE_EOF);
		list->unmatched_next = list->first;
	}

	for (m = list->unmatched_next; m != NULL; m = m->next) {
		int r;

		if (m->matches)
			continue;
		if (mbs) {
			const char *p;
			r = archive_mstring_get_mbs(&(a->archive),
				&(m->pattern), &p);
			if (r < 0 && errno == ENOMEM)
				return (error_nomem(a));
			if (p == NULL)
				p = "";
			*vp = p;
		} else {
			const wchar_t *p;
			r = archive_mstring_get_wcs(&(a->archive),
				&(m->pattern), &p);
			if (r < 0 && errno == ENOMEM)
				return (error_nomem(a));
			if (p == NULL)
				p = L"";
			*vp = p;
		}
		list->unmatched_next = m->next;
		if (list->unmatched_next == NULL)
			/* To return EOF next time. */
			list->unmatched_eof = 1;
		return (ARCHIVE_OK);
	}
	list->unmatched_next = NULL;
	return (ARCHIVE_EOF);
}

/*
 * Utility functions to manage inclusion timestamps.
 */

int
archive_matching_newer_mtime(struct archive *_a, time_t sec, long nsec)
{
	struct archive_matching *a;

	archive_check_magic(_a, ARCHIVE_MATCHING_MAGIC,
	    ARCHIVE_STATE_NEW, "archive_matching_newer_mtime");
	a = (struct archive_matching *)_a;

	a->newer_mtime_filter = 1;
	a->newer_mtime_sec = sec;
	a->newer_mtime_nsec = nsec;
	a->setflag |= TIME_IS_SET;
	return (ARCHIVE_OK);
}

int
archive_matching_newer_mtime_than(struct archive *_a, const char *pathname)
{
	struct archive_matching *a;
	int r;

	archive_check_magic(_a, ARCHIVE_MATCHING_MAGIC,
	    ARCHIVE_STATE_NEW, "archive_matching_newer_mtime_than");
	a = (struct archive_matching *)_a;

	if (pathname == NULL || *pathname == '\0') {
		archive_set_error(&(a->archive), EINVAL, "pathname is empty");
		return (ARCHIVE_FAILED);
	}
	r = get_filetime_mbs(a, pathname, 0, &(a->newer_mtime_sec),
		&(a->newer_mtime_nsec));
	if (r != ARCHIVE_OK)
		return (r);
	a->newer_mtime_filter = 1;
	a->setflag |= TIME_IS_SET;
	return (ARCHIVE_OK);
}

int
archive_matching_newer_mtime_than_w(struct archive *_a, const wchar_t *pathname)
{
	struct archive_matching *a;
	int r;

	archive_check_magic(_a, ARCHIVE_MATCHING_MAGIC,
	    ARCHIVE_STATE_NEW, "archive_matching_newer_mtime_than_w");
	a = (struct archive_matching *)_a;

	if (pathname == NULL || *pathname == L'\0') {
		archive_set_error(&(a->archive), EINVAL, "pathname is empty");
		return (ARCHIVE_FAILED);
	}
	r = get_filetime_wcs(a, pathname, 0, &(a->newer_mtime_sec),
		&(a->newer_mtime_nsec));
	if (r != ARCHIVE_OK)
		return (r);
	a->newer_mtime_filter = 1;
	a->setflag |= TIME_IS_SET;
	return (ARCHIVE_OK);
}

int
archive_matching_newer_ctime(struct archive *_a, time_t sec, long nsec)
{
	struct archive_matching *a;

	archive_check_magic(_a, ARCHIVE_MATCHING_MAGIC,
	    ARCHIVE_STATE_NEW, "archive_matching_newer_ctime");
	a = (struct archive_matching *)_a;

	a->newer_ctime_filter = 1;
	a->newer_ctime_sec = sec;
	a->newer_ctime_nsec = nsec;
	a->setflag |= TIME_IS_SET;
	return (ARCHIVE_OK);
}

int
archive_matching_newer_ctime_than(struct archive *_a,
    const char *pathname)
{
	struct archive_matching *a;
	int r;

	archive_check_magic(_a, ARCHIVE_MATCHING_MAGIC,
	    ARCHIVE_STATE_NEW, "archive_matching_newer_ctime_than");
	a = (struct archive_matching *)_a;

	if (pathname == NULL || *pathname == '\0') {
		archive_set_error(&(a->archive), EINVAL, "pathname is empty");
		return (ARCHIVE_FAILED);
	}
	r = get_filetime_mbs(a, pathname, 1, &(a->newer_ctime_sec),
	    &(a->newer_ctime_nsec));
	if (r != ARCHIVE_OK)
		return (r);
	a->newer_ctime_filter = 1;
	a->setflag |= TIME_IS_SET;
	return (ARCHIVE_OK);
}

int
archive_matching_newer_ctime_than_w(struct archive *_a, const wchar_t *pathname)
{
	struct archive_matching *a;
	int r;

	archive_check_magic(_a, ARCHIVE_MATCHING_MAGIC,
	    ARCHIVE_STATE_NEW, "archive_matching_newer_ctime_than_w");
	a = (struct archive_matching *)_a;

	if (pathname == NULL || *pathname == L'\0') {
		archive_set_error(&(a->archive), EINVAL, "pathname is empty");
		return (ARCHIVE_FAILED);
	}
	r = get_filetime_wcs(a, pathname, 1, &(a->newer_ctime_sec),
		&(a->newer_ctime_nsec));
	if (r != ARCHIVE_OK)
		return (r);
	a->newer_ctime_filter = 1;
	a->setflag |= TIME_IS_SET;
	return (ARCHIVE_OK);
}

int
archive_matching_older_mtime(struct archive *_a, time_t sec, long nsec)
{
	struct archive_matching *a;

	archive_check_magic(_a, ARCHIVE_MATCHING_MAGIC,
	    ARCHIVE_STATE_NEW, "archive_matching_older_mtime");
	a = (struct archive_matching *)_a;

	a->older_mtime_filter = 1;
	a->older_mtime_sec = sec;
	a->older_mtime_nsec = nsec;
	a->setflag |= TIME_IS_SET;
	return (ARCHIVE_OK);
}

int
archive_matching_older_mtime_than(struct archive *_a, const char *pathname)
{
	struct archive_matching *a;
	int r;

	archive_check_magic(_a, ARCHIVE_MATCHING_MAGIC,
	    ARCHIVE_STATE_NEW, "archive_matching_older_mtime_than");
	a = (struct archive_matching *)_a;

	if (pathname == NULL || *pathname == '\0') {
		archive_set_error(&(a->archive), EINVAL, "pathname is empty");
		return (ARCHIVE_FAILED);
	}
	r = get_filetime_mbs(a, pathname, 0, &(a->older_mtime_sec),
		&(a->older_mtime_nsec));
	if (r != ARCHIVE_OK)
		return (r);
	a->older_mtime_filter = 1;
	a->setflag |= TIME_IS_SET;
	return (ARCHIVE_OK);
}

int
archive_matching_older_mtime_than_w(struct archive *_a, const wchar_t *pathname)
{
	struct archive_matching *a;
	int r;

	archive_check_magic(_a, ARCHIVE_MATCHING_MAGIC,
	    ARCHIVE_STATE_NEW, "archive_matching_older_mtime_than_w");
	a = (struct archive_matching *)_a;

	if (pathname == NULL || *pathname == L'\0') {
		archive_set_error(&(a->archive), EINVAL, "pathname is empty");
		return (ARCHIVE_FAILED);
	}
	r = get_filetime_wcs(a, pathname, 0, &(a->older_mtime_sec),
	    &(a->older_mtime_nsec));
	if (r != ARCHIVE_OK)
		return (r);
	a->older_mtime_filter = 1;
	a->setflag |= TIME_IS_SET;
	return (ARCHIVE_OK);
}

int
archive_matching_older_ctime(struct archive *_a, time_t sec, long nsec)
{
	struct archive_matching *a;

	archive_check_magic(_a, ARCHIVE_MATCHING_MAGIC,
	    ARCHIVE_STATE_NEW, "archive_matching_older_ctime");
	a = (struct archive_matching *)_a;

	a->older_ctime_filter = 1;
	a->older_ctime_sec = sec;
	a->older_ctime_nsec = nsec;
	a->setflag |= TIME_IS_SET;
	return (ARCHIVE_OK);
}

int
archive_matching_older_ctime_than(struct archive *_a, const char *pathname)
{
	struct archive_matching *a;
	int r;

	archive_check_magic(_a, ARCHIVE_MATCHING_MAGIC,
	    ARCHIVE_STATE_NEW, "archive_matching_older_ctime_than");
	a = (struct archive_matching *)_a;

	if (pathname == NULL || *pathname == '\0') {
		archive_set_error(&(a->archive), EINVAL, "pathname is empty");
		return (ARCHIVE_FAILED);
	}
	r = get_filetime_mbs(a, pathname, 1, &(a->older_ctime_sec),
		&(a->older_ctime_nsec));
	if (r != ARCHIVE_OK)
		return (r);
	a->older_ctime_filter = 1;
	a->setflag |= TIME_IS_SET;
	return (ARCHIVE_OK);
}

int
archive_matching_older_ctime_than_w(struct archive *_a, const wchar_t *pathname)
{
	struct archive_matching *a;
	int r;

	archive_check_magic(_a, ARCHIVE_MATCHING_MAGIC,
	    ARCHIVE_STATE_NEW, "archive_matching_older_ctime_than_w");
	a = (struct archive_matching *)_a;

	if (pathname == NULL || *pathname == '\0') {
		archive_set_error(&(a->archive), EINVAL, "pathname is empty");
		return (ARCHIVE_FAILED);
	}
	r = get_filetime_wcs(a, pathname, 1, &(a->older_ctime_sec),
		&(a->older_ctime_nsec));
	if (r != ARCHIVE_OK)
		return (r);
	a->older_ctime_filter = 1;
	a->setflag |= TIME_IS_SET;
	return (ARCHIVE_OK);
}

int
archive_matching_pathname_newer_mtime(struct archive *_a,
    const char *pathname, time_t sec, long nsec)
{
	struct archive_matching *a;

	archive_check_magic(_a, ARCHIVE_MATCHING_MAGIC,
	    ARCHIVE_STATE_NEW, "archive_matching_add_newer_mtime_pathname");
	a = (struct archive_matching *)_a;

	if (pathname == NULL || *pathname == '\0') {
		archive_set_error(&(a->archive), EINVAL, "pathname is empty");
		return (ARCHIVE_FAILED);
	}
	a->newer_tree.rbt_ops = &rb_ops_mbs;
	return (add_newer_mtime_pathname(a, 1, pathname, sec, nsec));
}

int
archive_matching_pathname_newer_mtime_w(struct archive *_a,
    const wchar_t *pathname, time_t sec, long nsec)
{
	struct archive_matching *a;

	archive_check_magic(_a, ARCHIVE_MATCHING_MAGIC,
	    ARCHIVE_STATE_NEW, "archive_matching_add_newer_mtime_pathname_w");
	a = (struct archive_matching *)_a;

	if (pathname == NULL || *pathname == '\0') {
		archive_set_error(&(a->archive), EINVAL, "pathname is empty");
		return (ARCHIVE_FAILED);
	}
	a->newer_tree.rbt_ops = &rb_ops_wcs;
	return (add_newer_mtime_pathname(a, 0, pathname, sec, nsec));
}

int
archive_matching_pathname_newer_mtime_ae(struct archive *_a,
    struct archive_entry *entry)
{
	struct archive_matching *a;
	const void *pathname;
	int mbs;

	archive_check_magic(_a, ARCHIVE_MATCHING_MAGIC,
	    ARCHIVE_STATE_NEW, "archive_matching_add_newer_mtime_ae");
	a = (struct archive_matching *)_a;

	if (entry == NULL) {
		archive_set_error(&(a->archive), EINVAL, "entry is NULL");
		return (ARCHIVE_FAILED);
	}
#if defined(_WIN32) && !defined(__CYGWIN__)
	a->newer_tree.rbt_ops = &rb_ops_wcs;
	pathname = archive_entry_pathname_w(entry);
	mbs = 0;
#else
	a->newer_tree.rbt_ops = &rb_ops_mbs;
	pathname = archive_entry_pathname(entry);
	mbs = 1;
#endif
	if (pathname == NULL) {
		archive_set_error(&(a->archive), EINVAL, "pathname is NULL");
		return (ARCHIVE_FAILED);
	}
	return (add_newer_mtime_pathname(a, mbs, pathname,
		archive_entry_mtime(entry), archive_entry_mtime_nsec(entry)));
}

/*
 * Test function for time stamps.
 *
 * Returns 1 if archive entry is excluded.
 * Returns 0 if archive entry is not excluded.
 * Returns <0 if something error happened.
 */
int
archive_matching_time_excluded(struct archive *_a,
    struct archive_entry *entry)
{
	struct archive_matching *a;

	archive_check_magic(_a, ARCHIVE_MATCHING_MAGIC,
	    ARCHIVE_STATE_NEW, "archive_matching_time_excluded_ae");

	a = (struct archive_matching *)_a;
	if (entry == NULL) {
		archive_set_error(&(a->archive), EINVAL, "entry is NULL");
		return (ARCHIVE_FAILED);
	}

	/* If we don't have inclusion time set at all, the entry is always
	 * not excluded. */
	if ((a->setflag & TIME_IS_SET) == 0)
		return (0);
	return (time_excluded(a, entry));
}

#if defined(_WIN32) && !defined(__CYGWIN__)
#define EPOC_TIME (116444736000000000ui64)
#else
static int
get_time(struct archive_matching *a, struct stat *st, int is_ctime,
    time_t *time, long *ns)
{
	struct archive_entry *ae;

	ae = archive_entry_new();
	if (ae == NULL)
		return (error_nomem(a));
	archive_entry_copy_stat(ae, st);
	if (is_ctime) {
		*time = archive_entry_ctime(ae);
		*ns = archive_entry_ctime_nsec(ae);
	} else {
		*time = archive_entry_mtime(ae);
		*ns = archive_entry_mtime_nsec(ae);
	}
	archive_entry_free(ae);
	return (ARCHIVE_OK);
}
#endif

static int
get_filetime_mbs(struct archive_matching *a, const char *path,
    int is_ctime, time_t *time, long *ns)
{
#if defined(_WIN32) && !defined(__CYGWIN__)
	/* NOTE: stat() on Windows cannot handle nano seconds. */
	HANDLE h;
	WIN32_FIND_DATA d;
	ULARGE_INTEGER utc;

	h = FindFirstFileA(path, &d);
	if (h == INVALID_HANDLE_VALUE) {
		la_dosmaperr(GetLastError());
		archive_set_error(&(a->archive), errno,
		    "Failed to FindFirstFileA");
		return (ARCHIVE_FAILED);
	}
	FindClose(h);
	if (is_ctime) {
		utc.HighPart = d.ftCreationTime.dwHighDateTime;
		utc.LowPart = d.ftCreationTime.dwLowDateTime;
	} else {
		utc.HighPart = d.ftLastWriteTime.dwHighDateTime;
		utc.LowPart = d.ftLastWriteTime.dwLowDateTime;
	}
	if (utc.QuadPart >= EPOC_TIME) {
		utc.QuadPart -= EPOC_TIME;
		*time = (time_t)(utc.QuadPart / 10000000);
		*ns = (long)(utc.QuadPart % 10000000) * 100;
	} else {
		*time = 0;
		*ns = 0;
	}
	return (ARCHIVE_OK);
#else
	struct stat st;

	if (stat(path, &st) != 0) {
		archive_set_error(&(a->archive), errno, "Failed to stat()");
		return (ARCHIVE_FAILED);
	}
	return (get_time(a, &st, is_ctime, time, ns));
#endif
}

static int
get_filetime_wcs(struct archive_matching *a, const wchar_t *path,
    int is_ctime, time_t *time, long *ns)
{
#if defined(_WIN32) && !defined(__CYGWIN__)
	HANDLE h;
	WIN32_FIND_DATAW d;
	ULARGE_INTEGER utc;

	h = FindFirstFileW(path, &d);
	if (h == INVALID_HANDLE_VALUE) {
		la_dosmaperr(GetLastError());
		archive_set_error(&(a->archive), errno,
		    "Failed to FindFirstFile");
		return (ARCHIVE_FAILED);
	}
	FindClose(h);
	if (is_ctime) {
		utc.HighPart = d.ftCreationTime.dwHighDateTime;
		utc.LowPart = d.ftCreationTime.dwLowDateTime;
	} else {
		utc.HighPart = d.ftLastWriteTime.dwHighDateTime;
		utc.LowPart = d.ftLastWriteTime.dwLowDateTime;
	}
	if (utc.QuadPart >= EPOC_TIME) {
		utc.QuadPart -= EPOC_TIME;
		*time = (time_t)(utc.QuadPart / 10000000);
		*ns = (long)(utc.QuadPart % 10000000) * 100;
	} else {
		*time = 0;
		*ns = 0;
	}
	return (ARCHIVE_OK);
#else
	struct stat st;
	struct archive_string as;

	archive_string_init(&as);
	if (archive_string_append_from_wcs(&as, path, wcslen(path)) < 0) {
		if (errno == ENOMEM)
			return (error_nomem(a));
		archive_set_error(&(a->archive), -1,
		    "Failed to convert WCS to MBS");
		return (ARCHIVE_FAILED);
	}
	if (stat(as.s, &st) != 0) {
		archive_set_error(&(a->archive), errno, "Failed to stat()");
		archive_string_free(&as);
		return (ARCHIVE_FAILED);
	}
	archive_string_free(&as);
	return (get_time(a, &st, is_ctime, time, ns));
#endif
}

static int
cmp_node_mbs(const struct archive_rb_node *n1,
    const struct archive_rb_node *n2)
{
	struct newer_file *f1 = (struct newer_file *)n1;
	struct newer_file *f2 = (struct newer_file *)n2;
	const char *p1, *p2;

	archive_mstring_get_mbs(NULL, &(f1->pathname), &p1);
	archive_mstring_get_mbs(NULL, &(f2->pathname), &p2);
	if (p1 == NULL)
		return (1);
	if (p2 == NULL)
		return (-1);
	return (strcmp(p1, p2));
}
        
static int
cmp_key_mbs(const struct archive_rb_node *n, const void *key)
{
	struct newer_file *f = (struct newer_file *)n;
	const char *p;

	archive_mstring_get_mbs(NULL, &(f->pathname), &p);
	if (p == NULL)
		return (-1);
	return (strcmp(p, (const char *)key));
}

static int
cmp_node_wcs(const struct archive_rb_node *n1,
    const struct archive_rb_node *n2)
{
	struct newer_file *f1 = (struct newer_file *)n1;
	struct newer_file *f2 = (struct newer_file *)n2;
	const wchar_t *p1, *p2;

	archive_mstring_get_wcs(NULL, &(f1->pathname), &p1);
	archive_mstring_get_wcs(NULL, &(f2->pathname), &p2);
	if (p1 == NULL)
		return (1);
	if (p2 == NULL)
		return (-1);
	return (wcscmp(p1, p2));
}
        
static int
cmp_key_wcs(const struct archive_rb_node *n, const void *key)
{
	struct newer_file *f = (struct newer_file *)n;
	const wchar_t *p;

	archive_mstring_get_wcs(NULL, &(f->pathname), &p);
	if (p == NULL)
		return (-1);
	return (wcscmp(p, (const wchar_t *)key));
}

static void
newer_file_list_init(struct newer_file_list *list)
{
	list->first = NULL;
	list->last = &(list->first);
	list->count = 0;
}

static void
newer_file_list_free(struct newer_file_list *list)
{
	struct newer_file *p, *q;

	for (p = list->first; p != NULL; ) {
		q = p;
		p = p->next;
		archive_mstring_clean(&(q->pathname));
		free(q);
	}
}

static void
newer_file_list_add(struct newer_file_list *list, struct newer_file *file)
{
	*list->last = file;
	list->last = &(file->next);
	list->count++;
}

static int
add_newer_mtime_pathname(struct archive_matching *a, int mbs,
    const void *pathname, time_t sec, long nsec)
{
	struct newer_file *f;
	int r;

	f = calloc(1, sizeof(*f));
	if (f == NULL)
		return (error_nomem(a));
	if (mbs)
		archive_mstring_copy_mbs(&(f->pathname), pathname);
	else
		archive_mstring_copy_wcs(&(f->pathname), pathname);
	f->mtime_sec = sec;
	f->mtime_nsec = nsec;
	r = __archive_rb_tree_insert_node(&(a->newer_tree), &(f->node));
	if (!r) {
		struct newer_file *f2;

		/* Get the duplicated file. */
		f2 = (struct newer_file *)__archive_rb_tree_find_node(
			&(a->newer_tree), pathname);

		/* Overwrite mtime condision if it is newer than. */
		if (f2 != NULL && ((f2->mtime_sec < f->mtime_sec) ||
		    (f2->mtime_sec == f->mtime_sec &&
		     f2->mtime_nsec < f->mtime_nsec))) {
			f2->mtime_sec = f->mtime_sec;
			f2->mtime_nsec = f->mtime_nsec;
			/* Release the duplicated file. */ 
			archive_mstring_clean(&(f->pathname));
			free(f);
			return (ARCHIVE_OK);
		}
	}
	newer_file_list_add(&(a->newer_list), f);
	a->setflag |= TIME_IS_SET;
	return (ARCHIVE_OK);
}

static int
time_excluded(struct archive_matching *a, struct archive_entry *entry)
{
	struct newer_file *f;
	const void *pathname;
	time_t sec;
	long nsec;

	/*
	 * If this file/dir is excluded by a time comparison, skip it.
	 */
	if (a->newer_ctime_filter) {
		/* If ctime is not set, use mtime instead. */
		if (archive_entry_ctime_is_set(entry))
			sec = archive_entry_ctime(entry);
		else
			sec = archive_entry_mtime(entry);
		if (sec < a->newer_ctime_sec)
			return (1); /* Too old, skip it. */
		if (archive_entry_ctime_is_set(entry))
			nsec = archive_entry_ctime_nsec(entry);
		else
			nsec = archive_entry_mtime_nsec(entry);
		if (sec == a->newer_ctime_sec
		    && nsec <= a->newer_ctime_nsec)
			return (1); /* Too old, skip it. */
	}
	if (a->older_ctime_filter) {
		/* If ctime is not set, use mtime instead. */
		if (archive_entry_ctime_is_set(entry))
			sec = archive_entry_ctime(entry);
		else
			sec = archive_entry_mtime(entry);
		if (sec > a->older_ctime_sec)
			return (1); /* Too new, skip it. */
		if (archive_entry_ctime_is_set(entry))
			nsec = archive_entry_ctime_nsec(entry);
		else
			nsec = archive_entry_mtime_nsec(entry);
		if (sec == a->older_ctime_sec
		    && nsec >= a->older_ctime_nsec)
			return (1); /* Too new, skip it. */
	}
	if (a->newer_mtime_filter) {
		sec = archive_entry_mtime(entry);
		if (sec < a->newer_mtime_sec)
			return (1); /* Too old, skip it. */
		nsec = archive_entry_mtime_nsec(entry);
		if (sec == a->newer_mtime_sec
		    && nsec <= a->newer_mtime_nsec)
			return (1); /* Too old, skip it. */
	}
	if (a->older_mtime_filter) {
		sec = archive_entry_mtime(entry);
		if (sec > a->older_mtime_sec)
			return (1); /* Too new, skip it. */
		nsec = archive_entry_mtime_nsec(entry);
		if (sec == a->older_mtime_sec
		    && nsec >= a->older_mtime_nsec)
			return (1); /* Too new, skip it. */
	}

	/* If there is no incluson list, include the file. */
	if (a->newer_list.count == 0)
		return (0);

#if defined(_WIN32) && !defined(__CYGWIN__)
	pathname = archive_entry_pathname_w(entry);
	a->newer_tree.rbt_ops = &rb_ops_wcs;
#else
	pathname = archive_entry_pathname(entry);
	a->newer_tree.rbt_ops = &rb_ops_mbs;
#endif
	if (pathname == NULL)
		return (0);

	f = (struct newer_file *)__archive_rb_tree_find_node(
		&(a->newer_tree), pathname);
	/* If the file wasn't rejected, include it. */
	if (f == NULL)
		return (0);

	sec = archive_entry_mtime(entry);
	if (f->mtime_sec < sec)
		return (0);
	nsec = archive_entry_mtime_nsec(entry);
	return (f->mtime_sec > sec || f->mtime_nsec >= nsec);
}

/*
 * Utility functions to manage inclusion owners
 */

int
archive_matching_include_uid(struct archive *_a, int64_t uid)
{
	struct archive_matching *a;

	archive_check_magic(_a, ARCHIVE_MATCHING_MAGIC,
	    ARCHIVE_STATE_NEW, "archive_matching_include_uid");
	a = (struct archive_matching *)_a;
	return (add_owner_id(a, &(a->inclusion_uids), uid));
}

int
archive_matching_include_gid(struct archive *_a, int64_t gid)
{
	struct archive_matching *a;

	archive_check_magic(_a, ARCHIVE_MATCHING_MAGIC,
	    ARCHIVE_STATE_NEW, "archive_matching_include_gid");
	a = (struct archive_matching *)_a;
	return (add_owner_id(a, &(a->inclusion_gids), gid));
}

int
archive_matching_include_uname(struct archive *_a, const char *uname)
{
	struct archive_matching *a;

	archive_check_magic(_a, ARCHIVE_MATCHING_MAGIC,
	    ARCHIVE_STATE_NEW, "archive_matching_include_uname");
	a = (struct archive_matching *)_a;
	return (add_owner_name(a, &(a->inclusion_unames), 1, uname));
}

int
archive_matching_include_uname_w(struct archive *_a, const wchar_t *uname)
{
	struct archive_matching *a;

	archive_check_magic(_a, ARCHIVE_MATCHING_MAGIC,
	    ARCHIVE_STATE_NEW, "archive_matching_include_uname_w");
	a = (struct archive_matching *)_a;
	return (add_owner_name(a, &(a->inclusion_unames), 0, uname));
}

int
archive_matching_include_gname(struct archive *_a, const char *gname)
{
	struct archive_matching *a;

	archive_check_magic(_a, ARCHIVE_MATCHING_MAGIC,
	    ARCHIVE_STATE_NEW, "archive_matching_include_gname");
	a = (struct archive_matching *)_a;
	return (add_owner_name(a, &(a->inclusion_gnames), 1, gname));
}

int
archive_matching_include_gname_w(struct archive *_a, const wchar_t *gname)
{
	struct archive_matching *a;

	archive_check_magic(_a, ARCHIVE_MATCHING_MAGIC,
	    ARCHIVE_STATE_NEW, "archive_matching_include_gname_w");
	a = (struct archive_matching *)_a;
	return (add_owner_name(a, &(a->inclusion_gnames), 0, gname));
}

/*
 * Test function for owner(uid, gid, uname, gname).
 *
 * Returns 1 if archive entry is excluded.
 * Returns 0 if archive entry is not excluded.
 * Returns <0 if something error happened.
 */
int
archive_matching_owner_excluded(struct archive *_a,
    struct archive_entry *entry)
{
	struct archive_matching *a;

	archive_check_magic(_a, ARCHIVE_MATCHING_MAGIC,
	    ARCHIVE_STATE_NEW, "archive_matching_id_excluded_ae");

	a = (struct archive_matching *)_a;
	if (entry == NULL) {
		archive_set_error(&(a->archive), EINVAL, "entry is NULL");
		return (ARCHIVE_FAILED);
	}

	/* If we don't have inclusion id set at all, the entry is always
	 * not excluded. */
	if ((a->setflag & ID_IS_SET) == 0)
		return (0);
	return (owner_excluded(a, entry));
}

static int
add_owner_id(struct archive_matching *a, struct id_array *ids, int64_t id)
{
	if (ids->count + 1 >= ids->size) {
		if (ids->size == 0)
			ids->size = 8;
		else
			ids->size *= 2;
		ids->ids = realloc(ids->ids, sizeof(*ids->ids) * ids->size);
		if (ids->ids == NULL)
			return (error_nomem(a));
	}
	/*
	 * TODO: sort id list.
	 */
	ids->ids[ids->count++] = id;
	a->setflag |= ID_IS_SET;
	return (ARCHIVE_OK);
}

static int
match_owner_id(struct id_array *ids, int64_t id)
{
	int i;

	for (i = 0; i < (int)ids->count; i++) {
		if (ids->ids[i] == id)
			return (1);
	}
	return (0);
}

static int
add_owner_name(struct archive_matching *a, struct match_list *list,
    int mbs, const void *name)
{
	struct match *match;

	match = calloc(1, sizeof(*match));
	if (match == NULL)
		return (error_nomem(a));
	if (mbs)
		archive_mstring_copy_mbs(&(match->pattern), name);
	else
		archive_mstring_copy_wcs(&(match->pattern), name);
	match_list_add(list, match);
	a->setflag |= ID_IS_SET;
	return (ARCHIVE_OK);
}

#if !defined(_WIN32) || defined(__CYGWIN__)
static int
match_owner_name_mbs(struct archive_matching *a, struct match_list *list,
    const char *name)
{
	struct match *m;
	const char *p;

	if (name == NULL || *name == '\0')
		return (0);
	for (m = list->first; m; m = m->next) {
		if (archive_mstring_get_mbs(&(a->archive), &(m->pattern), &p)
		    < 0 && errno == ENOMEM)
			return (error_nomem(a));
		if (p != NULL && strcmp(p, name) == 0) {
			m->matches++;
			return (1);
		}
	}
	return (0);
}
#else
static int
match_owner_name_wcs(struct archive_matching *a, struct match_list *list,
    const wchar_t *name)
{
	struct match *m;
	const wchar_t *p;

	if (name == NULL || *name == L'\0')
		return (0);
	for (m = list->first; m; m = m->next) {
		if (archive_mstring_get_wcs(&(a->archive), &(m->pattern), &p)
		    < 0 && errno == ENOMEM)
			return (error_nomem(a));
		if (p != NULL && wcscmp(p, name) == 0) {
			m->matches++;
			return (1);
		}
	}
	return (0);
}
#endif

static int
owner_excluded(struct archive_matching *a, struct archive_entry *entry)
{
	int r;

	if (a->inclusion_uids.count) {
		if (!match_owner_id(&(a->inclusion_uids),
		    archive_entry_uid(entry)))
			return (1);
	}

	if (a->inclusion_gids.count) {
		if (!match_owner_id(&(a->inclusion_gids),
		    archive_entry_gid(entry)))
			return (1);
	}

	if (a->inclusion_unames.count) {
#if defined(_WIN32) && !defined(__CYGWIN__)
		r = match_owner_name_wcs(a, &(a->inclusion_unames),
			archive_entry_uname_w(entry));
#else
		r = match_owner_name_mbs(a, &(a->inclusion_unames),
			archive_entry_uname(entry));
#endif
		if (!r)
			return (1);
		else if (r < 0)
			return (r);
	}

	if (a->inclusion_gnames.count) {
#if defined(_WIN32) && !defined(__CYGWIN__)
		r = match_owner_name_wcs(a, &(a->inclusion_gnames),
			archive_entry_gname_w(entry));
#else
		r = match_owner_name_mbs(a, &(a->inclusion_gnames),
			archive_entry_gname(entry));
#endif
		if (!r)
			return (1);
		else if (r < 0)
			return (r);
	}
	return (0);
}

