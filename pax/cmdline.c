/*-
 * Copyright (c) 2003-2007 Tim Kientzle
 * Copyright (c) 2010-2012 Michihiro NAKAJIMA
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


#include "bsdpax_platform.h"
__FBSDID("$FreeBSD$");

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#ifdef HAVE_GRP_H
#include <grp.h>
#endif
#ifdef HAVE_PWD_H
#include <pwd.h>
#endif
#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif

#include "bsdpax.h"
#include "err.h"

/*
 * Short options for bsdpax.  Please keep this sorted.
 */
static const char *short_options = "ab:cDdf:G:HiJjkLlno:Pp:rs:T:tU:uvW:wXxYZz";

/*
 * Long options for bsdpax.  Please keep this sorted.
 */
static const struct bsdpax_option {
	const char *name;
	int required;	/* 1 if this option requires an argument */
	int equivalent;	/* Equivalent short option. */
} bsdpax_longopts[] = {
	{ "append",			0, 'a' },
	{ "b64encode",			0, OPTION_B64ENCODE },
	{ "block-size",			1, 'b' },
	{ "bunzip2",			0, 'j' },
	{ "bzip",			0, 'j' },
	{ "bzip2",			0, 'j' },
	{ "compress",			0, OPTION_COMPRESS },
	{ "confirmation",		0, 'i' },
	{ "create",			0, 'w' },
	{ "dereference",		0, 'L' },
	{ "disable-copyfile",		0, OPTION_DISABLE_COPYFILE },
	{ "extract",			0, 'r' },
	{ "fast-read",			0, 'n' },
	{ "file",			1, 'f' },
	{ "format",			1, 'x' },
	{ "gunzip",			0, 'z' },
	{ "gzip",			0, 'z' },
	{ "help",			0, OPTION_HELP },
	{ "inverse",			0, 'c' },
	{ "insecure",			0, OPTION_INSECURE },
	{ "interactive",		0, 'i' },
	{ "keep-newer-ctime-files",	0, 'D' },
	{ "keep-newer-mtime-files",	0, 'u' },
	{ "keep-newer-ctime-files2",	0, 'Y' },
	{ "keep-newer-mtime-files2",	0, 'Z' },
	{ "keep-old-files",		0, 'k' },
	{ "link",			0, 'l' },
	{ "lrzip",			0, OPTION_LRZIP },
	{ "lzip",			0, OPTION_LZIP },
	{ "lzma",			0, OPTION_LZMA },
	{ "lzop",			0, OPTION_LZOP },
	{ "no-recursion",		0, 'd' },
	{ "nodump",			0, OPTION_NODUMP },
	{ "norecurse",			0, 'd' },
	{ "null",			0, OPTION_NULL },
	{ "one-file-system",		0, 'X' },
	{ "options",			1, 'o' },
	{ "strip-components",		1, OPTION_STRIP_COMPONENTS },
	{ "uncompress",			0, OPTION_COMPRESS },
	{ "use-compress-program",	1, OPTION_USE_COMPRESS_PROGRAM },
	{ "uuencode",			0, OPTION_UUENCODE },
	{ "verbose",			0, 'v' },
	{ "version",			0, OPTION_VERSION },
	{ "xz",				0, 'J' },
	{ NULL, 0, 0 }
};

/*
 * I used to try to select platform-provided getopt() or
 * getopt_long(), but that caused a lot of headaches.  In particular,
 * I couldn't consistently use long options in the test harness
 * because not all platforms have getopt_long(). 
 */
int
bsdpax_getopt(struct bsdpax *bsdpax)
{
	enum { state_start = 0, state_next_word, state_short, state_long };

	const struct bsdpax_option *popt, *match = NULL, *match2 = NULL;
	const char *p, *long_prefix = "--";
	size_t optlength;
	int opt = '?';
	int required = 0;

	bsdpax->argument = NULL;

	/* First time through, initialize everything. */
	if (bsdpax->getopt_state == state_start) {
		/* Skip program name. */
		++bsdpax->argv;
		--bsdpax->argc;
		bsdpax->getopt_state = state_next_word;
	}

	/*
	 * We're ready to look at the next word in argv.
	 */
	if (bsdpax->getopt_state == state_next_word) {
		/* No more arguments, so no more options. */
		if (bsdpax->argv[0] == NULL)
			return (-1);
		/* Doesn't start with '-', so no more options. */
		if (bsdpax->argv[0][0] != '-')
			return (-1);
		/* "--" marks end of options; consume it and return. */
		if (strcmp(bsdpax->argv[0], "--") == 0) {
			++bsdpax->argv;
			--bsdpax->argc;
			return (-1);
		}
		/* Get next word for parsing. */
		bsdpax->getopt_word = *bsdpax->argv++;
		--bsdpax->argc;
		if (bsdpax->getopt_word[1] == '-') {
			/* Set up long option parser. */
			bsdpax->getopt_state = state_long;
			bsdpax->getopt_word += 2; /* Skip leading '--' */
		} else {
			/* Set up short option parser. */
			bsdpax->getopt_state = state_short;
			++bsdpax->getopt_word;  /* Skip leading '-' */
		}
	}

	/*
	 * We're parsing a group of POSIX-style single-character options.
	 */
	if (bsdpax->getopt_state == state_short) {
		/* Peel next option off of a group of short options. */
		opt = *bsdpax->getopt_word++;
		if (opt == '\0') {
			/* End of this group; recurse to get next option. */
			bsdpax->getopt_state = state_next_word;
			return bsdpax_getopt(bsdpax);
		}

		/* Does this option take an argument? */
		p = strchr(short_options, opt);
		if (p == NULL)
			return ('?');
		if (p[1] == ':')
			required = 1;

		/* If it takes an argument, parse that. */
		if (required) {
			/* If arg is run-in, bsdpax->getopt_word already points to it. */
			if (bsdpax->getopt_word[0] == '\0') {
				/* Otherwise, pick up the next word. */
				bsdpax->getopt_word = *bsdpax->argv;
				if (bsdpax->getopt_word == NULL) {
					lafe_warnc(0,
					    "Option -%c requires an argument",
					    opt);
					return ('?');
				}
				++bsdpax->argv;
				--bsdpax->argc;
			}
			if (opt == 'W') {
				bsdpax->getopt_state = state_long;
				long_prefix = "-W "; /* For clearer errors. */
			} else {
				bsdpax->getopt_state = state_next_word;
				bsdpax->argument = bsdpax->getopt_word;
			}
		}
	}

	/* We're reading a long option, including -W long=arg convention. */
	if (bsdpax->getopt_state == state_long) {
		/* After this long option, we'll be starting a new word. */
		bsdpax->getopt_state = state_next_word;

		/* Option name ends at '=' if there is one. */
		p = strchr(bsdpax->getopt_word, '=');
		if (p != NULL) {
			optlength = (size_t)(p - bsdpax->getopt_word);
			bsdpax->argument = (char *)(uintptr_t)(p + 1);
		} else {
			optlength = strlen(bsdpax->getopt_word);
		}

		/* Search the table for an unambiguous match. */
		for (popt = bsdpax_longopts; popt->name != NULL; popt++) {
			/* Short-circuit if first chars don't match. */
			if (popt->name[0] != bsdpax->getopt_word[0])
				continue;
			/* If option is a prefix of name in table, record it.*/
			if (strncmp(bsdpax->getopt_word, popt->name, optlength) == 0) {
				match2 = match; /* Record up to two matches. */
				match = popt;
				/* If it's an exact match, we're done. */
				if (strlen(popt->name) == optlength) {
					match2 = NULL; /* Forget the others. */
					break;
				}
			}
		}

		/* Fail if there wasn't a unique match. */
		if (match == NULL) {
			lafe_warnc(0,
			    "Option %s%s is not supported",
			    long_prefix, bsdpax->getopt_word);
			return ('?');
		}
		if (match2 != NULL) {
			lafe_warnc(0,
			    "Ambiguous option %s%s (matches --%s and --%s)",
			    long_prefix, bsdpax->getopt_word, match->name, match2->name);
			return ('?');
		}

		/* We've found a unique match; does it need an argument? */
		if (match->required) {
			/* Argument required: get next word if necessary. */
			if (bsdpax->argument == NULL) {
				bsdpax->argument = *bsdpax->argv;
				if (bsdpax->argument == NULL) {
					lafe_warnc(0,
					    "Option %s%s requires an argument",
					    long_prefix, match->name);
					return ('?');
				}
				++bsdpax->argv;
				--bsdpax->argc;
			}
		} else {
			/* Argument forbidden: fail if there is one. */
			if (bsdpax->argument != NULL) {
				lafe_warnc(0,
				    "Option %s%s does not allow an argument",
				    long_prefix, match->name);
				return ('?');
			}
		}
		return (match->equivalent);
	}

	return (opt);
}

