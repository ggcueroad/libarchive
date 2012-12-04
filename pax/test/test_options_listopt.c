/*-
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
#include "test.h"
__FBSDID("$FreeBSD$");

#if defined(_WIN32) && !defined(__CYGWIN__)
#define setenv(_name, _value, f)	_putenv_s(_name, _value)
#define BSDPAX	"bsdpax.exe"
#define LARC	"("
#define RARC	")"
#else
#define BSDPAX	"bsdpax"
#define LARC	"\\("
#define RARC	"\\)"
#endif

DEFINE_TEST(test_options_listopt)
{
	const char *reffile1 = "test_options_listopt.tar.Z";

	extract_reference_file(reffile1);

	/* Test1: without -v option. */
	assertEqualInt(0, systemf(
	    "%s < %s >test.out 2>test.err", testprog, reffile1));

	failure("Output should be only filenames");
	assertTextFileContents("file1\nhardlink1\noldfile\nsymlink1\n",
	    "test.out");
	assertTextFileContents(
	    BSDPAX ": POSIX pax interchange format,"
	    " compress (.Z) filters, 4 files,"
	    " 8192 bytes read, 0 bytes written\n",
	    "test.err");

	setenv("LANG", "C", 1);

	/* Test2: with -v option. */
	assertEqualInt(0, systemf(
	    "%s -v < %s >test.out 2>test.err", testprog, reffile1));

	failure("Output should be default value");
#if defined(_WIN32) && !defined(__CYGWIN__)
	assertTextFileContents(
"-rw-r--r--  0 cue    cue        17 6 23  2011 file1\n"
"hrw-r--r--  0 cue    cue         0 6 23  2011 hardlink1 link to file1\n"
"-rw-r--r--  0 cue    cue         4 1 01  1980 oldfile\n"
"lrwxr-xr-x  0 cue    cue         0 6 23  2011 symlink1 -> file1\n",
	    "test.out");
#else
	assertTextFileContents(
"-rw-r--r--  0 cue    cue        17 Jun 23  2011 file1\n"
"hrw-r--r--  0 cue    cue         0 Jun 23  2011 hardlink1 link to file1\n"
"-rw-r--r--  0 cue    cue         4 Jan  1  1980 oldfile\n"
"lrwxr-xr-x  0 cue    cue         0 Jun 23  2011 symlink1 -> file1\n",
	    "test.out");
#endif
	assertTextFileContents(
	    BSDPAX ": POSIX pax interchange format,"
	    " compress (.Z) filters, 4 files,"
	    " 8192 bytes read, 0 bytes written\n",
	    "test.err");

	/* Test3: with listopt.
	 * Make bsdpax print only filenames. */
	assertEqualInt(0, systemf(
	    "%s -o listopt=%%F < %s >test.out 2>test.err",
	    testprog, reffile1));

	failure("Output should be only a filename");
	assertTextFileContents("file1\nhardlink1\noldfile\nsymlink1\n",
	    "test.out");
	assertTextFileContents(
	    BSDPAX ": POSIX pax interchange format,"
	    " compress (.Z) filters, 4 files,"
	    " 8192 bytes read, 0 bytes written\n",
	    "test.err");

	/* Test4: with listopt.
	 * Make bsdpax print a mode and a filename. */
	assertEqualInt(0, systemf(
	    "%s -o listopt=%%M%%F < %s >test.out 2>test.err",
	    testprog, reffile1));

	failure("Output should be only filenames");
	assertTextFileContents(
	    "-rw-r--r-- file1\n"
	    "hrw-r--r-- hardlink1\n"
	    "-rw-r--r-- oldfile\n"
	    "lrwxr-xr-x symlink1\n",
	    "test.out");
	assertTextFileContents(
	    BSDPAX ": POSIX pax interchange format,"
	    " compress (.Z) filters, 4 files,"
	    " 8192 bytes read, 0 bytes written\n",
	    "test.err");

	/* Test5: with listopt.
	 * Make bsdpax print a date and a filename. */
	assertEqualInt(0, systemf(
	    "%s -o listopt=%%T_%%F < %s >test.out 2>test.err",
	    testprog, reffile1));

	failure("Output should be only filenames");
#if defined(_WIN32) && !defined(__CYGWIN__)
	assertTextFileContents(
	    "6 23 14:07 2011_file1\n"
	    "6 23 14:07 2011_hardlink1\n"
	    "1 01 01:01 1980_oldfile\n"
	    "6 23 14:08 2011_symlink1\n",
	    "test.out");
#else
	assertTextFileContents(
	    "Jun 23 14:07 2011_file1\n"
	    "Jun 23 14:07 2011_hardlink1\n"
	    "Jan  1 01:01 1980_oldfile\n"
	    "Jun 23 14:08 2011_symlink1\n",
	    "test.out");
#endif
	assertTextFileContents(
	    BSDPAX ": POSIX pax interchange format,"
	    " compress (.Z) filters, 4 files,"
	    " 8192 bytes read, 0 bytes written\n",
	    "test.err");

	/* Test6: with listopt.
	 * Make bsdpax print a date specified atime, and a filename . */
	assertEqualInt(0, systemf(
	    "%s -o listopt=%%" LARC "atime" RARC "T_%%F"
	    " < %s >test.out 2>test.err",
	    testprog, reffile1));

	failure("Output should be only filenames");
#if defined(_WIN32) && !defined(__CYGWIN__)
	assertTextFileContents(
	    "6 26 06:30 2011_file1\n"
	    "6 26 06:32 2011_hardlink1\n"
	    "6 26 06:30 2011_oldfile\n"
	    "6 23 14:08 2011_symlink1\n",
	    "test.out");
#else
	assertTextFileContents(
	    "Jun 26 06:30 2011_file1\n"
	    "Jun 26 06:32 2011_hardlink1\n"
	    "Jun 26 06:30 2011_oldfile\n"
	    "Jun 23 14:08 2011_symlink1\n",
	    "test.out");
#endif
	assertTextFileContents(
	    BSDPAX ": POSIX pax interchange format,"
	    " compress (.Z) filters, 4 files,"
	    " 8192 bytes read, 0 bytes written\n",
	    "test.err");

	/* Test7: with listopt.
	 * Make bsdpax print a date specified ctime, and a filename . */
	assertEqualInt(0, systemf(
	    "%s -o listopt=%%" LARC "ctime" RARC "T_%%F"
	    " < %s >test.out 2>test.err",
	    testprog, reffile1));

	failure("Output should be only filenames");
#if defined(_WIN32) && !defined(__CYGWIN__)
	assertTextFileContents(
	    "6 23 14:08 2011_file1\n"
	    "6 23 14:08 2011_hardlink1\n"
	    "6 23 14:09 2011_oldfile\n"
	    "6 23 14:08 2011_symlink1\n",
	    "test.out");
#else
	assertTextFileContents(
	    "Jun 23 14:08 2011_file1\n"
	    "Jun 23 14:08 2011_hardlink1\n"
	    "Jun 23 14:09 2011_oldfile\n"
	    "Jun 23 14:08 2011_symlink1\n",
	    "test.out");
#endif
	assertTextFileContents(
	    BSDPAX ": POSIX pax interchange format,"
	    " compress (.Z) filters, 4 files,"
	    " 8192 bytes read, 0 bytes written\n",
	    "test.err");

	/* Test8: with listopt.
	 * Make bsdpax print a date specified mtime, and a filename . */
	assertEqualInt(0, systemf(
	    "%s -o listopt=%%" LARC "mtime" RARC "T_%%F"
	    " < %s >test.out 2>test.err",
	    testprog, reffile1));

	failure("Output should be only filenames");
#if defined(_WIN32) && !defined(__CYGWIN__)
	assertTextFileContents(
	    "6 23 14:07 2011_file1\n"
	    "6 23 14:07 2011_hardlink1\n"
	    "1 01 01:01 1980_oldfile\n"
	    "6 23 14:08 2011_symlink1\n",
	    "test.out");
#else
	assertTextFileContents(
	    "Jun 23 14:07 2011_file1\n"
	    "Jun 23 14:07 2011_hardlink1\n"
	    "Jan  1 01:01 1980_oldfile\n"
	    "Jun 23 14:08 2011_symlink1\n",
	    "test.out");
#endif
	assertTextFileContents(
	    BSDPAX ": POSIX pax interchange format,"
	    " compress (.Z) filters, 4 files,"
	    " 8192 bytes read, 0 bytes written\n",
	    "test.err");

	/* Test9: with listopt.
	 * Make bsdpax print a date specified its time format
	 * like "yyyy-mm-dd", and a filename . */
	assertEqualInt(0, systemf(
	    "%s -o listopt=%%" LARC "mtime=%%Y-%%m-%%d" RARC "T_%%F"
	    " < %s >test.out 2>test.err",
	    testprog, reffile1));

	failure("Output should be only filenames");
	assertTextFileContents(
	    "2011-06-23_file1\n"
	    "2011-06-23_hardlink1\n"
	    "1980-01-01_oldfile\n"
	    "2011-06-23_symlink1\n",
	    "test.out");
	assertTextFileContents(
	    BSDPAX ": POSIX pax interchange format,"
	    " compress (.Z) filters, 4 files,"
	    " 8192 bytes read, 0 bytes written\n",
	    "test.err");

	/* Test10: with listopt.
	 * Make bsdpax print a date specified its time format
	 * like "HH:MM", and a filename . */
	assertEqualInt(0, systemf(
	    "%s -o listopt=%%" LARC "mtime=%%H:%%M" RARC "T_%%F"
	    " < %s >test.out 2>test.err",
	    testprog, reffile1));

	failure("Output should be only filenames");
	assertTextFileContents(
	    "14:07_file1\n"
	    "14:07_hardlink1\n"
	    "01:01_oldfile\n"
	    "14:08_symlink1\n",
	    "test.out");
	assertTextFileContents(
	    BSDPAX ": POSIX pax interchange format,"
	    " compress (.Z) filters, 4 files,"
	    " 8192 bytes read, 0 bytes written\n",
	    "test.err");

	/* Test11: with listopt.
	 * Make bsdpax print a filename and a linkname. */
	assertEqualInt(0, systemf(
	    "%s -o listopt=%%L < %s >test.out 2>test.err",
	    testprog, reffile1));

	failure("Output should be only a filename");
	assertTextFileContents(
	    "file1\n"
	    "hardlink1 link to file1\n"
	    "oldfile\n"
	    "symlink1 -> file1\n",
	    "test.out");
	assertTextFileContents(
	    BSDPAX ": POSIX pax interchange format,"
	    " compress (.Z) filters, 4 files,"
	    " 8192 bytes read, 0 bytes written\n",
	    "test.err");

	/* Test12: with listopt.
	 * Make bsdpax print a file size and a filename. */
	assertEqualInt(0, systemf(
	    "%s -o listopt=%%4" LARC "size" RARC "u%%10F"
	    " < %s >test.out 2>test.err",
	    testprog, reffile1));

	failure("Output should be only a filename");
	assertTextFileContents(
	    "  17     file1\n"
	    "   0 hardlink1\n"
	    "   4   oldfile\n"
	    "   0  symlink1\n",
	    "test.out");
	assertTextFileContents(
	    BSDPAX ": POSIX pax interchange format,"
	    " compress (.Z) filters, 4 files,"
	    " 8192 bytes read, 0 bytes written\n",
	    "test.err");

	/* Test13: with listopt.
	 * Make bsdpax print a file size with zero-padding
	 * and a filename in left alignment. */
	assertEqualInt(0, systemf(
	    "%s -o listopt=%%04" LARC "size" RARC "u%%-10F"
	    " < %s >test.out 2>test.err",
	    testprog, reffile1));

	failure("Output should be only a filename");
	assertTextFileContents(
	    "0017file1     \n"
	    "0000hardlink1 \n"
	    "0004oldfile   \n"
	    "0000symlink1  \n",
	    "test.out");
	assertTextFileContents(
	    BSDPAX ": POSIX pax interchange format,"
	    " compress (.Z) filters, 4 files,"
	    " 8192 bytes read, 0 bytes written\n",
	    "test.err");

	/* Test14: with listopt.
	 * Make bsdpax print a file size in hex and a mode in oct
	 * and a filename. */
	assertEqualInt(0, systemf(
	    "%s -o listopt=%%04" LARC "size" RARC "x%%7"
	    LARC "mode" RARC "o%%10F"
	    " < %s >test.out 2>test.err",
	    testprog, reffile1));

	failure("Output should be only a filename");
	assertTextFileContents(
	    "0011 100644     file1\n"
	    "0000    644 hardlink1\n"
	    "0004 100644   oldfile\n"
	    "0000 120755  symlink1\n",
	    "test.out");
	assertTextFileContents(
	    BSDPAX ": POSIX pax interchange format,"
	    " compress (.Z) filters, 4 files,"
	    " 8192 bytes read, 0 bytes written\n",
	    "test.err");
}
