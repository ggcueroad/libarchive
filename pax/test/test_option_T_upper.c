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

/*
 * Note: Windows system() does not allow " or ' characters to argument
 * execept program name. So We do not use -T "2011-1-1 1:0:0 utc"
 * style command line, and thus we use -T 2011-1-1()1:0:0utc style instead
 * on Windows platform. "()" will be parsed as comment statment by getdate().
 * Note2: Unfortunately "()" will cause error in system() on posix platform.
 */
static char *
t_datestr(const char *str)
{
	static char buff[1024];
	char *p = buff;

#if defined(_WIN32) && !defined(__CYGWIN__)
	while (*str && p < buff+sizeof(buff)-3) {
		if (*str == ' ') {
			*p++ = '(';
			*p++ = ')';
			str++;
		} else
			*p++ = *str++;
	}
	*p = '\0';
#else
	*p++ = '"';
	while (*str && p < buff+sizeof(buff)-2)
		*p++ = *str++;
	*p++ = '"';
	*p = '\0';
#endif
	return (buff);
}

DEFINE_TEST(test_option_T_upper)
{
	const char *reffile1 = "test_option_T_upper.tar";
	int r;

	extract_reference_file(reffile1);

	/* Test 1: -T "2011-1-1 1:0:0 utc" should only extract file5. */
	assertMakeDir("test1", 0755);
	assertChdir("test1");
	r = systemf("%s -rf ../%s -T %s >test.out 2>test.err",
	    testprog, reffile1, t_datestr("2011-1-1 1:0:0utc"));
	failure("Fatal error trying to use -T option");
	if (!assertEqualInt(0, r))
		return;

	assertFileNotExists("file1");
	assertFileNotExists("file2");
	assertFileNotExists("file3");
	assertFileNotExists("file4");
	assertFileContents("hello\n", 6, "file5");
	assertEmptyFile("test.out");
	assertEmptyFile("test.err");
	assertChdir("..");

	/* Test 2: -T "2011-1-1 1:0:0 jst" should extract file4 and file5. */
	assertMakeDir("test2", 0755);
	assertChdir("test2");
	assertEqualInt(0, systemf(
	    "%s -rf ../%s -T %s >test.out 2>test.err",
	    testprog, reffile1, t_datestr("2011-1-1 1:0:0jst")));
	assertFileNotExists("file1");
	assertFileNotExists("file2");
	assertFileNotExists("file3");
	assertFileContents("hello\n", 6, "file4");
	assertFileContents("hello\n", 6, "file5");
	assertEmptyFile("test.out");
	assertEmptyFile("test.err");
	assertChdir("..");

	/* Test 3: -T ",2001-1-1 0:0:0 utc" should only extract file1. */
	assertMakeDir("test3", 0755);
	assertChdir("test3");
	assertEqualInt(0, systemf(
	    "%s -rf ../%s -T %s >test.out 2>test.err",
	    testprog, reffile1, t_datestr(",2001-1-1 1:0:0utc")));
	assertFileContents("hello\n", 6, "file1");
	assertFileNotExists("file2");
	assertFileNotExists("file3");
	assertFileNotExists("file4");
	assertFileNotExists("file5");
	assertEmptyFile("test.out");
	assertEmptyFile("test.err");
	assertChdir("..");

	/* Test 4: -T ",2001-6-1 0:0:0 utc" should extract file1 and file2. */
	assertMakeDir("test4", 0755);
	assertChdir("test4");
	assertEqualInt(0, systemf(
	    "%s -rf ../%s -T %s >test.out 2>test.err",
	    testprog, reffile1, t_datestr(",2001-6-1 0:0:0utc")));
	assertFileContents("hello\n", 6, "file1");
	assertFileContents("hello\n", 6, "file2");
	assertFileNotExists("file3");
	assertFileNotExists("file4");
	assertFileNotExists("file5");
	assertEmptyFile("test.out");
	assertEmptyFile("test.err");
	assertChdir("..");

	/* Test 5: -T "2001-6-1 0:0:0,2011-1-1 0:0:0 utc" should extract file2,
	 * file3 and file4. */
	assertMakeDir("test5", 0755);
	assertChdir("test5");
	assertEqualInt(0, systemf(
	    "%s -rf ../%s -T %s >test.out 2>test.err",
	    testprog, reffile1, t_datestr("2001-6-1 0:0:0,2011-1-1 0:0:0utc")));
	assertFileNotExists("file1");
	assertFileContents("hello\n", 6, "file2");
	assertFileContents("hello\n", 6, "file3");
	assertFileContents("hello\n", 6, "file4");
	assertFileNotExists("file5");
	assertEmptyFile("test.out");
	assertEmptyFile("test.err");
	assertChdir("..");

	/* Test 6: -T ",2001-1-1 0:0:0 utc/m" should only extract file1. */
	assertMakeDir("test6", 0755);
	assertChdir("test6");
	assertEqualInt(0, systemf(
	    "%s -rf ../%s -T %s >test.out 2>test.err",
	    testprog, reffile1, t_datestr(",2001-1-1 1:0:0utc/m")));
	assertFileContents("hello\n", 6, "file1");
	assertFileNotExists("file2");
	assertFileNotExists("file3");
	assertFileNotExists("file4");
	assertFileNotExists("file5");
	assertEmptyFile("test.out");
	assertEmptyFile("test.err");
	assertChdir("..");

	/* Test 7: -T ",2001-1-1 0:0:0 utc/c" should not extract any files. */
	assertMakeDir("test7", 0755);
	assertChdir("test7");
	assertEqualInt(0, systemf(
	    "%s -rf ../%s -T %s >test.out 2>test.err",
	    testprog, reffile1, t_datestr(",2001-1-1 1:0:0utc/c")));
	assertFileNotExists("file1");
	assertFileNotExists("file2");
	assertFileNotExists("file3");
	assertFileNotExists("file4");
	assertFileNotExists("file5");
	assertEmptyFile("test.out");
	assertEmptyFile("test.err");
	assertChdir("..");

	/* Test 8: -T ",2001-1-1 0:0:0 utc/cm" should not extract any files. */
	assertMakeDir("test8", 0755);
	assertChdir("test8");
	assertEqualInt(0, systemf(
	    "%s -rf ../%s -T %s >test.out 2>test.err",
	    testprog, reffile1, t_datestr(",2001-1-1 1:0:0utc/cm")));
	assertFileNotExists("file1");
	assertFileNotExists("file2");
	assertFileNotExists("file3");
	assertFileNotExists("file4");
	assertFileNotExists("file5");
	assertEmptyFile("test.out");
	assertEmptyFile("test.err");
	assertChdir("..");

	/* Test 9: -T ",2001-1-1 0:0:0 utc/mc" should not extract any files. */
	assertMakeDir("test9", 0755);
	assertChdir("test9");
	assertEqualInt(0, systemf(
	    "%s -rf ../%s -T %s >test.out 2>test.err",
	    testprog, reffile1, t_datestr(",2001-1-1 1:0:0utc/mc")));
	assertFileNotExists("file1");
	assertFileNotExists("file2");
	assertFileNotExists("file3");
	assertFileNotExists("file4");
	assertFileNotExists("file5");
	assertEmptyFile("test.out");
	assertEmptyFile("test.err");
	assertChdir("..");

	/* Test 10: -T "2011-1-1 0:0:0 utc/c" should extract everything. */
	assertMakeDir("test10", 0755);
	assertChdir("test10");
	assertEqualInt(0, systemf(
	    "%s -rf ../%s -T %s >test.out 2>test.err",
	    testprog, reffile1, t_datestr("2011-1-1 1:0:0utc/c")));
	assertFileContents("hello\n", 6, "file1");
	assertFileContents("hello\n", 6, "file2");
	assertFileContents("hello\n", 6, "file3");
	assertFileContents("hello\n", 6, "file4");
	assertFileContents("hello\n", 6, "file5");
	assertEmptyFile("test.out");
	assertEmptyFile("test.err");
	assertChdir("..");


	/* Test 11: Without -T, should extract everything. */
	assertMakeDir("test11", 0755);
	assertChdir("test11");
	assertEqualInt(0,
	    systemf("%s -rf ../%s >test.out 2>test.err", testprog, reffile1));
	assertFileContents("hello\n", 6, "file1");
	assertFileContents("hello\n", 6, "file2");
	assertFileContents("hello\n", 6, "file3");
	assertFileContents("hello\n", 6, "file4");
	assertFileContents("hello\n", 6, "file5");
	assertEmptyFile("test.out");
	assertEmptyFile("test.err");
	assertChdir("..");
}
