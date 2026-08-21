/*
 * Copyright (c) 2026 Onomondo ApS & sysmocom - s.f.m.c. GmbH & Iapyx Informatica Ltda. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * The optional source location on log lines: off by default so that the golden .err comparisons elsewhere in
 * this suite keep working, and reduced to the last path component so that the output does not depend on where
 * the tree was built.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <onomondo/ipa/utils.h>
#include <onomondo/ipa/log.h>

#define CAPTURE_FILE "log_test_stderr.tmp"

static int saved_stderr = -1;
static char captured[8192];

static void capture_begin(void)
{
	int fd;

	fflush(stderr);
	saved_stderr = dup(STDERR_FILENO);
	assert(saved_stderr >= 0);
	fd = open(CAPTURE_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	assert(fd >= 0);
	assert(dup2(fd, STDERR_FILENO) >= 0);
	close(fd);
}

static void capture_end(void)
{
	FILE *f;
	size_t len;

	fflush(stderr);
	assert(dup2(saved_stderr, STDERR_FILENO) >= 0);
	close(saved_stderr);
	saved_stderr = -1;

	f = fopen(CAPTURE_FILE, "rb");
	assert(f);
	len = fread(captured, 1, sizeof(captured) - 1, f);
	captured[len] = '\0';
	fclose(f);
	remove(CAPTURE_FILE);
}

/* The default has to stay quiet: tests/bpp_segments compares stderr byte for byte against a golden file. */
static void default_is_off_test(void)
{
	printf("== default_is_off_test ==\n");

	capture_begin();
	IPA_LOGP(SMAIN, LERROR, "hello\n");
	capture_end();

	assert(strstr(captured, "hello"));
	assert(strstr(captured, "MAIN"));
	assert(strstr(captured, "ERROR"));
	assert(strstr(captured, "log_test.c") == NULL);
	assert(strchr(captured, '(') == NULL);
	printf("   %s", captured);
}

static void enabled_test(void)
{
	char expected[64];

	printf("== enabled_test ==\n");

	ipa_log_set_print_source(true);
	capture_begin();
	/* Kept on one line so that __LINE__ below names exactly this statement. */
	IPA_LOGP(SMAIN, LINFO, "world\n"); const int line = __LINE__;
	capture_end();
	ipa_log_set_print_source(false);

	/* The location names this file and this line, and nothing else. */
	snprintf(expected, sizeof(expected), "(log_test.c:%d)", line);
	assert(strstr(captured, expected));
	assert(strstr(captured, "world"));

	/* Only the last path component: an absolute __FILE__ must not reach the output, or the log would differ
	 * from one build machine to the next. */
	assert(strstr(captured, "/log_test.c") == NULL);
	assert(strstr(captured, "tests/log") == NULL);
	printf("   %s", captured);
}

/* Turning it back off leaves nothing behind. */
static void toggle_test(void)
{
	printf("== toggle_test ==\n");

	ipa_log_set_print_source(true);
	capture_begin();
	IPA_LOGP(SMAIN, LDEBUG, "on\n");
	capture_end();
	assert(strstr(captured, "log_test.c"));

	ipa_log_set_print_source(false);
	capture_begin();
	IPA_LOGP(SMAIN, LDEBUG, "off\n");
	capture_end();
	assert(strstr(captured, "off"));
	assert(strstr(captured, "log_test.c") == NULL);
}

int main(int argc, char **argv)
{
	default_is_off_test();
	enabled_test();
	toggle_test();
	printf("log_test: all checks passed\n");
	return 0;
}

/* Stubs */
void *ipa_http_init(const char *cabundle, bool no_verif)
{
	return NULL;
}

struct ipa_buf *ipa_http_req(void *http_ctx, const struct ipa_buf *req, const char *url)
{
	return NULL;
}

struct ipa_buf *ipa_http_req_with_ct(void *http_ctx, const struct ipa_buf *req, const char *url,
				     const char *content_type)
{
	return NULL;
}

void ipa_http_close(void *http_ctx)
{
	return;
}

void ipa_http_free(void *http_ctx)
{
	return;
}

void *ipa_scard_init(unsigned int reader_num)
{
	return NULL;
}

int ipa_scard_reset(void *scard_ctx)
{
	return 0;
}

int ipa_scard_atr(void *scard_ctx, struct ipa_buf *atr)
{
	return 0;
}

int ipa_scard_transceive(void *scard_ctx, struct ipa_buf *res, const struct ipa_buf *req)
{
	return 0;
}

int ipa_scard_free(void *scard_ctx)
{
	return 0;
}
