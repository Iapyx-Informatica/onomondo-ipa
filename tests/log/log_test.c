/*
 * Copyright (c) 2026 Onomondo ApS & sysmocom - s.f.m.c. GmbH & Iapyx Informatica Ltda. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Runtime control of the log: the per-subsystem levels and enable flags, the name lookups the command line
 * parses with, and the dump helpers that have to consult the filter themselves.
 *
 * Also the optional source location on log lines: off by default so that the golden .err comparisons elsewhere
 * in this suite keep working, and reduced to the last path component so that the output does not depend on
 * where the tree was built.
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
#include <NotificationEvent.h>
#include "src/ipa/libipa/utils.h"

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

/* Every subsystem and level has to survive a name -> value -> name round trip: the command line parser has no
 * table of its own, so a name that does not resolve is a name nobody can type. */
static void name_lookup_test(void)
{
	unsigned int i;

	printf("== name_lookup_test ==\n");

	for (i = 0; i < _NUM_LOG_SUBSYS; i++) {
		const char *name = ipa_log_subsys_name(i);

		assert(name);
		assert(ipa_log_subsys_by_name(name) == (int)i);
		printf("   subsystem %u = %s\n", i, name);
	}

	for (i = 0; i < _NUM_LOG_LEVEL; i++) {
		const char *name = ipa_log_level_name(i);

		assert(name);
		assert(ipa_log_level_by_name(name) == (int)i);
		printf("   level %u = %s\n", i, name);
	}

	/* Case does not matter: the printed names are mixed case and nobody types them back that way. */
	assert(ipa_log_subsys_by_name("es10b") == SES10B);
	assert(ipa_log_subsys_by_name("ES10B") == SES10B);
	assert(ipa_log_subsys_by_name("euicc") == SEUICC);
	assert(ipa_log_level_by_name("debug") == LDEBUG);
	assert(ipa_log_level_by_name("Error") == LERROR);

	/* An abbreviation must not match: "ES10" would have to pick between ES10x and ES10b. */
	assert(ipa_log_subsys_by_name("ES10") == -1);
	assert(ipa_log_level_by_name("DEB") == -1);

	/* And neither must a name with something appended. */
	assert(ipa_log_subsys_by_name("MAINX") == -1);

	assert(ipa_log_subsys_by_name("bogus") == -1);
	assert(ipa_log_level_by_name("bogus") == -1);
	assert(ipa_log_subsys_by_name(NULL) == -1);
	assert(ipa_log_level_by_name(NULL) == -1);

	/* Out of range in the other direction. */
	assert(ipa_log_subsys_name(_NUM_LOG_SUBSYS) == NULL);
	assert(ipa_log_level_name(_NUM_LOG_LEVEL) == NULL);
}

/* Lowering a subsystem's level drops the lines above it and keeps the ones at or below it. */
static void level_filter_test(void)
{
	printf("== level_filter_test ==\n");

	ipa_log_set_level(SMAIN, LINFO);
	assert(ipa_log_get_level(SMAIN) == LINFO);

	capture_begin();
	IPA_LOGP(SMAIN, LERROR, "an error\n");
	IPA_LOGP(SMAIN, LINFO, "some info\n");
	IPA_LOGP(SMAIN, LDEBUG, "a debug line\n");
	capture_end();

	assert(strstr(captured, "an error"));
	assert(strstr(captured, "some info"));
	assert(strstr(captured, "a debug line") == NULL);

	ipa_log_set_level(SMAIN, LERROR);
	capture_begin();
	IPA_LOGP(SMAIN, LERROR, "still an error\n");
	IPA_LOGP(SMAIN, LINFO, "no longer info\n");
	capture_end();

	assert(strstr(captured, "still an error"));
	assert(strstr(captured, "no longer info") == NULL);

	ipa_log_set_level_all(LDEBUG);
}

/* The levels are per subsystem, and setting them all is just shorthand for setting each one. */
static void level_independence_test(void)
{
	printf("== level_independence_test ==\n");

	ipa_log_set_level_all(LERROR);
	assert(ipa_log_get_level(SMAIN) == LERROR);
	assert(ipa_log_get_level(SESIPA) == LERROR);

	ipa_log_set_level(SESIPA, LDEBUG);
	assert(ipa_log_get_level(SESIPA) == LDEBUG);
	assert(ipa_log_get_level(SMAIN) == LERROR);

	capture_begin();
	IPA_LOGP(SMAIN, LDEBUG, "main debug\n");
	IPA_LOGP(SESIPA, LDEBUG, "esipa debug\n");
	capture_end();

	assert(strstr(captured, "main debug") == NULL);
	assert(strstr(captured, "esipa debug"));

	/* Out of range arguments are ignored rather than written past the end of the tables. */
	ipa_log_set_level(_NUM_LOG_SUBSYS, LDEBUG);
	ipa_log_set_level(SMAIN, _NUM_LOG_LEVEL);
	assert(ipa_log_get_level(SMAIN) == LERROR);
	assert(ipa_log_get_level(_NUM_LOG_SUBSYS) == LERROR);

	ipa_log_set_level_all(LDEBUG);
}

/* Disabling a subsystem silences it completely, which is something no level can do: the lowest one still
 * prints errors. */
static void subsys_enabled_test(void)
{
	printf("== subsys_enabled_test ==\n");

	assert(ipa_log_subsys_enabled(SMAIN));

	ipa_log_set_subsys_enabled(SMAIN, false);
	assert(!ipa_log_subsys_enabled(SMAIN));

	capture_begin();
	IPA_LOGP(SMAIN, LERROR, "muted error\n");
	IPA_LOGP(SHTTP, LERROR, "audible error\n");
	capture_end();

	assert(strstr(captured, "muted error") == NULL);
	assert(strstr(captured, "audible error"));

	ipa_log_set_subsys_enabled(SMAIN, true);
	capture_begin();
	IPA_LOGP(SMAIN, LERROR, "back again\n");
	capture_end();
	assert(strstr(captured, "back again"));

	assert(!ipa_log_subsys_enabled(_NUM_LOG_SUBSYS));
	ipa_log_set_subsys_enabled(_NUM_LOG_SUBSYS, false);
	assert(ipa_log_subsys_enabled(SMAIN));
}

/* ipa_log_check() has to answer exactly what ipa_logp() would do, or the dump helpers that ask it in advance
 * would suppress output the log would have printed. */
static void check_test(void)
{
	printf("== check_test ==\n");

	ipa_log_set_level(SMAIN, LINFO);
	assert(ipa_log_check(SMAIN, LERROR));
	assert(ipa_log_check(SMAIN, LINFO));
	assert(!ipa_log_check(SMAIN, LDEBUG));

	ipa_log_set_subsys_enabled(SMAIN, false);
	assert(!ipa_log_check(SMAIN, LERROR));
	ipa_log_set_subsys_enabled(SMAIN, true);

	assert(!ipa_log_check(_NUM_LOG_SUBSYS, LERROR));
	assert(!ipa_log_check(SMAIN, _NUM_LOG_LEVEL));

	ipa_log_set_level_all(LDEBUG);
}

/* The dump helpers do their work before they have anything to log, so they consult the filter themselves. */
static void dump_helpers_test(void)
{
	const uint8_t data[] = { 0xde, 0xad, 0xbe, 0xef };
	struct ipa_buf *buf;
	NotificationEvent_t ne = { 0 };
	const char *first;
	const char *mark;
	unsigned int period;
	unsigned int i;

	printf("== dump_helpers_test ==\n");

	buf = ipa_buf_alloc(sizeof(data));
	assert(buf);
	memcpy(buf->data, data, sizeof(data));

	ipa_log_set_level_all(LDEBUG);
	capture_begin();
	ipa_hexdump_multiline(data, sizeof(data), 16, 1, SMAIN, LDEBUG);
	ipa_buf_hexdump_multiline(buf, 16, 1, SMAIN, LDEBUG);
	ipa_hexdump_multiline(NULL, 0, 16, 1, SMAIN, LDEBUG);
	capture_end();
	assert(strstr(captured, "DEADBEEF"));
	assert(strstr(captured, "(none)"));

	ipa_log_set_level(SMAIN, LERROR);
	capture_begin();
	ipa_hexdump_multiline(data, sizeof(data), 16, 1, SMAIN, LDEBUG);
	ipa_buf_hexdump_multiline(buf, 16, 1, SMAIN, LDEBUG);
	ipa_hexdump_multiline(NULL, 0, 16, 1, SMAIN, LDEBUG);
	capture_end();
	assert(captured[0] == '\0');

	/* Producing no output is not the point -- ipa_logp() would have dropped the lines anyway. The point is
	 * that a suppressed dump does no work, and that is visible: ipa_hexdump() hands out one of a small set of
	 * rotating buffers, so every row a dump formats moves the next caller one buffer along. Find the period
	 * first, so this keeps working if the number of buffers changes. */
	first = ipa_hexdump(data, 1);
	for (period = 1; period < 64; period++) {
		if (ipa_hexdump(data, 1) == first)
			break;
	}
	assert(period > 1 && period < 64);

	/* After `period` calls we are back on the same buffer -- unless the suppressed dump slipped some in. */
	mark = ipa_hexdump(data, 1);
	ipa_hexdump_multiline(data, sizeof(data), 16, 1, SMAIN, LDEBUG);
	ipa_buf_hexdump_multiline(buf, 16, 1, SMAIN, LDEBUG);
	for (i = 1; i < period; i++)
		ipa_hexdump(data, 1);
	assert(ipa_hexdump(data, 1) == mark);

	ipa_buf_free(buf);

	/* An ASN.1 dump belongs to the subsystem that asked for it: raising one interface to LDEBUG has to bring
	 * up the payloads of that interface and of no other. */
	ipa_log_set_level_all(LDEBUG);
	capture_begin();
	ipa_asn1c_dump(&asn_DEF_NotificationEvent, &ne, 1, SESIPA, LDEBUG);
	capture_end();
	assert(strstr(captured, "ESIPA"));
	assert(strstr(captured, "ES10x") == NULL);
	printf("   %s", captured);

	/* Turning one interface down leaves the other one dumping. */
	ipa_log_set_level(SESIPA, LERROR);
	capture_begin();
	ipa_asn1c_dump(&asn_DEF_NotificationEvent, &ne, 1, SESIPA, LDEBUG);
	capture_end();
	assert(captured[0] == '\0');

	capture_begin();
	ipa_asn1c_dump(&asn_DEF_NotificationEvent, &ne, 1, SES10X, LDEBUG);
	capture_end();
	assert(strstr(captured, "ES10x"));

	ipa_log_set_level_all(LDEBUG);
}

int main(int argc, char **argv)
{
	default_is_off_test();
	enabled_test();
	toggle_test();
	name_lookup_test();
	level_filter_test();
	level_independence_test();
	subsys_enabled_test();
	check_test();
	dump_helpers_test();
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
