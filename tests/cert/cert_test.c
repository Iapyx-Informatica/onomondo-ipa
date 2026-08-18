/*
 * Copyright (c) 2026 Onomondo ApS & sysmocom - s.f.m.c. GmbH & Iapyx Informatica Ltda. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <stdbool.h>
#include <time.h>
#include <onomondo/ipa/utils.h>
#include "src/ipa/libipa/cert.h"

/* 2026-01-01T00:00:00Z, the moment every case below is judged against. */
#define NOW 1767225600

static void set_time(Time_t *t, Time_PR present, const char *str)
{
	memset(t, 0, sizeof(*t));
	t->present = present;
	switch (present) {
	case Time_PR_utcTime:
		t->choice.utcTime.buf = (uint8_t *) str;
		t->choice.utcTime.size = strlen(str);
		break;
	case Time_PR_generalTime:
		t->choice.generalTime.buf = (uint8_t *) str;
		t->choice.generalTime.size = strlen(str);
		break;
	default:
		break;
	}
}

/* Build a certificate that carries nothing but a validity period. Everything ipa_cert_check_validity_at() looks at
 * lives in tbsCertificate.validity, so there is no need to decode a real certificate here. */
static void set_validity(Certificate_t *cert, Time_PR present, const char *not_before, const char *not_after)
{
	memset(cert, 0, sizeof(*cert));
	set_time(&cert->tbsCertificate.validity.notBefore, present, not_before);
	set_time(&cert->tbsCertificate.validity.notAfter, present, not_after);
}

static void utc_time_test(void)
{
	Certificate_t cert;

	/* Inside the period. */
	set_validity(&cert, Time_PR_utcTime, "250101000000Z", "270101000000Z");
	assert(ipa_cert_check_validity_at(&cert, "test", NOW) == 0);

	/* Expired, by a second and by a year. */
	set_validity(&cert, Time_PR_utcTime, "250101000000Z", "251231235959Z");
	assert(ipa_cert_check_validity_at(&cert, "test", NOW) == -EINVAL);
	set_validity(&cert, Time_PR_utcTime, "230101000000Z", "240101000000Z");
	assert(ipa_cert_check_validity_at(&cert, "test", NOW) == -EINVAL);

	/* Not valid yet. */
	set_validity(&cert, Time_PR_utcTime, "270101000000Z", "280101000000Z");
	assert(ipa_cert_check_validity_at(&cert, "test", NOW) == -EINVAL);

	/* Both endpoints belong to the period (RFC 5280, section 4.1.2.5). */
	set_validity(&cert, Time_PR_utcTime, "260101000000Z", "270101000000Z");
	assert(ipa_cert_check_validity_at(&cert, "test", NOW) == 0);
	set_validity(&cert, Time_PR_utcTime, "250101000000Z", "260101000000Z");
	assert(ipa_cert_check_validity_at(&cert, "test", NOW) == 0);

	/* One second outside either endpoint is not. */
	set_validity(&cert, Time_PR_utcTime, "260101000001Z", "270101000000Z");
	assert(ipa_cert_check_validity_at(&cert, "test", NOW) == -EINVAL);
	set_validity(&cert, Time_PR_utcTime, "250101000000Z", "251231235959Z");
	assert(ipa_cert_check_validity_at(&cert, "test", NOW) == -EINVAL);

	/* The two digit year is read per RFC 5280, section 4.1.2.5.1: YY >= 50 means 19YY. A certificate that
	 * claims to run until "99" therefore expired in 1999 and must not be taken for one valid until 2099. */
	set_validity(&cert, Time_PR_utcTime, "970101000000Z", "990101000000Z");
	assert(ipa_cert_check_validity_at(&cert, "test", NOW) == -EINVAL);
}

static void general_time_test(void)
{
	Certificate_t cert;

	set_validity(&cert, Time_PR_generalTime, "20250101000000Z", "20270101000000Z");
	assert(ipa_cert_check_validity_at(&cert, "test", NOW) == 0);

	set_validity(&cert, Time_PR_generalTime, "20230101000000Z", "20240101000000Z");
	assert(ipa_cert_check_validity_at(&cert, "test", NOW) == -EINVAL);

	set_validity(&cert, Time_PR_generalTime, "20270101000000Z", "20280101000000Z");
	assert(ipa_cert_check_validity_at(&cert, "test", NOW) == -EINVAL);

	/* Beyond 2049 a certificate must use generalTime. Where time_t is 64 bit that date is read correctly; on a
	 * 32 bit build it cannot be represented at all, and the certificate is then refused rather than silently
	 * accepted -- which is the safe way round, and is what is asserted here. */
	set_validity(&cert, Time_PR_generalTime, "20250101000000Z", "20510101000000Z");
	if (sizeof(time_t) > 4)
		assert(ipa_cert_check_validity_at(&cert, "test", NOW) == 0);
	else
		assert(ipa_cert_check_validity_at(&cert, "test", NOW) == -EINVAL);
}

/* A malformed or absent validity period is a reason to refuse the certificate, not to wave it through. */
static void malformed_test(void)
{
	Certificate_t cert;

	set_validity(&cert, Time_PR_utcTime, "250101000000Z", "not a timestamp");
	assert(ipa_cert_check_validity_at(&cert, "test", NOW) == -EINVAL);

	set_validity(&cert, Time_PR_utcTime, "", "");
	assert(ipa_cert_check_validity_at(&cert, "test", NOW) == -EINVAL);

	set_validity(&cert, Time_PR_NOTHING, "", "");
	assert(ipa_cert_check_validity_at(&cert, "test", NOW) == -EINVAL);

	/* Not printable, and not to be passed on to the log as it stands. */
	set_validity(&cert, Time_PR_utcTime, "250101000000Z", "\x1b[31m\x07oops");
	assert(ipa_cert_check_validity_at(&cert, "test", NOW) == -EINVAL);
}

/* ipa_cert_check_validity() reads the system clock, so what it returns depends on two things this test cannot
 * choose: whether the clock on the build machine is set, and whether the build skips or fails the check when it is
 * not (CERT_ALLOW_UNSET_CLOCK). Both are known here, so both cases can still be asserted exactly. */
static void system_clock_test(void)
{
	Certificate_t cert;
	bool clock_set = time(NULL) >= IPA_CERT_CLOCK_VALID_AFTER;
#ifdef CERT_ALLOW_UNSET_CLOCK
	int unset_clock_rc = 0;
#else
	int unset_clock_rc = -EINVAL;
#endif

	/* Valid over the whole range the clock can plausibly hold: accepted whenever the clock can be trusted. */
	set_validity(&cert, Time_PR_generalTime, "20000101000000Z", "20370101000000Z");
	assert(ipa_cert_check_validity(&cert, "test") == (clock_set ? 0 : unset_clock_rc));

	/* Long expired: refused whenever the clock can be trusted. */
	set_validity(&cert, Time_PR_generalTime, "20000101000000Z", "20010101000000Z");
	assert(ipa_cert_check_validity(&cert, "test") == (clock_set ? -EINVAL : unset_clock_rc));
}

int main(int argc, char **argv)
{
	utc_time_test();
	general_time_test();
	malformed_test();
	system_clock_test();
	printf("cert_test: all checks passed\n");
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
