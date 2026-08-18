/*
 * Copyright (c) 2026 Onomondo ApS & sysmocom - s.f.m.c. GmbH & Iapyx Informatica Ltda. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * See also: IETF RFC 5280, section 4.1.2.5: Validity
 *           GSMA SGP.22, section 4.5.2: Certificate description
 *
 * The eUICC is the authority on the certificates it is handed (it verifies CERT.XXauth.SIG in
 * ES10b.AuthenticateServer and CERT.DPpb.SIG in ES10b.PrepareDownload), but it has no clock of its own. The validity
 * period is therefore the one part of the verification that only the IPA can perform, and until now nobody did:
 * an expired or not-yet-valid SM-DP+ certificate was accepted without comment.
 *
 * What happens when the IPA has no trustworthy clock either is a build time decision, see the
 * CERT_ALLOW_UNSET_CLOCK option in the top level CMakeLists.txt and ipa_cert_check_validity() below.
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <onomondo/ipa/log.h>
#include <Certificate.h>
#include <UTCTime.h>
#include <GeneralizedTime.h>
#include "cert.h"

/* Render an X.509 Time the way it stands in the certificate ("YYMMDDhhmmssZ" for utcTime, "YYYYMMDDhhmmssZ" for
 * generalTime). For log output only. The bytes arrive from the network, so everything that is not printable ASCII
 * is replaced instead of being handed to the log. */
static const char *time_to_str(const Time_t *t, char *buf, size_t buf_size)
{
	const OCTET_STRING_t *str;
	size_t i;

	switch (t->present) {
	case Time_PR_utcTime:
		str = &t->choice.utcTime;
		break;
	case Time_PR_generalTime:
		str = &t->choice.generalTime;
		break;
	default:
		return "(absent)";
	}

	if (!str->buf || str->size < 0 || (size_t)str->size >= buf_size)
		return "(malformed)";

	for (i = 0; i < (size_t)str->size; i++)
		buf[i] = (str->buf[i] >= 0x20 && str->buf[i] < 0x7f) ? (char)str->buf[i] : '?';
	buf[str->size] = '\0';

	return buf;
}

/* Convert an X.509 Time into a UNIX timestamp, (time_t)-1 on error. */
static time_t time_to_time_t(const Time_t *t)
{
	switch (t->present) {
	case Time_PR_utcTime:
		/* asn_UT2time() applies the two digit year rule of RFC 5280, section 4.1.2.5.1
		 * (YY >= 50 means 19YY, YY < 50 means 20YY). */
		return asn_UT2time(&t->choice.utcTime, NULL, 0);
	case Time_PR_generalTime:
		return asn_GT2time(&t->choice.generalTime, NULL, 0);
	default:
		return (time_t)-1;
	}
}

/*! Check a certificate against a given point in time.
 *  \param[in] cert certificate to check.
 *  \param[in] cert_name name of the certificate, used in the log output.
 *  \param[in] now point in time to check the certificate against (UNIX timestamp).
 *  \returns 0 when the certificate is valid at that moment, -EINVAL otherwise. */
int ipa_cert_check_validity_at(const Certificate_t *cert, const char *cert_name, time_t now)
{
	const Validity_t *validity = &cert->tbsCertificate.validity;
	char not_before_str[32];
	char not_after_str[32];
	time_t not_before;
	time_t not_after;

	not_before = time_to_time_t(&validity->notBefore);
	not_after = time_to_time_t(&validity->notAfter);

	if (not_before == (time_t)-1 || not_after == (time_t)-1) {
		IPA_LOGP(SIPA, LERROR,
			 "unable to parse the validity period of the %s certificate (notBefore=%s, notAfter=%s)!\n",
			 cert_name, time_to_str(&validity->notBefore, not_before_str, sizeof(not_before_str)),
			 time_to_str(&validity->notAfter, not_after_str, sizeof(not_after_str)));
		return -EINVAL;
	}

	/* RFC 5280, section 4.1.2.5: the period includes both of its endpoints. */
	if (now < not_before) {
		IPA_LOGP(SIPA, LERROR, "the %s certificate is not valid yet (notBefore=%s)!\n", cert_name,
			 time_to_str(&validity->notBefore, not_before_str, sizeof(not_before_str)));
		return -EINVAL;
	}

	if (now > not_after) {
		IPA_LOGP(SIPA, LERROR, "the %s certificate has expired (notAfter=%s)!\n", cert_name,
			 time_to_str(&validity->notAfter, not_after_str, sizeof(not_after_str)));
		return -EINVAL;
	}

	return 0;
}

/*! Check a certificate against the current system time.
 *  \param[in] cert certificate to check.
 *  \param[in] cert_name name of the certificate, used in the log output.
 *  \returns 0 when the certificate is valid now, -EINVAL otherwise. When the system clock cannot be trusted the
 *           result depends on the build: -EINVAL by default, 0 when CERT_ALLOW_UNSET_CLOCK is defined. */
int ipa_cert_check_validity(const Certificate_t *cert, const char *cert_name)
{
	time_t now = time(NULL);

	if (now == (time_t)-1 || now < IPA_CERT_CLOCK_VALID_AFTER) {
#ifdef CERT_ALLOW_UNSET_CLOCK
		/* Built for a device that has no clock to set (see the CERT_ALLOW_UNSET_CLOCK option in the top level
		 * CMakeLists.txt). An unset clock is not evidence against the certificate, and refusing to
		 * authenticate on it would leave such a device permanently unable to provision itself. The check is
		 * therefore skipped rather than failed, and the fact is logged so that it is visible why. */
		IPA_LOGP(SIPA, LINFO,
			 "the system clock is not set, skipping the validity period check of the %s certificate!\n",
			 cert_name);
		return 0;
#else
		/* Without a trustworthy clock the validity period cannot be judged at all, so the certificate is
		 * refused. Build with -DCERT_ALLOW_UNSET_CLOCK=ON on a device that has no way of setting its clock
		 * before it is provisioned. */
		IPA_LOGP(SIPA, LERROR,
			 "the system clock is not set, unable to check the validity period of the %s certificate!\n",
			 cert_name);
		return -EINVAL;
#endif
	}

	return ipa_cert_check_validity_at(cert, cert_name, now);
}
