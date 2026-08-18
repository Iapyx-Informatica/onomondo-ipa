/*
 * Copyright (c) 2026 Onomondo ApS & sysmocom - s.f.m.c. GmbH & Iapyx Informatica Ltda. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * See also: IETF RFC 5280, section 4.1.2.5: Validity
 *           GSMA SGP.22, section 4.5.2: Certificate description
 */

#pragma once

#include <time.h>
#include <Certificate.h>

/*! Lower bound for a system clock that may be used to judge a certificate. A clock that reads earlier than this
 *  cannot have been set, and is treated as "no clock" rather than as "every certificate is not valid yet".
 *  (2025-01-01T00:00:00Z, before the first release of this software.)
 *
 *  Whether an unset clock then fails the check or skips it is a build time decision, see the CERT_ALLOW_UNSET_CLOCK
 *  option in the top level CMakeLists.txt. */
#define IPA_CERT_CLOCK_VALID_AFTER 1735689600

int ipa_cert_check_validity_at(const Certificate_t *cert, const char *cert_name, time_t now);
int ipa_cert_check_validity(const Certificate_t *cert, const char *cert_name);
