/*
 * Copyright (c) 2025 Onomondo ApS & sysmocom - s.f.m.c. GmbH. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#pragma once

/* UPDATE for v1.2: CR111005R00 / §6.1 — SGP.32 v1.1+ mandates that the
 * User-Agent HTTP header MUST be "gsma-rsp-ipad" (or "gsma-rsp-ipae" when
 * running as IPAe).  Additional free-form information MAY follow a semicolon.
 * The original v1.0 value "Onomondo IPAd / 1.0.0 via libcurl" was not
 * compliant and would cause interop failures against a strict eIM. */
#define IPA_HTTP_USER_AGENT "gsma-rsp-ipad; Onomondo IPAd / 1.0.0 via libcurl"
#define IPA_HTTP_X_ADMIN_PROTOCOL "gsma/rsp/v2.1.0"
#define IPA_HTTP_CONTENT_TYPE "application/x-gsma-rsp-asn1"
