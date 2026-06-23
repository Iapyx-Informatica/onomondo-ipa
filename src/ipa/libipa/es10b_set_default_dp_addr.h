/*
 * Copyright (c) 2025 Onomondo ApS & sysmocom - s.f.m.c. GmbH. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * =====================================================================
 * NEW in v1.1: 5.9.25 — ES10b function SetDefaultDpAddress.
 * Tag: [101] (BF65).
 *
 * Also referenced from Psmo.setDefaultDpAddress (§2.11.1.1.3); when the eIM
 * issues it as a PSMO, libipa processes it via the normal eUICC Package path
 * and does not need a direct ES10b caller.  A direct ES10b caller is only
 * needed if the host application wants to set the default SM-DP+ locally.
 *
 * SetDefaultDpAddressRequest  ::= SEQUENCE { defaultDpAddress UTF8String }
 * SetDefaultDpAddressResponse ::= SEQUENCE {
 *   setDefaultDpAddressResult INTEGER { ok(0), undefinedError(127) }
 * }
 *
 * TODO v1.1: implement es10b_set_default_dp_addr.c only if the host needs
 * direct control; otherwise rely on Psmo-driven application.
 * =====================================================================
 */

#pragma once

struct ipa_context;

int ipa_es10b_set_default_dp_addr(struct ipa_context *ctx, const char *default_dp_fqdn);
