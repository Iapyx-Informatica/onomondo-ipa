/*
 * Copyright (c) 2025 Onomondo ApS & sysmocom - s.f.m.c. GmbH. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * =====================================================================
 * NEW in v1.1: 5.9.20 — ES10b function ExecuteFallbackMechanism.
 * Tag: [93] (BF5D).
 *
 * ExecuteFallbackMechanismRequest ::= SEQUENCE { refreshFlag BOOLEAN }
 * ExecuteFallbackMechanismResponse ::= SEQUENCE {
 *   executeFallbackMechanismResult [0] INTEGER {
 *     ok(0), profileNotInDisabledState(2), catBusy(5),
 *     fallbackNotAvailable(6), commandError(7),
 *     ecallActive(104), undefinedError(127)
 *   }
 * }
 *
 * Used when an IPA must swap to the Fallback Profile because the currently
 * enabled profile lost connectivity.  The Fallback Profile must first have
 * been tagged via Psmo.setFallbackAttribute; see proc_euicc_pkg_dwnld_exec.c.
 *
 * Implemented in es10b_execute_fallback.c, including the IoT eUICC emulation.  For
 * IPAd usage this is triggered by host logic when the radio stack fails to register
 * with the enabled profile; the library never calls it on its own.
 * =====================================================================
 */

#pragma once

#include <stdbool.h>

struct ipa_context;

int ipa_es10b_execute_fallback(struct ipa_context *ctx, bool refresh_flag);
