/*
 * Copyright (c) 2025 Onomondo ApS & sysmocom - s.f.m.c. GmbH. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * =====================================================================
 * NEW in v1.1: 5.9.21 — ES10b function ReturnFromFallback.
 * Tag: [94] (BF5E).
 *
 * ReturnFromFallbackRequest  ::= SEQUENCE { refreshFlag BOOLEAN }
 * ReturnFromFallbackResponse ::= SEQUENCE {
 *   returnFromFallbackResult [0] INTEGER {
 *     ok(0), catBusy(5), fallbackNotAvailable(6),
 *     commandError(7), undefinedError(127)
 *   }
 * }
 *
 * Inverse of ExecuteFallbackMechanism: returns the eUICC to the previously
 * enabled operational profile.
 *
 * Implemented in es10b_return_from_fallback.c, including the IoT eUICC emulation.
 * =====================================================================
 */

#pragma once

#include <stdbool.h>

struct ipa_context;

int ipa_es10b_return_from_fallback(struct ipa_context *ctx, bool refresh_flag);
