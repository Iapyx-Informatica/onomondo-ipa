/*
 * Copyright (c) 2025 Onomondo ApS & sysmocom - s.f.m.c. GmbH. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * =====================================================================
 * NEW in v1.1: 5.9.23 — ES10b function DisableEmergencyProfile.
 * Tag: [92] (BF5C).
 *
 * DisableEmergencyProfileRequest  ::= SEQUENCE { refreshFlag BOOLEAN }
 * DisableEmergencyProfileResponse ::= SEQUENCE {
 *   disableEmergencyProfileResult [0] INTEGER {
 *     ok(0), profileNotInEnabledState(2), catBusy(5), undefinedError(127)
 *   }
 * }
 *
 * UPDATE for v1.2: CR111007R00 — rollback authorization MUST also be reset
 * when refreshFlag == true.
 *
 * Implemented in es10b_disable_emergency_profile.c.
 * =====================================================================
 */

#pragma once

#include <stdbool.h>

struct ipa_context;

int ipa_es10b_disable_emergency_profile(struct ipa_context *ctx, bool refresh_flag);
