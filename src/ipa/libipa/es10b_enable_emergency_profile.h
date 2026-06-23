/*
 * Copyright (c) 2025 Onomondo ApS & sysmocom - s.f.m.c. GmbH. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * =====================================================================
 * NEW in v1.1: 5.9.22 — ES10b function EnableEmergencyProfile.
 * Tag: [91] (BF5B).
 *
 * EnableEmergencyProfileRequest  ::= SEQUENCE { refreshFlag BOOLEAN }
 * EnableEmergencyProfileResponse ::= SEQUENCE {
 *   enableEmergencyProfileResult [0] INTEGER {
 *     ok(0), profileNotInDisabledState(2), catBusy(5),
 *     ecallNotAvailable(8), undefinedError(127)
 *   }
 * }
 *
 * UPDATE for v1.2: CR111007R00 — rollback authorization MUST also be reset
 * when refreshFlag == true.
 *
 * Emergency Profile semantics: while enabled, the eUICC rejects
 * EuiccPackageRequest / EuiccMemoryResetRequest / ExecuteFallbackMechanism
 * with error code ecallActive(104) (see §2.11.2.1 of v1.2).
 *
 * TODO v1.1: implement es10b_enable_emergency_profile.c only if the device
 * supports eCall use cases (iotSpecificInfo.ecallSupported SHALL be set).
 * =====================================================================
 */

#pragma once

#include <stdbool.h>

struct ipa_context;

int ipa_es10b_enable_emergency_profile(struct ipa_context *ctx, bool refresh_flag);
