/*
 * Copyright (c) 2026 Onomondo ApS & sysmocom - s.f.m.c. GmbH & Iapyx Informatica Ltda. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * =====================================================================
 * NEW in v1.1: 5.9.17 — ES10b function ConfigureImmediateProfileEnabling
 * (renamed from ConfigureAutoProfileEnabling).  Tag: [89] (BF59).
 *
 * ConfigureImmediateProfileEnablingRequest ::= SEQUENCE {
 *   immediateEnableFlag [0] NULL OPTIONAL,
 *   defaultSmdpOid      [1] OBJECT IDENTIFIER OPTIONAL,
 *   defaultSmdpAddress  [2] UTF8String OPTIONAL
 * }
 * ConfigureImmediateProfileEnablingResponse ::= SEQUENCE {
 *   configImmediateEnableResult [0] INTEGER {
 *     ok(0), insufficientMemory(1), associatedEimAlreadyExists(2), undefinedError(127)
 *   }
 * }
 *
 * The same configuration the eIM can set through the configureImmediateEnable PSMO
 * (see es10b_load_euicc_pkg.c), but driven by the IPA instead.  Section 5.9.17 has
 * the eUICC reject the call with associatedEimAlreadyExists once any eIM
 * Configuration Data is present, so this is the pre-association path: the device
 * configures immediate enabling for itself while it is still unmanaged.
 * =====================================================================
 */

#pragma once

#include <stdbool.h>

struct ipa_context;

int ipa_es10b_cfg_immediate_enable(struct ipa_context *ctx, bool immediate_enable, const char *smdp_oid,
				   const char *smdp_address);
