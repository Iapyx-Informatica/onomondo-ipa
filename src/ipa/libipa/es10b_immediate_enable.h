/*
 * Copyright (c) 2025 Onomondo ApS & sysmocom - s.f.m.c. GmbH. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * =====================================================================
 * NEW in v1.1: 5.9.15 — ES10b function ImmediateEnable.
 * Replaces EnableUsingDD (5.9.15 v1.0).
 * See es10b_enable_using_dd.{c,h} for the legacy implementation; this
 * header documents the target surface for the rename.
 *
 * UPDATE for v1.2: CR111007R00 — rollback authorization MUST be reset when
 * refreshFlag == true.  Same requirement applies to EnableEmergencyProfile
 * and DisableEmergencyProfile (5.9.22 / 5.9.23).
 * =====================================================================
 *
 * TODO v1.1: move the implementation in es10b_enable_using_dd.c to
 * es10b_immediate_enable.c (rename), update CMakeLists.txt, update callers.
 */

#pragma once

#include <stdbool.h>

struct ipa_context;

/* UPDATE for v1.1: 5.9.15 — new mandatory refresh_flag parameter corresponding
 * to ImmediateEnableRequest.refreshFlag BOOLEAN. */
int ipa_es10b_immediate_enable(struct ipa_context *ctx, bool refresh_flag);
