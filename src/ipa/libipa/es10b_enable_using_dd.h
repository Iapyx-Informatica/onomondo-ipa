/*
 * Copyright (c) 2025 Onomondo ApS & sysmocom - s.f.m.c. GmbH. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * UPDATE for v1.1: 5.9.15 — ES10b function EnableUsingDD was renamed to
 * ImmediateEnable.  This file and its implementation should eventually be
 * renamed to es10b_immediate_enable.{c,h}; the exported symbol should become
 * ipa_es10b_immediate_enable(ctx, refresh_flag).  See MIGRATION.md.
 * TODO v1.1: add `bool refresh_flag` parameter (ImmediateEnableRequest.refreshFlag).
 */

 #pragma once

struct ipa_context;

/* UPDATE for v1.1: 5.9.15 — legacy name retained for source-compat; calls the
 * v1.2 ImmediateEnable function.  Prefer ipa_es10b_immediate_enable() once added. */
int ipa_es10b_enable_using_dd(struct ipa_context *ctx);
