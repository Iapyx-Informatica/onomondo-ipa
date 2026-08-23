/*
 * Copyright (c) 2025 Onomondo ApS & sysmocom - s.f.m.c. GmbH. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#pragma once

#include <stdbool.h>
struct ipa_context;

/* GSMA SGP.32, section 5.9.5 (SGP.22, section 5.7.19 for the emulation branch, which only knows the
 * first three options). The public API takes these as a bitmask, see enum ipa_euicc_mem_rst_opt in
 * onomondo/ipa/ipad.h. */
struct ipa_es10b_euicc_mem_rst {
	bool operatnl_profiles;
	bool test_profiles;
	bool default_smdp_addr;
	/* NEW in SGP.32 v1.2, no equivalent in SGP.22. */
	bool pre_loaded_test_profiles;
	bool provisioning_profiles;
	bool eim_cfg_data;
	bool immediate_enable_cfg;
};

int ipa_es10b_euicc_mem_rst(struct ipa_context *ctx, const struct ipa_es10b_euicc_mem_rst *req);
