/*
 * Copyright (c) 2025 Onomondo ApS & sysmocom - s.f.m.c. GmbH. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#pragma once

#include <IpaEuiccDataRequest.h>
#include <IpaCapabilities.h>
struct ipa_context;

struct ipa_proc_euicc_data_req_pars {
	const struct IpaEuiccDataRequest *ipa_euicc_data_request;
};

int ipa_proc_euicc_data_req(struct ipa_context *ctx, const struct ipa_proc_euicc_data_req_pars *pars);

/* Exposed for the golden-file encode test (see tests/ipa_capabilities).  Returns a
 * pointer to static storage describing the IPA's advertised capabilities. */
struct IpaCapabilities *make_ipa_capabilties(void);
