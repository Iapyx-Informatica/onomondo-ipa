/*
 * Copyright (c) 2025 Onomondo ApS & sysmocom - s.f.m.c. GmbH. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#pragma once

#include <AddInitialEimRequest.h>
#include <AddInitialEimResponse.h>
#include <EimConfigurationData.h>
#include <SubjectKeyIdentifier.h>
struct ipa_context;

/* GSMA SGP.32, section 5.9.4 */
struct ipa_es10b_add_init_eim_req {
	struct AddInitialEimRequest req;
};

struct ipa_es10b_add_init_eim_res {
	struct AddInitialEimResponse *res;
	long add_init_eim_err;
};

/* Validate the mandatory content of an AddInitialEimRequest, see also SGP.32, section 5.9.4. Returns 0 when the
 * request is acceptable, an AddInitialEimResponse error code otherwise. Called by ipa_es10b_add_init_eim() for
 * both eUICC flavours; exposed for the unit tests. */
long ipa_es10b_add_init_eim_validate(const struct AddInitialEimRequest *req);

/* Check that no entry presents an already resolved associationToken, see also SGP.32, section 5.9.4. Only
 * meaningful for an initial configuration supplied to the IPA, see ipa_add_init_eim_cfg(). */
long ipa_es10b_add_init_eim_check_assoc_tokens(const struct AddInitialEimRequest *req);

/* Fill in the sub-fields that a native IoT eUICC would assign itself when the IPA leaves them out, see also
 * SGP.32, section 5.9.4. Only used by the IoT eUICC emulation; a real eUICC does this on its own.
 * ci_pk_id_default may be NULL, in which case euiccCiPKId is left absent instead of being guessed.
 * Returns 0 on success, -1 when the entry cannot be stored (counterValue out of range). */
int complete_eim_cfg(struct ipa_context *ctx, struct EimConfigurationData *eim_cfg,
		     const SubjectKeyIdentifier_t *ci_pk_id_default);

struct ipa_es10b_add_init_eim_res *ipa_es10b_add_init_eim(struct ipa_context *ctx,
							  const struct ipa_es10b_add_init_eim_req *req);
void ipa_es10b_add_init_eim_res_free(struct ipa_es10b_add_init_eim_res *res);
