/*
 * Copyright (c) 2026 Onomondo ApS & sysmocom - s.f.m.c. GmbH & Iapyx Informatica Ltda. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * See also: GSMA SGP.22, section 2.9: Profile Policy Management
 *           GSMA SGP.22, section 3.1.3, step 7: Profile Download and Installation
 *           GSMA SGP.32, section 3.2.3.2, step 15: Indirect Profile Download
 */

#pragma once

#include <stdbool.h>
#include <OperatorId.h>
#include <PprIds.h>
#include <RulesAuthorisationTable.h>
#include <StoreMetadataRequest.h>
#include <onomondo/ipa/ipad.h>

struct ipa_context;

bool ipa_ppr_operator_matches(const OperatorId_t *allowed, const OperatorId_t *profile_owner);

/* Fills in the rule flags of consent only; the profile name and service provider name are added by
 * ipa_ppr_verify_metadata(), which is the one that has the metadata to take them from. */
int ipa_ppr_check_against_rat(const PprIds_t *profile_pprs, const OperatorId_t *profile_owner,
			      const RulesAuthorisationTable_t *rat, struct ipa_ppr_consent *consent);

int ipa_ppr_verify_metadata(struct ipa_context *ctx, const StoreMetadataRequest_t *metadata);
