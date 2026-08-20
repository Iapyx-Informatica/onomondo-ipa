/*
 * Copyright (c) 2026 Onomondo ApS & sysmocom - s.f.m.c. GmbH & Iapyx Informatica Ltda. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * See also: GSMA SGP.22, section 2.9: Profile Policy Management
 *           GSMA SGP.22, section 3.1.3, step 7: Profile Download and Installation
 *           GSMA SGP.32, section 3.2.3.2, step 15: Indirect Profile Download
 *
 * Profile Policy Rules (PPRs) are set by the Profile Owner in the Profile Metadata; the Rules Authorisation Table
 * (RAT) on the eUICC says which of them which Profile Owner is allowed to use, and whether the end user has to
 * consent to them. SGP.32 splits the verification between the eIM and the IPA and lets the IPA announce which of
 * the two does it (IPA Capability eimProfileMetadataVerification, see proc_euicc_data_req.c). This IPA announces
 * that it verifies the metadata itself, so the eIM sends the metadata along and expects the checks below to happen.
 *
 * The eUICC runs the same check again at installation time (its Profile Policy Enabler, SGP.22 section 2.9.3.1), so
 * this is not the only line of defence -- but it is the one that stops the download before the profile is fetched
 * and installed, and it is the only one that can tell the SM-DP+ why (cancel session reason pprNotAllowed) or ask
 * the end user for consent.
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <assert.h>
#include <BIT_STRING.h>
#include <ProfileClass.h>
#include <ProfilePolicyAuthorisationRule.h>
#include <onomondo/ipa/mem.h>
#include <onomondo/ipa/utils.h>
#include <onomondo/ipa/log.h>
#include "context.h"
#include "utils.h"
#include "es10b_get_rat.h"
#include "es10c_get_prfle_info.h"
#include "ppr.h"

/* Read named bit N of a DER BIT STRING. Bits beyond the encoded length are absent and count as zero
 * (SGP.22, section 5.7.22: "bits that are not present SHALL be considered zero"). */
static bool bit_string_get_named_bit(const BIT_STRING_t *bs, unsigned int bit)
{
	unsigned int num_bits;

	if (!bs || !bs->buf || bs->size <= 0)
		return false;

	num_bits = (unsigned int)bs->size * 8;
	if (bs->bits_unused > 0 && (unsigned int)bs->bits_unused < num_bits)
		num_bits -= (unsigned int)bs->bits_unused;
	if (bit >= num_bits)
		return false;

	return (bs->buf[bit / 8] & (0x80 >> (bit % 8))) != 0;
}

static unsigned int bit_string_num_bits(const BIT_STRING_t *bs)
{
	unsigned int num_bits;

	if (!bs || !bs->buf || bs->size <= 0)
		return 0;

	num_bits = (unsigned int)bs->size * 8;
	if (bs->bits_unused > 0 && (unsigned int)bs->bits_unused < num_bits)
		num_bits -= (unsigned int)bs->bits_unused;

	return num_bits;
}

/* Is any Profile Policy Rule at all set? pprUpdateControl (bit 0) does not count: it has no meaning in
 * ES8+.StoreMetadata (SGP.22, section 4.4.2) and the LPA ignores it in the RAT as well (section 5.7.22). */
static bool ppr_any_set(const PprIds_t *pprs)
{
	unsigned int bit;

	for (bit = PprIds_ppr1; bit < bit_string_num_bits(pprs); bit++) {
		if (bit_string_get_named_bit(pprs, bit))
			return true;
	}

	return false;
}

/* A rule this version of the specification does not define. It cannot be evaluated against the RAT, and a rule
 * that cannot be evaluated must not be installed (SGP.22, section 2.9.2.4, figure 5: "Is PPR known?"). */
static bool ppr_any_unknown_set(const PprIds_t *pprs)
{
	unsigned int bit;

	for (bit = PprIds_ppr2 + 1; bit < bit_string_num_bits(pprs); bit++) {
		if (bit_string_get_named_bit(pprs, bit))
			return true;
	}

	return false;
}

/* Compare the mccMnc of an allowedOperators entry against the one of the Profile Owner. Any nibble on the RAT side
 * may be 'E', which makes that digit a wildcard (SGP.22, section 2.9.2.1). */
static bool mcc_mnc_matches(const OCTET_STRING_t *allowed, const OCTET_STRING_t *profile_owner)
{
	int i;

	if (!allowed->buf || !profile_owner->buf || allowed->size != profile_owner->size)
		return false;

	for (i = 0; i < allowed->size; i++) {
		if ((allowed->buf[i] >> 4) != 0x0e && (allowed->buf[i] >> 4) != (profile_owner->buf[i] >> 4))
			return false;
		if ((allowed->buf[i] & 0x0f) != 0x0e && (allowed->buf[i] & 0x0f) != (profile_owner->buf[i] & 0x0f))
			return false;
	}

	return true;
}

/* Compare a gid1/gid2 of an allowedOperators entry against the one of the Profile Owner. Three cases, all from
 * SGP.22, section 2.9.2.1: an omitted value matches only an absent one on the Profile Owner side, a present but
 * empty value is a wildcard, and a present non-empty value has to match exactly. */
static bool gid_matches(const OCTET_STRING_t *allowed, const OCTET_STRING_t *profile_owner)
{
	if (!allowed)
		return profile_owner == NULL;

	if (allowed->size == 0)
		return true;

	if (!profile_owner || !profile_owner->buf || !allowed->buf || profile_owner->size != allowed->size)
		return false;

	return memcmp(allowed->buf, profile_owner->buf, allowed->size) == 0;
}

/*! Check whether an allowedOperators entry of the RAT covers a Profile Owner.
 *  \param[in] allowed one entry of a PPAR's allowedOperators list.
 *  \param[in] profile_owner profileOwner field of the profile metadata.
 *  \returns true when the entry covers that Profile Owner. */
bool ipa_ppr_operator_matches(const OperatorId_t *allowed, const OperatorId_t *profile_owner)
{
	if (!allowed || !profile_owner)
		return false;

	return mcc_mnc_matches(&allowed->mccMnc, &profile_owner->mccMnc)
	    && gid_matches(allowed->gid1, profile_owner->gid1)
	    && gid_matches(allowed->gid2, profile_owner->gid2);
}

/* Evaluate one PPR against the RAT (SGP.22, section 2.9.2.4, figure 6). The PPARs are walked in the order the eUICC
 * returned them, because the first one that allows the Profile Owner is the one whose consent flag applies. */
static int check_ppr(unsigned int ppr, const OperatorId_t *profile_owner, const RulesAuthorisationTable_t *rat,
		     bool *consent_required)
{
	int i;
	int j;

	if (!rat)
		return -EPERM;

	for (i = 0; i < rat->list.count; i++) {
		const ProfilePolicyAuthorisationRule_t *ppar = rat->list.array[i];

		if (!ppar || !bit_string_get_named_bit(&ppar->pprIds, ppr))
			continue;

		for (j = 0; j < ppar->allowedOperators.list.count; j++) {
			if (!ipa_ppr_operator_matches(ppar->allowedOperators.list.array[j], profile_owner))
				continue;

			*consent_required =
			    bit_string_get_named_bit(&ppar->pprFlags,
						     ProfilePolicyAuthorisationRule__pprFlags_consentRequired);
			return 0;
		}
	}

	/* No PPAR covers this PPR for this Profile Owner, which forbids it (a PPR for which the RAT holds no PPAR at
	 * all is forbidden for everyone). */
	return -EPERM;
}

/*! Check the Profile Policy Rules of a profile against a Rules Authorisation Table.
 *  \param[in] profile_pprs profilePolicyRules field of the profile metadata (may be NULL).
 *  \param[in] profile_owner profileOwner field of the profile metadata (may be NULL).
 *  \param[in] rat Rules Authorisation Table as read from the eUICC (may be NULL, which forbids every PPR).
 *  \param[out] consent flags of the rules the RAT allows only with end user consent (optional, may be NULL).
 *  \returns 0 when every PPR of the profile is allowed, -EPERM when at least one is not. */
int ipa_ppr_check_against_rat(const PprIds_t *profile_pprs, const OperatorId_t *profile_owner,
			      const RulesAuthorisationTable_t *rat, struct ipa_ppr_consent *consent)
{
	unsigned int ppr;

	if (consent) {
		consent->ppr1 = false;
		consent->ppr2 = false;
	}

	if (!ppr_any_set(profile_pprs))
		return 0;

	if (ppr_any_unknown_set(profile_pprs)) {
		IPA_LOGP(SIPA, LERROR,
			 "the profile metadata sets a profile policy rule that is not defined in this version of the specification!\n");
		return -EPERM;
	}

	if (!profile_owner) {
		IPA_LOGP(SIPA, LERROR,
			 "the profile metadata sets profile policy rules but names no profile owner, so no entry of the RAT can authorise them!\n");
		return -EPERM;
	}

	/* The bit numbers of ppr1 and ppr2 in PprIds are also the numbers the rules are known by, which is what makes
	 * "PPR%u" below read correctly. */
	for (ppr = PprIds_ppr1; ppr <= PprIds_ppr2; ppr++) {
		bool ppr_consent = false;

		if (!bit_string_get_named_bit(profile_pprs, ppr))
			continue;

		if (check_ppr(ppr, profile_owner, rat, &ppr_consent) < 0) {
			IPA_LOGP(SIPA, LERROR, "PPR%u is not allowed by the RAT of this eUICC!\n", ppr);
			return -EPERM;
		}

		IPA_LOGP(SIPA, LINFO, "PPR%u is allowed by the RAT of this eUICC%s\n", ppr,
			 ppr_consent ? " (end user consent required)" : "");

		if (consent && ppr_consent) {
			if (ppr == PprIds_ppr1)
				consent->ppr1 = true;
			else
				consent->ppr2 = true;
		}
	}

	return 0;
}

/* Ask the end user to consent to the rules the RAT would not allow without it (SGP.22, section 3.1.3, step 8).
 * A device that registered a callback asks it; a device that did not has nobody to ask, and what happens then was
 * decided when this was built -- see the PPR_ALLOW_WITHOUT_CONSENT option in the top level CMakeLists.txt. */
static bool consent_granted(struct ipa_context *ctx, const StoreMetadataRequest_t *metadata,
			    struct ipa_ppr_consent *consent)
{
	char *profile_name;
	char *service_provider_name;
	bool granted;

	if (!consent->ppr1 && !consent->ppr2)
		return true;

	if (!ctx->cfg->ppr_consent_cb) {
#ifdef PPR_ALLOW_WITHOUT_CONSENT
		IPA_LOGP(SIPA, LERROR,
			 "the RAT requires end user consent for the profile policy rules of this profile, but no consent callback is registered -- installing without it!\n");
		return true;
#else
		IPA_LOGP(SIPA, LERROR,
			 "the RAT requires end user consent for the profile policy rules of this profile, but no consent callback is registered -- refusing the profile!\n");
		return false;
#endif
	}

	profile_name = IPA_STR_FROM_ASN(&metadata->profileName);
	service_provider_name = IPA_STR_FROM_ASN(&metadata->serviceProviderName);
	consent->profile_name = profile_name;
	consent->service_provider_name = service_provider_name;

	granted = ctx->cfg->ppr_consent_cb(consent);

	IPA_FREE(profile_name);
	IPA_FREE(service_provider_name);
	consent->profile_name = NULL;
	consent->service_provider_name = NULL;

	if (!granted)
		IPA_LOGP(SIPA, LERROR,
			 "the end user did not consent to the profile policy rules of this profile!\n");

	return granted;
}

/* Is there an operational profile on the eUICC? profileClass is optional and defaults to operational, so an absent
 * one counts (see the DEFAULT in the ASN.1 definition of ProfileInfo). */
static int operational_profile_installed(struct ipa_context *ctx, bool *installed)
{
	struct ipa_es10c_get_prfle_info_res *res;
	int i;

	*installed = false;

	res = ipa_es10c_get_prfle_info(ctx, NULL);
	if (!res)
		return -EIO;

	if (!res->sgp32_res || res->sgp32_res->present != SGP32_ProfileInfoListResponse_PR_profileInfoListOk) {
		ipa_es10c_get_prfle_info_res_free(res);
		return -EIO;
	}

	for (i = 0; i < res->sgp32_res->choice.profileInfoListOk.list.count; i++) {
		const struct SGP32_ProfileInfo *info = res->sgp32_res->choice.profileInfoListOk.list.array[i];

		if (!info)
			continue;
		if (!info->profileClass || *info->profileClass == ProfileClass_operational) {
			*installed = true;
			break;
		}
	}

	ipa_es10c_get_prfle_info_res_free(res);
	return 0;
}

/*! Verify the Profile Policy Rules of a profile metadata against the eUICC, and obtain the consent of the end user
 *  where the RAT asks for it.
 *  \param[inout] ctx pointer to ipa_context.
 *  \param[in] metadata profile metadata as received from the SM-DP+ via the eIM (may be NULL).
 *  \returns 0 when the profile may be installed, -EPERM when a rule forbids it, -EACCES when the end user did not
 *           consent, -EIO when the eUICC could not be asked (in which case the profile must not be installed
 *           either, since nothing has been verified). */
int ipa_ppr_verify_metadata(struct ipa_context *ctx, const StoreMetadataRequest_t *metadata)
{
	struct ipa_es10b_get_rat_res *get_rat_res = NULL;
	struct ipa_ppr_consent consent = { 0 };
	bool operational_installed = false;
	int rc;

	if (!metadata || !ppr_any_set(metadata->profilePolicyRules)) {
		IPA_LOGP(SIPA, LINFO, "the profile metadata sets no profile policy rules, nothing to authorise\n");
		return 0;
	}

	get_rat_res = ipa_es10b_get_rat(ctx);
	if (!get_rat_res) {
		IPA_LOGP(SIPA, LERROR,
			 "unable to read the RAT from the eUICC, the profile policy rules of this profile cannot be authorised!\n");
		return -EIO;
	}

	rc = ipa_ppr_check_against_rat(metadata->profilePolicyRules, metadata->profileOwner, &get_rat_res->res->rat,
				       &consent);
	ipa_es10b_get_rat_res_free(get_rat_res);
	if (rc < 0)
		return rc;

	if (!consent_granted(ctx, metadata, &consent))
		return -EACCES;

	/* PPR1 says "disabling of this profile is not allowed". Installing it next to an operational profile would
	 * leave the eUICC with a profile that can never be switched away from, so it is forbidden regardless of what
	 * the RAT says (SGP.22, section 3.1.3, step 7). */
	if (!bit_string_get_named_bit(metadata->profilePolicyRules, PprIds_ppr1))
		return 0;

	rc = operational_profile_installed(ctx, &operational_installed);
	if (rc < 0) {
		IPA_LOGP(SIPA, LERROR,
			 "unable to read the list of installed profiles from the eUICC, unable to tell whether PPR1 may be installed!\n");
		return rc;
	}

	if (operational_installed) {
		IPA_LOGP(SIPA, LERROR,
			 "the profile sets PPR1 but an operational profile is already installed on this eUICC!\n");
		return -EPERM;
	}

	return 0;
}
