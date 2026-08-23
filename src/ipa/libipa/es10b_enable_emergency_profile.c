/*
 * Copyright (c) 2026 Onomondo ApS & sysmocom - s.f.m.c. GmbH & Iapyx Informatica Ltda. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * See also: GSMA SGP.32, 5.9.22: Function (ES10b): EnableEmergencyProfile.
 *           NEW in v1.1.  Tag [91] (BF5B).
 *
 * UPDATE for v1.2: CR111007R00 — the eUICC resets rollback authorization when
 * refreshFlag == true; the IPA merely conveys the flag.
 *
 * Only meaningful on devices that support eCall use cases
 * (IoTSpecificInfo.ecallSupported set).
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <onomondo/ipa/mem.h>
#include <onomondo/ipa/utils.h>
#include <onomondo/ipa/scard.h>
#include <onomondo/ipa/log.h>
#include <EnableEmergencyProfileRequest.h>
#include <EnableEmergencyProfileResponse.h>
#include "context.h"
#include "utils.h"
#include "euicc.h"
#include "es10x.h"
#include "esipa_get_eim_pkg.h"
#include "es10b_enable_emergency_profile.h"

static const struct num_str_map error_code_strings[] = {
	{ EnableEmergencyProfileResponse__enableEmergencyProfileResult_ok, "ok" },
	{ EnableEmergencyProfileResponse__enableEmergencyProfileResult_profileNotInDisabledState,
	  "profileNotInDisabledState" },
	{ EnableEmergencyProfileResponse__enableEmergencyProfileResult_catBusy, "catBusy" },
	{ EnableEmergencyProfileResponse__enableEmergencyProfileResult_ecallNotAvailable, "ecallNotAvailable" },
	{ EnableEmergencyProfileResponse__enableEmergencyProfileResult_undefinedError, "undefinedError" },
	{ 0, NULL }
};

static int dec_enable_emergency_profile_res(const struct ipa_buf *es10b_res)
{
	struct EnableEmergencyProfileResponse *asn = NULL;
	int rc;

	asn = ipa_es10x_res_dec(&asn_DEF_EnableEmergencyProfileResponse, es10b_res, "EnableEmergencyProfile");
	if (!asn)
		return -EINVAL;

	rc = asn->enableEmergencyProfileResult;
	if (rc == EnableEmergencyProfileResponse__enableEmergencyProfileResult_ok)
		IPA_LOGP_ES10X("EnableEmergencyProfile", LINFO, "function succeeded with status code %d=%s\n",
			       rc, ipa_str_from_num(error_code_strings, rc, "(unknown)"));
	else
		IPA_LOGP_ES10X("EnableEmergencyProfile", LERROR, "function failed with error code %d=%s\n",
			       rc, ipa_str_from_num(error_code_strings, rc, "(unknown)"));

	ASN_STRUCT_FREE(asn_DEF_EnableEmergencyProfileResponse, asn);
	return rc;
}

/*! Function (ES10b): EnableEmergencyProfile.
 *  \param[inout] ctx pointer to ipa_context.
 *  \param[in] refresh_flag request a UICC REFRESH (and rollback-auth reset, CR111007R00).
 *  \returns eUICC result code (0 = ok, positive = eUICC error status), negative on transport error. */
int ipa_es10b_enable_emergency_profile(struct ipa_context *ctx, bool refresh_flag)
{
	struct ipa_buf *es10b_req = NULL;
	struct ipa_buf *es10b_res = NULL;
	struct EnableEmergencyProfileRequest req = { 0 };
	int rc = -EINVAL;

	req.refreshFlag = refresh_flag ? 1 : 0;

	es10b_req = ipa_es10x_req_enc(&asn_DEF_EnableEmergencyProfileRequest, &req, "EnableEmergencyProfile");
	if (!es10b_req) {
		IPA_LOGP_ES10X("EnableEmergencyProfile", LERROR, "unable to encode ES10b request\n");
		goto error;
	}

	es10b_res = ipa_euicc_transceive_es10x(ctx, es10b_req);
	if (!es10b_res) {
		IPA_LOGP_ES10X("EnableEmergencyProfile", LERROR, "no ES10b response\n");
		goto error;
	}

	rc = dec_enable_emergency_profile_res(es10b_res);
	if (rc == EnableEmergencyProfileResponse__enableEmergencyProfileResult_ok)
		ipa_esipa_note_state_change(ctx, IPA_STATE_CHANGE_EMERGENCY_PROFILE);

error:
	IPA_FREE(es10b_req);
	IPA_FREE(es10b_res);
	return rc;
}
