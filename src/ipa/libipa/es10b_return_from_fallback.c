/*
 * Copyright (c) 2026 Onomondo ApS & sysmocom - s.f.m.c. GmbH & Iapyx Informatica Ltda. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * See also: GSMA SGP.32, 5.9.21: Function (ES10b): ReturnFromFallback.
 *           NEW in v1.1.  Tag [94] (BF5E).
 *
 * Inverse of ExecuteFallbackMechanism: returns the eUICC to the previously
 * enabled operational profile.
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <onomondo/ipa/mem.h>
#include <onomondo/ipa/utils.h>
#include <onomondo/ipa/scard.h>
#include <onomondo/ipa/log.h>
#include <ReturnFromFallbackRequest.h>
#include <ReturnFromFallbackResponse.h>
#include "context.h"
#include "utils.h"
#include "euicc.h"
#include "es10x.h"
#include "esipa_get_eim_pkg.h"
#include "es10c_enable_prfle.h"
#include "es10c_get_prfle_info.h"
#include "es10b_return_from_fallback.h"

static const struct num_str_map error_code_strings[] = {
	{ ReturnFromFallbackResponse__returnFromFallbackResult_ok, "ok" },
	{ ReturnFromFallbackResponse__returnFromFallbackResult_catBusy, "catBusy" },
	{ ReturnFromFallbackResponse__returnFromFallbackResult_fallbackNotAvailable, "fallbackNotAvailable" },
	{ ReturnFromFallbackResponse__returnFromFallbackResult_commandError, "commandError" },
	{ ReturnFromFallbackResponse__returnFromFallbackResult_undefinedError, "undefinedError" },
	{ 0, NULL }
};

static int dec_return_from_fallback_res(const struct ipa_buf *es10b_res)
{
	struct ReturnFromFallbackResponse *asn = NULL;
	int rc;

	asn = ipa_es10x_res_dec(&asn_DEF_ReturnFromFallbackResponse, es10b_res, "ReturnFromFallback");
	if (!asn)
		return -EINVAL;

	rc = asn->returnFromFallbackResult;
	if (rc == ReturnFromFallbackResponse__returnFromFallbackResult_ok)
		IPA_LOGP_ES10X("ReturnFromFallback", LINFO, "function succeeded with status code %d=%s\n",
			       rc, ipa_str_from_num(error_code_strings, rc, "(unknown)"));
	else
		IPA_LOGP_ES10X("ReturnFromFallback", LERROR, "function failed with error code %d=%s\n",
			       rc, ipa_str_from_num(error_code_strings, rc, "(unknown)"));

	ASN_STRUCT_FREE(asn_DEF_ReturnFromFallbackResponse, asn);
	return rc;
}

/*! Function (ES10b): ReturnFromFallback.
 *  \param[inout] ctx pointer to ipa_context.
 *  \param[in] refresh_flag request a UICC REFRESH after the swap.
 *  \returns eUICC result code (0 = ok, positive = eUICC error status), negative on transport error. */
/* SGP.32 section 5.9.21 against a consumer eUICC. The "Profile that was previously enabled" is the
 * one execute_fallback_emu() recorded on its way out; a real IoT eUICC keeps that internally.
 *
 * As there, the swap is a single ES10c EnableProfile, which implicitly disables the Fallback Profile.
 * refresh_flag is passed through to ES10c, which handles the REFRESH itself. */
static int return_from_fallback_emu(struct ipa_context *ctx, bool refresh_flag)
{
	struct ipa_es10c_get_prfle_info_res *get_prfle_info_res = NULL;
	struct ipa_es10c_enable_prfle_req enable_prfle_req = { 0 };
	struct ipa_es10c_enable_prfle_res *enable_prfle_res = NULL;
	const struct SGP32_ProfileInfo *previous;
	int rc = ReturnFromFallbackResponse__returnFromFallbackResult_undefinedError;

	get_prfle_info_res = ipa_es10c_get_prfle_info(ctx, NULL);
	if (!get_prfle_info_res)
		goto leave;

	/* The enabled Profile must be the Fallback Profile, otherwise there is nothing to return from. */
	if (!IPA_EMU_FALLBACK_SET(ctx) || !get_prfle_info_res->currently_active_prfle ||
	    get_prfle_info_res->currently_active_prfle !=
	    ipa_es10c_prfle_by_iccid(get_prfle_info_res, ctx->nvstate.iot_euicc_emu.fallback_iccid)) {
		IPA_LOGP_ES10X("ReturnFromFallback", LERROR,
			       "IoT eUICC emulation active, but the fallback profile is not the enabled one\n");
		rc = ReturnFromFallbackResponse__returnFromFallbackResult_fallbackNotAvailable;
		goto leave;
	}

	/* Section 5.9.21 does not name a result for "the previous Profile is gone", because a real eUICC
	 * cannot lose it. Here it can: it may have been deleted while the fallback was in effect. */
	previous = ipa_es10c_prfle_by_iccid(get_prfle_info_res, ctx->nvstate.iot_euicc_emu.pre_fallback_iccid);
	if (!previous) {
		IPA_LOGP_ES10X("ReturnFromFallback", LERROR,
			       "IoT eUICC emulation active, but the profile enabled before the fallback is gone\n");
		rc = ReturnFromFallbackResponse__returnFromFallbackResult_commandError;
		goto leave;
	}

	enable_prfle_req.req.profileIdentifier.present = EnableProfileRequest__profileIdentifier_PR_iccid;
	enable_prfle_req.req.profileIdentifier.choice.iccid = *previous->iccid;
	enable_prfle_req.req.refreshFlag = refresh_flag;

	enable_prfle_res = ipa_es10c_enable_prfle(ctx, &enable_prfle_req);
	if (!enable_prfle_res || enable_prfle_res->res->enableResult != EnableProfileResponse__enableResult_ok) {
		IPA_LOGP_ES10X("ReturnFromFallback", LERROR,
			       "IoT eUICC emulation active, but re-enabling the previous profile failed\n");
		goto leave;
	}

	IPA_LOGP_ES10X("ReturnFromFallback", LINFO,
		       "IoT eUICC emulation active, returned from fallback to ICCID %s\n",
		       ipa_hexdump(ctx->nvstate.iot_euicc_emu.pre_fallback_iccid, IPA_LEN_ICCID));
	memset(ctx->nvstate.iot_euicc_emu.pre_fallback_iccid, 0, IPA_LEN_ICCID);
	rc = ReturnFromFallbackResponse__returnFromFallbackResult_ok;

leave:
	ipa_es10c_enable_prfle_res_free(enable_prfle_res);
	ipa_es10c_get_prfle_info_res_free(get_prfle_info_res);
	return rc;
}

static int return_from_fallback(struct ipa_context *ctx, bool refresh_flag)
{
	struct ipa_buf *es10b_req = NULL;
	struct ipa_buf *es10b_res = NULL;
	struct ReturnFromFallbackRequest req = { 0 };
	int rc = -EINVAL;

	req.refreshFlag = refresh_flag ? 1 : 0;

	es10b_req = ipa_es10x_req_enc(&asn_DEF_ReturnFromFallbackRequest, &req, "ReturnFromFallback");
	if (!es10b_req) {
		IPA_LOGP_ES10X("ReturnFromFallback", LERROR, "unable to encode ES10b request\n");
		goto error;
	}

	es10b_res = ipa_euicc_transceive_es10x(ctx, es10b_req);
	if (!es10b_res) {
		IPA_LOGP_ES10X("ReturnFromFallback", LERROR, "no ES10b response\n");
		goto error;
	}

	rc = dec_return_from_fallback_res(es10b_res);

error:
	IPA_FREE(es10b_req);
	IPA_FREE(es10b_res);
	return rc;
}

/*! Function (ES10b): ReturnFromFallback.
 *  \param[inout] ctx pointer to ipa_context.
 *  \param[in] refresh_flag request a UICC REFRESH after the swap.
 *  \returns eUICC result code (0 = ok, positive = eUICC error status), negative on transport error. */
int ipa_es10b_return_from_fallback(struct ipa_context *ctx, bool refresh_flag)
{
	int rc;

	if (IPA_EUICC_EMU(ctx))
		rc = return_from_fallback_emu(ctx, refresh_flag);
	else
		rc = return_from_fallback(ctx, refresh_flag);

	/* Coming back is as much a Fallback-caused change as going out; the enumeration has one value
	 * for both, and notifyStateChange has the eIM re-read the states either way. */
	if (rc == ReturnFromFallbackResponse__returnFromFallbackResult_ok)
		ipa_esipa_note_state_change(ctx, IPA_STATE_CHANGE_FALLBACK);

	return rc;
}
