/*
 * Copyright (c) 2026 Onomondo ApS & sysmocom - s.f.m.c. GmbH & Iapyx Informatica Ltda. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * See also: GSMA SGP.32, 5.9.20: Function (ES10b): ExecuteFallbackMechanism.
 *           NEW in v1.1.  Tag [93] (BF5D).
 *
 * Swaps the eUICC to the Fallback Profile (previously tagged via
 * Psmo.setFallbackAttribute) when the enabled profile lost connectivity.
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <onomondo/ipa/mem.h>
#include <onomondo/ipa/utils.h>
#include <onomondo/ipa/scard.h>
#include <onomondo/ipa/log.h>
#include <ExecuteFallbackMechanismRequest.h>
#include <ExecuteFallbackMechanismResponse.h>
#include "context.h"
#include "utils.h"
#include "euicc.h"
#include "es10x.h"
#include "es10c_enable_prfle.h"
#include "es10c_get_prfle_info.h"
#include "es10b_execute_fallback.h"

static const struct num_str_map error_code_strings[] = {
	{ ExecuteFallbackMechanismResponse__executeFallbackMechanismResult_ok, "ok" },
	{ ExecuteFallbackMechanismResponse__executeFallbackMechanismResult_profileNotInDisabledState,
	  "profileNotInDisabledState" },
	{ ExecuteFallbackMechanismResponse__executeFallbackMechanismResult_catBusy, "catBusy" },
	{ ExecuteFallbackMechanismResponse__executeFallbackMechanismResult_fallbackNotAvailable,
	  "fallbackNotAvailable" },
	{ ExecuteFallbackMechanismResponse__executeFallbackMechanismResult_commandError, "commandError" },
	{ ExecuteFallbackMechanismResponse__executeFallbackMechanismResult_ecallActive, "ecallActive" },
	{ ExecuteFallbackMechanismResponse__executeFallbackMechanismResult_undefinedError, "undefinedError" },
	{ 0, NULL }
};

static int dec_execute_fallback_res(const struct ipa_buf *es10b_res)
{
	struct ExecuteFallbackMechanismResponse *asn = NULL;
	int rc;

	asn = ipa_es10x_res_dec(&asn_DEF_ExecuteFallbackMechanismResponse, es10b_res, "ExecuteFallbackMechanism");
	if (!asn)
		return -EINVAL;

	rc = asn->executeFallbackMechanismResult;
	if (rc == ExecuteFallbackMechanismResponse__executeFallbackMechanismResult_ok)
		IPA_LOGP_ES10X("ExecuteFallbackMechanism", LINFO, "function succeeded with status code %d=%s\n",
			       rc, ipa_str_from_num(error_code_strings, rc, "(unknown)"));
	else
		IPA_LOGP_ES10X("ExecuteFallbackMechanism", LERROR, "function failed with error code %d=%s\n",
			       rc, ipa_str_from_num(error_code_strings, rc, "(unknown)"));

	ASN_STRUCT_FREE(asn_DEF_ExecuteFallbackMechanismResponse, asn);
	return rc;
}

/* SGP.32 section 5.9.20 against a consumer eUICC, which has no Fallback Mechanism of its own: the
 * Fallback Profile is whichever ICCID the setFallbackAttribute PSMO recorded in nvstate, and the swap
 * is two ordinary ES10c operations.
 *
 * The ordering below is not the spec's. Section 5.9.20 has the eUICC disable the enabled Profile and
 * then enable the Fallback Profile, atomically. We cannot be atomic over two ES10c commands, so we
 * enable the Fallback Profile first: ES10c EnableProfile on a consumer eUICC implicitly disables the
 * previously enabled one, which gets us the same end state in a single command that either succeeds
 * or leaves everything alone. Doing it the other way round would leave the eUICC with no enabled
 * Profile if the second command failed.
 *
 * refresh_flag is passed through to ES10c, which handles the REFRESH itself. */
static int execute_fallback_emu(struct ipa_context *ctx, bool refresh_flag)
{
	struct ipa_es10c_get_prfle_info_res *get_prfle_info_res = NULL;
	struct ipa_es10c_enable_prfle_req enable_prfle_req = { 0 };
	struct ipa_es10c_enable_prfle_res *enable_prfle_res = NULL;
	const struct SGP32_ProfileInfo *fallback;
	int rc = ExecuteFallbackMechanismResponse__executeFallbackMechanismResult_undefinedError;

	/* A Profile must carry the Fallback Attribute. */
	if (!IPA_EMU_FALLBACK_SET(ctx)) {
		IPA_LOGP_ES10X("ExecuteFallbackMechanism", LERROR,
			       "IoT eUICC emulation active, but no fallback profile is set\n");
		return ExecuteFallbackMechanismResponse__executeFallbackMechanismResult_fallbackNotAvailable;
	}

	get_prfle_info_res = ipa_es10c_get_prfle_info(ctx, NULL);
	if (!get_prfle_info_res)
		goto leave;

	/* There must be an enabled Profile to fall back from. */
	if (!get_prfle_info_res->currently_active_prfle) {
		IPA_LOGP_ES10X("ExecuteFallbackMechanism", LERROR,
			       "IoT eUICC emulation active, but no profile is enabled\n");
		rc = ExecuteFallbackMechanismResponse__executeFallbackMechanismResult_commandError;
		goto leave;
	}

	/* The eUICC must still have the Fallback Profile, and it must be disabled. */
	fallback = ipa_es10c_prfle_by_iccid(get_prfle_info_res, ctx->nvstate.iot_euicc_emu.fallback_iccid);
	if (!fallback) {
		IPA_LOGP_ES10X("ExecuteFallbackMechanism", LERROR,
			       "IoT eUICC emulation active, but the fallback profile is gone from the eUICC\n");
		rc = ExecuteFallbackMechanismResponse__executeFallbackMechanismResult_fallbackNotAvailable;
		goto leave;
	}
	if (ipa_es10c_prfle_is_enabled(fallback)) {
		IPA_LOGP_ES10X("ExecuteFallbackMechanism", LERROR,
			       "IoT eUICC emulation active, but the fallback profile is already enabled\n");
		rc = ExecuteFallbackMechanismResponse__executeFallbackMechanismResult_profileNotInDisabledState;
		goto leave;
	}

	/* The Emergency Profile check of section 5.9.20 has no counterpart here: ecallIndication is part
	 * of the SGP.32 Profile Metadata and a consumer eUICC never reports it, so there is nothing to
	 * test against and no Emergency Profile that could be enabled. */

	if (!get_prfle_info_res->currently_active_prfle->iccid ||
	    get_prfle_info_res->currently_active_prfle->iccid->size != IPA_LEN_ICCID) {
		IPA_LOGP_ES10X("ExecuteFallbackMechanism", LERROR,
			       "IoT eUICC emulation active, but the enabled profile has no usable ICCID\n");
		goto leave;
	}

	enable_prfle_req.req.profileIdentifier.present = EnableProfileRequest__profileIdentifier_PR_iccid;
	enable_prfle_req.req.profileIdentifier.choice.iccid = *fallback->iccid;
	enable_prfle_req.req.refreshFlag = refresh_flag;

	enable_prfle_res = ipa_es10c_enable_prfle(ctx, &enable_prfle_req);
	if (!enable_prfle_res || enable_prfle_res->res->enableResult != EnableProfileResponse__enableResult_ok) {
		IPA_LOGP_ES10X("ExecuteFallbackMechanism", LERROR,
			       "IoT eUICC emulation active, but enabling the fallback profile failed\n");
		goto leave;
	}

	/* Remember what to come back to; see ipa_es10b_return_from_fallback(). */
	memcpy(ctx->nvstate.iot_euicc_emu.pre_fallback_iccid,
	       get_prfle_info_res->currently_active_prfle->iccid->buf, IPA_LEN_ICCID);
	IPA_LOGP_ES10X("ExecuteFallbackMechanism", LINFO,
		       "IoT eUICC emulation active, fell back to ICCID %s (was ICCID %s)\n",
		       ipa_hexdump(ctx->nvstate.iot_euicc_emu.fallback_iccid, IPA_LEN_ICCID),
		       ipa_hexdump(ctx->nvstate.iot_euicc_emu.pre_fallback_iccid, IPA_LEN_ICCID));
	rc = ExecuteFallbackMechanismResponse__executeFallbackMechanismResult_ok;

leave:
	ipa_es10c_enable_prfle_res_free(enable_prfle_res);
	ipa_es10c_get_prfle_info_res_free(get_prfle_info_res);
	return rc;
}

static int execute_fallback(struct ipa_context *ctx, bool refresh_flag)
{
	struct ipa_buf *es10b_req = NULL;
	struct ipa_buf *es10b_res = NULL;
	struct ExecuteFallbackMechanismRequest req = { 0 };
	int rc = -EINVAL;

	req.refreshFlag = refresh_flag ? 1 : 0;

	es10b_req = ipa_es10x_req_enc(&asn_DEF_ExecuteFallbackMechanismRequest, &req, "ExecuteFallbackMechanism");
	if (!es10b_req) {
		IPA_LOGP_ES10X("ExecuteFallbackMechanism", LERROR, "unable to encode ES10b request\n");
		goto error;
	}

	es10b_res = ipa_euicc_transceive_es10x(ctx, es10b_req);
	if (!es10b_res) {
		IPA_LOGP_ES10X("ExecuteFallbackMechanism", LERROR, "no ES10b response\n");
		goto error;
	}

	rc = dec_execute_fallback_res(es10b_res);

error:
	IPA_FREE(es10b_req);
	IPA_FREE(es10b_res);
	return rc;
}

/*! Function (ES10b): ExecuteFallbackMechanism.
 *  \param[inout] ctx pointer to ipa_context.
 *  \param[in] refresh_flag request a UICC REFRESH after the swap.
 *  \returns eUICC result code (0 = ok, positive = eUICC error status), negative on transport error. */
int ipa_es10b_execute_fallback(struct ipa_context *ctx, bool refresh_flag)
{
	if (IPA_EUICC_EMU(ctx))
		return execute_fallback_emu(ctx, refresh_flag);
	else
		return execute_fallback(ctx, refresh_flag);
}
