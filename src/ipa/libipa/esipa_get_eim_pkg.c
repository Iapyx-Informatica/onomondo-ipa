/*
 * Copyright (c) 2025 Onomondo ApS & sysmocom - s.f.m.c. GmbH. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Author: Philipp Maier <pmaier@sysmocom.de> / sysmocom - s.f.m.c. GmbH
 *
 * See also: GSMA SGP.32, section 5.14.5: Function (ESipa): GetEimPackage
 *
 * =====================================================================
 * v1.1/v1.2 migration notes for this file:
 * =====================================================================
 * UPDATE for v1.1: 5.14.5 — GetEimPackage now carries optional stateChangeCause.
 *   Table 16 makes notifyStateChange optional and stateChangeCause C(1),
 *   "mandatory if NotifyStateChange is present" -- so the two go together or
 *   not at all; there is no SHALL to send them.  Both are populated here from
 *   ctx->nvstate.state_change_cause, which ipa_esipa_note_state_change() sets
 *   at each local state change (Fallback, Emergency swap, immediate-enable,
 *   reset) and this file clears once the eIM has answered.
 * UPDATE for v1.1: 6.3.2.6 — GetEimPackageResponse.eimPackageError gains
 *   eidNotFound(2), invalidEid(3), missingEid(4).  Error table must be
 *   extended after libasn regeneration.
 * UPDATE for v1.1: 6.3.2.6 — rPLMN moved from tag [1] to tag [2] because the
 *   new stateChangeCause takes tag [1].  Purely a wire-format change handled
 *   by asn1c regeneration; no action needed here beyond regenerating.
 * =====================================================================
 */

#include <stdint.h>
#include <onomondo/ipa/http.h>
#include <onomondo/ipa/log.h>
#include <onomondo/ipa/ipad.h>
#include <EsipaMessageFromIpaToEim.h>
#include <GetEimPackageRequest.h>
#include "utils.h"
#include "length.h"
#include "context.h"
#include "esipa.h"
#include "esipa_json.h"
#include "esipa_get_eim_pkg.h"

#ifdef IPA_HAVE_ESIPA_ASN1		/* ESipa ASN.1 binding, SGP.32 section 6.3 */
static const struct num_str_map error_code_strings[] = {
	{ GetEimPackageResponse__eimPackageError_noEimPackageAvailable, "noEimPackageAvailable" },
	/* UPDATE for v1.1: 6.3.2.6 - new eIM error codes covering EID handling. */
	{ GetEimPackageResponse__eimPackageError_eidNotFound, "eidNotFound" },
	{ GetEimPackageResponse__eimPackageError_invalidEid, "invalidEid" },
	{ GetEimPackageResponse__eimPackageError_missingEid, "missingEid" },
	{ GetEimPackageResponse__eimPackageError_undefinedError, "undefinedError" },
	{ 0, NULL }
};

static struct ipa_buf *enc_get_eim_pkg_req(struct ipa_context *ctx, const void *req)
{
	const uint8_t *eid_value = req;
	struct EsipaMessageFromIpaToEim msg_to_eim = { 0 };
	StateChangeCause_t state_change_cause;
	NULL_t notify_state_change = 0;

	msg_to_eim.present = EsipaMessageFromIpaToEim_PR_getEimPackageRequest;
	msg_to_eim.choice.getEimPackageRequest.eidValue.buf = (uint8_t *) eid_value;
	msg_to_eim.choice.getEimPackageRequest.eidValue.size = IPA_LEN_EID;

	/* SGP.32 5.14.5 Table 16: notifyStateChange is optional, and stateChangeCause is C(1) --
	 * mandatory once notifyStateChange is there. They therefore go together or not at all. */
	if (ctx->nvstate.state_change_cause != IPA_STATE_CHANGE_NONE) {
		msg_to_eim.choice.getEimPackageRequest.notifyStateChange = &notify_state_change;
		state_change_cause = ctx->nvstate.state_change_cause;
		msg_to_eim.choice.getEimPackageRequest.stateChangeCause = &state_change_cause;
	}

	return ipa_esipa_msg_to_eim_enc(&msg_to_eim, "GetEimPackage");
}

static void *dec_get_eim_pkg_req(const struct ipa_buf *msg_to_ipa_encoded, const void *req)
{
	struct EsipaMessageFromEimToIpa *msg_to_ipa = NULL;
	struct ipa_esipa_get_eim_pkg_res *res = NULL;
	(void)req;

	msg_to_ipa =
	    ipa_esipa_msg_to_ipa_dec(msg_to_ipa_encoded, "GetEimPackage",
				     EsipaMessageFromEimToIpa_PR_getEimPackageResponse);
	if (!msg_to_ipa)
		return NULL;

	res = IPA_ALLOC_ZERO(struct ipa_esipa_get_eim_pkg_res);
	res->msg_to_ipa = msg_to_ipa;

	switch (msg_to_ipa->choice.getEimPackageResponse.present) {
	case GetEimPackageResponse_PR_euiccPackageRequest:
		res->euicc_package_request = &msg_to_ipa->choice.getEimPackageResponse.choice.euiccPackageRequest;
		break;
	case GetEimPackageResponse_PR_ipaEuiccDataRequest:
		res->ipa_euicc_data_request = &msg_to_ipa->choice.getEimPackageResponse.choice.ipaEuiccDataRequest;
		break;
	case GetEimPackageResponse_PR_profileDownloadTriggerRequest:
		res->dwnld_trigger_request =
		    &msg_to_ipa->choice.getEimPackageResponse.choice.profileDownloadTriggerRequest;
		break;
	case GetEimPackageResponse_PR_eimPackageError:
		res->eim_pkg_err = msg_to_ipa->choice.getEimPackageResponse.choice.eimPackageError;
		IPA_LOGP_ESIPA("GetEimPackage", LERROR, "function failed with error code %ld=%s!\n",
			       res->eim_pkg_err, ipa_str_from_num(error_code_strings, res->eim_pkg_err, "(unknown)"));
		break;
	default:
		IPA_LOGP_ESIPA("GetEimPackage", LERROR, "unexpected response content!\n");
		res->eim_pkg_err = -1;
		break;
	}

	return res;
}

#endif /* IPA_HAVE_ESIPA_ASN1 */

#ifdef IPA_HAVE_ESIPA_JSON		/* ESipa JSON binding, SGP.32 section 6.4 */
static struct ipa_buf *json_enc_get_eim_pkg_req(struct ipa_context *ctx, const void *req)
{
	/* Same coupling as the ASN.1 binding: the encoder emits stateChangeCause only for a
	 * non-negative value, and notifyStateChange only when told to, so pass both or neither. */
	bool notify = ctx->nvstate.state_change_cause != IPA_STATE_CHANGE_NONE;

	return ipa_esipa_json_enc_get_eim_pkg_req((const uint8_t *)req, notify,
						  notify ? ctx->nvstate.state_change_cause : -1);
}

static void *json_dec_get_eim_pkg_res(const struct ipa_buf *res, const void *req)
{
	(void)req;
	return ipa_esipa_json_dec_get_eim_pkg_res(res);
}

#endif /* IPA_HAVE_ESIPA_JSON */

/*! Function (ESipa): GetEimPackage.
 *  \param[inout] ctx pointer to ipa_context.
 *  \param[in] eid pointer to the eID (IPA_LEN_EID bytes).
 *  \returns pointer newly allocated struct with function result, NULL on error. */
struct ipa_esipa_get_eim_pkg_res *ipa_esipa_get_eim_pkg(struct ipa_context *ctx, const uint8_t *eid)
{
	struct ipa_esipa_get_eim_pkg_res *res;

	IPA_LOGP_ESIPA("GetEimPackage", LINFO, "Requesting eIM package for eID: %s\n", ipa_hexdump(eid, IPA_LEN_EID));

	res = ipa_esipa_call(ctx, "GetEimPackage", eid,
			     IPA_ESIPA_ASN1_CB(enc_get_eim_pkg_req, dec_get_eim_pkg_req),
			     IPA_ESIPA_JSON_CB(json_enc_get_eim_pkg_req, json_dec_get_eim_pkg_res));

	/* The report has been delivered once the eIM answered at all -- an eimPackageError still means it
	 * received the notification. A failed transaction leaves the cause pending for the next poll,
	 * which is the point of keeping it in nvstate. */
	if (res && ctx->nvstate.state_change_cause != IPA_STATE_CHANGE_NONE)
		ipa_esipa_note_state_change(ctx, IPA_STATE_CHANGE_NONE);

	return res;
}

void ipa_esipa_note_state_change(struct ipa_context *ctx, enum ipa_state_change_cause cause)
{
	static const struct num_str_map cause_strings[] = {
		{ IPA_STATE_CHANGE_OTHER_EIM, "otherEim" },
		{ IPA_STATE_CHANGE_FALLBACK, "fallback" },
		{ IPA_STATE_CHANGE_EMERGENCY_PROFILE, "emergencyProfile" },
		{ IPA_STATE_CHANGE_LOCAL, "local" },
		{ IPA_STATE_CHANGE_RESET, "reset" },
		{ IPA_STATE_CHANGE_IMMEDIATE_ENABLE_PROFILE, "immediateEnableProfile" },
		{ IPA_STATE_CHANGE_DEVICE_CHANGE, "deviceChange" },
		{ IPA_STATE_CHANGE_UNDEFINED, "undefined" },
		{ 0, NULL }
	};

	if (ctx->nvstate.state_change_cause == cause)
		return;

	if (cause == IPA_STATE_CHANGE_NONE)
		IPA_LOGP_ESIPA("GetEimPackage", LDEBUG, "state change reported to the eIM, nothing pending now\n");
	else
		IPA_LOGP_ESIPA("GetEimPackage", LINFO,
			       "eUICC state changed (%s), will notify the eIM on the next poll\n",
			       ipa_str_from_num(cause_strings, cause, "(unknown)"));

	ctx->nvstate.state_change_cause = cause;
}

/*! Free results of function (ESipa): GetEimPackage.
 *  \param[in] res pointer to function result. */
void ipa_esipa_get_eim_pkg_free(struct ipa_esipa_get_eim_pkg_res *res)
{
	IPA_ESIPA_RES_FREE(res);
}
