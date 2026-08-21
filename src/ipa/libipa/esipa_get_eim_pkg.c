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
 *   When the IPA calls this after a local state change (e.g. Fallback,
 *   Emergency swap, immediate-enable, reset) it SHALL populate the cause.
 *   Requires plumbing a StateChangeCause_t through ipa_esipa_get_eim_pkg().
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
	(void)ctx;

	msg_to_eim.present = EsipaMessageFromIpaToEim_PR_getEimPackageRequest;
	msg_to_eim.choice.getEimPackageRequest.eidValue.buf = (uint8_t *) eid_value;
	msg_to_eim.choice.getEimPackageRequest.eidValue.size = IPA_LEN_EID;

	/* TODO v1.1: 5.14.5 — populate optional stateChangeCause when a local
	 * state change preceded this poll.  Example skeleton (once regenerated
	 * types are available):
	 *   StateChangeCause_t cause = StateChangeCause_immediateEnableProfile;
	 *   msg_to_eim.choice.getEimPackageRequest.stateChangeCause = &cause;
	 * The cause value should be derived from ctx state (fallback active,
	 * emergency swap, reset, immediate-enable, etc.). */

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
	(void)ctx;
	/* TODO v1.1: 5.14.5 — plumb stateChangeCause through here too (see the
	 * ASN.1 encoder's TODO); the JSON binding takes notify_state_change +
	 * cause, hardcoded to "no state change" for now. */
	return ipa_esipa_json_enc_get_eim_pkg_req((const uint8_t *)req, false, -1);
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
	IPA_LOGP_ESIPA("GetEimPackage", LINFO, "Requesting eIM package for eID: %s\n", ipa_hexdump(eid, IPA_LEN_EID));

	return ipa_esipa_call(ctx, "GetEimPackage", eid,
			      IPA_ESIPA_ASN1_CB(enc_get_eim_pkg_req, dec_get_eim_pkg_req),
			      IPA_ESIPA_JSON_CB(json_enc_get_eim_pkg_req, json_dec_get_eim_pkg_res));
}

/*! Free results of function (ESipa): GetEimPackage.
 *  \param[in] res pointer to function result. */
void ipa_esipa_get_eim_pkg_free(struct ipa_esipa_get_eim_pkg_res *res)
{
	IPA_ESIPA_RES_FREE(res);
}
