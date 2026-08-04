/*
 * Copyright (c) 2025 Onomondo ApS & sysmocom - s.f.m.c. GmbH. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Author: Philipp Maier <pmaier@sysmocom.de> / sysmocom - s.f.m.c. GmbH
 *
 * See also: GSMA SGP.32, section 5.14.8 Function (ESipa): CancelSession
 */

#include <stdint.h>
#include <errno.h>
#include <onomondo/ipa/http.h>
#include <onomondo/ipa/log.h>
#include <onomondo/ipa/ipad.h>
#include <EsipaMessageFromIpaToEim.h>
#include <CancelSessionRequestEsipa.h>
#include <CancelSessionResponseEsipa.h>
#include "utils.h"
#include "length.h"
#include "context.h"
#include "esipa.h"
#include "esipa_cancel_session.h"

static const struct num_str_map error_code_strings[] = {
	{ CancelSessionResponseEsipa__cancelSessionError_invalidTransactionId, "invalidTransactionId" },
	{ CancelSessionResponseEsipa__cancelSessionError_euiccSignatureInvalid, "euiccSignatureInvalid" },
	{ CancelSessionResponseEsipa__cancelSessionError_undefinedError, "undefinedError" },
	{ 0, NULL }
};

static struct ipa_buf *enc_cancel_session_req(struct ipa_context *ctx, const void *req_)
{
	const struct ipa_esipa_cancel_session_req *req = req_;
	struct EsipaMessageFromIpaToEim msg_to_eim = { 0 };
	(void)ctx;

	msg_to_eim.present = EsipaMessageFromIpaToEim_PR_cancelSessionRequestEsipa;
	msg_to_eim.choice.cancelSessionRequestEsipa.transactionId = *req->transaction_id;

	if (req->cancel_session_ok) {
		msg_to_eim.choice.cancelSessionRequestEsipa.cancelSessionResponse.present =
		    SGP32_CancelSessionResponse_PR_cancelSessionResponseOk;
		msg_to_eim.choice.cancelSessionRequestEsipa.cancelSessionResponse.choice.cancelSessionResponseOk =
		    *req->cancel_session_ok;
	} else {
		msg_to_eim.choice.cancelSessionRequestEsipa.cancelSessionResponse.present =
		    SGP32_CancelSessionResponse_PR_cancelSessionResponseError;
		msg_to_eim.choice.cancelSessionRequestEsipa.cancelSessionResponse.choice.cancelSessionResponseError =
		    req->cancel_session_err;
	}

	/* Encode */
	return ipa_esipa_msg_to_eim_enc(&msg_to_eim, "CancelSession");
}

static void *dec_cancel_session_res(const struct ipa_buf *msg_to_ipa_encoded, const void *req)
{
	struct EsipaMessageFromEimToIpa *msg_to_ipa = NULL;
	struct ipa_esipa_cancel_session_res *res = NULL;
	(void)req;

	msg_to_ipa = ipa_esipa_msg_to_ipa_dec(msg_to_ipa_encoded, "CancelSession",
					      EsipaMessageFromEimToIpa_PR_cancelSessionResponseEsipa);
	if (!msg_to_ipa)
		return NULL;

	res = IPA_ALLOC_ZERO(struct ipa_esipa_cancel_session_res);
	res->msg_to_ipa = msg_to_ipa;

	switch (msg_to_ipa->choice.cancelSessionResponseEsipa.present) {
	case CancelSessionResponseEsipa_PR_cancelSessionOk:
		/* This function has no output data. The eIM is indicating a successful outcome through the presence
		 * of the CancelSessionOk field */
		res->cancel_session_ok = true;
		break;
	case CancelSessionResponseEsipa_PR_cancelSessionError:
		res->cancel_session_err = msg_to_ipa->choice.cancelSessionResponseEsipa.choice.cancelSessionError;
		IPA_LOGP_ESIPA("CancelSession", LERROR, "function failed with error code %ld=%s!\n",
			       res->cancel_session_err, ipa_str_from_num(error_code_strings, res->cancel_session_err,
									 "(unknown)"));
		break;
	default:
		IPA_LOGP_ESIPA("CancelSession", LERROR, "unexpected response content!\n");
		res->cancel_session_err = -1;
	}

	return res;
}

struct ipa_buf *ipa_esipa_json_enc_cancel_session_req(const struct ipa_esipa_cancel_session_req *);

static struct ipa_buf *json_enc_cancel_session_req(struct ipa_context *ctx, const void *req)
{
	(void)ctx;
	return ipa_esipa_json_enc_cancel_session_req(req);
}

/* CancelSession has no response body in the JSON binding: a successful
 * transport is itself the acknowledgement, so synthesise an "ok" result. */
static void *json_dec_cancel_session_res(const struct ipa_buf *res_buf, const void *req)
{
	struct ipa_esipa_cancel_session_res *res;
	(void)res_buf;
	(void)req;

	res = IPA_ALLOC_ZERO(struct ipa_esipa_cancel_session_res);
	if (res)
		res->cancel_session_ok = true;
	return res;
}

/*! Function (ESipa): CancelSession.
 *  \param[inout] ctx pointer to ipa_context.
 *  \param[in] req pointer to struct that holds the function parameters.
 *  \returns pointer newly allocated struct with function result, NULL on error. */
struct ipa_esipa_cancel_session_res *ipa_esipa_cancel_session(struct ipa_context *ctx,
							      const struct ipa_esipa_cancel_session_req *req)
{
	IPA_LOGP_ESIPA("CancelSession", LINFO, "Requesting cancellation of session\n");

	return ipa_esipa_call(ctx, "CancelSession", req,
			      enc_cancel_session_req, dec_cancel_session_res,
			      json_enc_cancel_session_req, json_dec_cancel_session_res);
}

/*! Free results of function (ESipa): CancelSession.
 *  \param[in] res pointer to function result. */
void ipa_esipa_cancel_session_res_free(struct ipa_esipa_cancel_session_res *res)
{
	IPA_ESIPA_RES_FREE(res);
}
