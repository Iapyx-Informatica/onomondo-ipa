/*
 * Copyright (c) 2025 Onomondo ApS & sysmocom - s.f.m.c. GmbH. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Author: Philipp Maier <pmaier@sysmocom.de> / sysmocom - s.f.m.c. GmbH
 *
 * See also: GSMA SGP.32, section 5.14.3: Function: (Esipa) AuthenticateClient
 *
 * =====================================================================
 * v1.1/v1.2 migration notes for this file:
 * =====================================================================
 * UPDATE for v1.1: 5.14.3 — AuthenticateClient procedure description changed.
 *   SGP.32 now defines its own EuiccSigned1 (overrides the SGP.22 type) and
 *   its own AuthenticateResponseOk.  This client forwards the eUICC's
 *   AuthenticateServer response; once libasn is regenerated against the
 *   updated .asn, the embedded signed structures will carry the SGP.32 shape
 *   automatically — but review the procedure text to confirm there are no
 *   new required steps (e.g. extra signature checks) on the IPA side.
 * UPDATE for v1.1: 5.6.1 — SGP.32 also defines its own AuthenticateClientRequest
 *   (§5.6.1); the code here uses AuthenticateClientRequestEsipa which is
 *   unchanged, but anywhere the raw AuthenticateClientRequest is referenced
 *   must be reviewed after regeneration.
 * =====================================================================
 */

#include <stdint.h>
#include <errno.h>
#include <onomondo/ipa/http.h>
#include <onomondo/ipa/log.h>
#include <onomondo/ipa/ipad.h>
#include <EsipaMessageFromIpaToEim.h>
#include <AuthenticateClientResponseEsipa.h>
#include "utils.h"
#include "length.h"
#include "context.h"
#include "esipa.h"
#include "esipa_json.h"
#include "esipa_auth_clnt.h"

static const struct num_str_map error_code_strings[] = {
	{ AuthenticateErrorCode_invalidCertificate, "invalidCertificate" },
	{ AuthenticateErrorCode_invalidSignature, "invalidSignature" },
	{ AuthenticateErrorCode_unsupportedCurve, "unsupportedCurve" },
	{ AuthenticateErrorCode_noSessionContext, "noSessionContext" },
	{ AuthenticateErrorCode_invalidOid, "invalidOid" },
	{ AuthenticateErrorCode_euiccChallengeMismatch, "euiccChallengeMismatch" },
	{ AuthenticateErrorCode_ciPKUnknown, "ciPKUnknown" },
	{ AuthenticateErrorCode_undefinedError, "undefinedError" },
	{ 0, NULL }
};

static struct ipa_buf *enc_auth_clnt_req(const struct ipa_esipa_auth_clnt_req *req)
{
	struct EsipaMessageFromIpaToEim msg_to_eim = { 0 };

	msg_to_eim.present = EsipaMessageFromIpaToEim_PR_authenticateClientRequestEsipa;
	msg_to_eim.choice.authenticateClientRequestEsipa = req->req;

	/* Encode */
	return ipa_esipa_msg_to_eim_enc(&msg_to_eim, "AuthenticateClient");
}

static struct ipa_esipa_auth_clnt_res *dec_auth_clnt_res(const struct ipa_buf *msg_to_ipa_encoded,
							 const struct ipa_esipa_auth_clnt_req *req)
{
	struct EsipaMessageFromEimToIpa *msg_to_ipa = NULL;
	struct ipa_esipa_auth_clnt_res *res = NULL;

	msg_to_ipa = ipa_esipa_msg_to_ipa_dec(msg_to_ipa_encoded, "AuthenticateClient",
					      EsipaMessageFromEimToIpa_PR_authenticateClientResponseEsipa);
	if (!msg_to_ipa)
		return NULL;

	res = IPA_ALLOC_ZERO(struct ipa_esipa_auth_clnt_res);
	res->msg_to_ipa = msg_to_ipa;

	switch (msg_to_ipa->choice.authenticateClientResponseEsipa.present) {
	case AuthenticateClientResponseEsipa_PR_authenticateClientOkDPEsipa:
		res->auth_clnt_ok_dpe =
		    &msg_to_ipa->choice.authenticateClientResponseEsipa.choice.authenticateClientOkDPEsipa;
		res->transaction_id = res->auth_clnt_ok_dpe->transactionId;
		if (!IPA_ASN_STR_CMP(res->transaction_id, &req->req.transactionId)) {
			IPA_LOGP_ESIPA("AuthenticateClient", LERROR,
				       "eIM responded with unexpected transaction ID (expected: %s, got: %s)\n",
				       ipa_hexdump(req->req.transactionId.buf, req->req.transactionId.size),
				       ipa_hexdump(res->transaction_id->buf, res->transaction_id->size));
			res->auth_clnt_err = -1;
		}
		break;
	case AuthenticateClientResponseEsipa_PR_authenticateClientOkDSEsipa:
		res->auth_clnt_ok_dse =
		    &msg_to_ipa->choice.authenticateClientResponseEsipa.choice.authenticateClientOkDSEsipa;
		res->transaction_id = &res->auth_clnt_ok_dse->transactionId;
		break;
	case AuthenticateClientResponseEsipa_PR_authenticateClientErrorEsipa:
		res->auth_clnt_err =
		    msg_to_ipa->choice.authenticateClientResponseEsipa.choice.authenticateClientErrorEsipa;
		IPA_LOGP_ESIPA("AuthenticateClient", LERROR, "function failed with error code %ld=%s!\n",
			       res->auth_clnt_err, ipa_str_from_num(error_code_strings, res->auth_clnt_err,
								    "(unknown)"));
		break;
	default:
		IPA_LOGP_ESIPA("AuthenticateClient", LERROR, "unexpected response content!\n");
		res->auth_clnt_err = -1;
	}

	return res;
}

/*! Function: (Esipa) AuthenticateClient.
 *  \param[inout] ctx pointer to ipa_context.
 *  \param[in] req pointer to struct that holds the function parameters.
 *  \returns pointer newly allocated struct with function result, NULL on error. */
struct ipa_esipa_auth_clnt_res *ipa_esipa_auth_clnt(struct ipa_context *ctx, const struct ipa_esipa_auth_clnt_req *req)
{
	struct ipa_buf *esipa_req = NULL;
	struct ipa_buf *esipa_res = NULL;
	struct ipa_esipa_auth_clnt_res *res = NULL;

	IPA_LOGP_ESIPA("AuthenticateClient", LINFO, "Requesting client authentication\n");

	/* NEW v1.2 §6.4: JSON binding dispatcher. */
	if (ctx->cfg->esipa_binding == IPA_ESIPA_BINDING_JSON) {
		esipa_req = ipa_esipa_json_enc_auth_clnt_req(req);
		if (!esipa_req) goto error;
		esipa_res = ipa_esipa_req(ctx, esipa_req, "AuthenticateClient");
		if (!esipa_res) goto error;
		res = ipa_esipa_json_dec_auth_clnt_res(esipa_res, req);
		goto error;
	}

	esipa_req = enc_auth_clnt_req(req);
	if (!esipa_req) {
		IPA_LOGP_ESIPA("AuthenticateClient", LERROR, "failed to encode the AuthenticateClient request!\n");
		goto error;
	}

	esipa_res = ipa_esipa_req(ctx, esipa_req, "AuthenticateClient");
	if (!esipa_res) {
		IPA_LOGP_ESIPA("AuthenticateClient", LERROR, "eIM response is NULL!\n");
		goto error;
	} else if (esipa_res->len == 0) {
		IPA_LOGP_ESIPA("AuthenticateClient", LERROR, "eIM response is empty!\n");
		goto error;
	}

	IPA_LOGP_ESIPA("AuthenticateClient", LINFO, "Decode the AuthenticateClient response\n");
	res = dec_auth_clnt_res(esipa_res, req);
	if (!res) {
		IPA_LOGP_ESIPA("AuthenticateClient", LERROR, "failed to decode the AuthenticateClient response!\n");
		goto error;
	}

error:
	IPA_FREE(esipa_req);
	IPA_FREE(esipa_res);
	return res;
}

/*! Free results of function: (Esipa) AuthenticateClient.
 *  \param[in] res pointer to function result. */
void ipa_esipa_auth_clnt_res_free(struct ipa_esipa_auth_clnt_res *res)
{
	IPA_ESIPA_RES_FREE(res);
}
