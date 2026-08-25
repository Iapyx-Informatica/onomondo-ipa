/*
 * Copyright (c) 2025 Onomondo ApS & sysmocom - s.f.m.c. GmbH. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Author: Philipp Maier <pmaier@sysmocom.de> / sysmocom - s.f.m.c. GmbH
 * 
 * See also: GSMA SGP.32, section 5.14.2: Function: (ESipa) GetBoundProfilePackage
 */

#include <stdint.h>
#include <errno.h>
#include <onomondo/ipa/http.h>
#include <onomondo/ipa/log.h>
#include <onomondo/ipa/ipad.h>
#include <EsipaMessageFromIpaToEim.h>
#include <SGP32-PrepareDownloadResponse.h>
#include <GetBoundProfilePackageRequestEsipa.h>
#include <GetBoundProfilePackageResponseEsipa.h>
#include "utils.h"
#include "length.h"
#include "context.h"
#include "esipa.h"
#include "esipa_json.h"
#include "esipa_get_bnd_prfle_pkg.h"

/*! The transaction id that belongs to a PrepareDownloadResponse, see the header for why both bindings need it. */
const TransactionId_t *ipa_esipa_get_bnd_prfle_pkg_transaction_id(const struct PrepareDownloadResponse
								  *prep_dwnld_res)
{
	if (!prep_dwnld_res)
		return NULL;

	switch (prep_dwnld_res->present) {
	case PrepareDownloadResponse_PR_downloadResponseOk:
		return &prep_dwnld_res->choice.downloadResponseOk.euiccSigned2.transactionId;
	case PrepareDownloadResponse_PR_downloadResponseError:
		return &prep_dwnld_res->choice.downloadResponseError.transactionId;
	default:
		return NULL;
	}
}

static const struct num_str_map error_code_strings[] = {
	{ GetBoundProfilePackageResponseEsipa__getBoundProfilePackageErrorEsipa_euiccSignatureInvalid,
	 "euiccSignatureInvalid" },
	{ GetBoundProfilePackageResponseEsipa__getBoundProfilePackageErrorEsipa_confirmationCodeMissing,
	 "confirmationCodeMissing" },
	{ GetBoundProfilePackageResponseEsipa__getBoundProfilePackageErrorEsipa_confirmationCodeRefused,
	 "confirmationCodeRefused" },
	{ GetBoundProfilePackageResponseEsipa__getBoundProfilePackageErrorEsipa_confirmationCodeRetriesExceeded,
	 "confirmationCodeRetriesExceeded" },
	{ GetBoundProfilePackageResponseEsipa__getBoundProfilePackageErrorEsipa_bppRebindingRefused,
	 "bppRebindingRefused" },
	{ GetBoundProfilePackageResponseEsipa__getBoundProfilePackageErrorEsipa_downloadOrderExpired,
	 "downloadOrderExpired" },
	/* UPDATE for v1.1: 6.3.2.3 - renamed profileMetadataMismatch -> metadataMismatch. */
	{ GetBoundProfilePackageResponseEsipa__getBoundProfilePackageErrorEsipa_metadataMismatch,
	 "metadataMismatch" },
	{ GetBoundProfilePackageResponseEsipa__getBoundProfilePackageErrorEsipa_invalidTransactionId,
	 "invalidTransactionId" },
	{ GetBoundProfilePackageResponseEsipa__getBoundProfilePackageErrorEsipa_undefinedError, "undefinedError" },
	{ 0, NULL }
};

/*! Name of an ESipa.GetBoundProfilePackage error code, for log messages.
 *  \param[in] err the error code as decoded from the eIM response.
 *  \returns the code's name from the ASN.1 definition (section 6.3.2.3), or "(unknown)".
 *
 *  Shared by both wire bindings on purpose: the JSON binding carries the same codes, and the two
 *  must not describe one code by two different names. */
const char *ipa_esipa_get_bnd_prfle_pkg_err_str(long err)
{
	return ipa_str_from_num(error_code_strings, err, "(unknown)");
}

#ifdef IPA_HAVE_ESIPA_ASN1		/* ESipa ASN.1 binding, SGP.32 section 6.3 */

static struct ipa_buf *enc_get_bnd_prfle_pkg_req(struct ipa_context *ctx, const void *req_)
{
	const struct ipa_esipa_get_bnd_prfle_pkg_req *req = req_;
	struct EsipaMessageFromIpaToEim msg_to_eim = { 0 };
	const TransactionId_t *transaction_id;
	(void)ctx;

	msg_to_eim.present = EsipaMessageFromIpaToEim_PR_getBoundProfilePackageRequestEsipa;

	switch (req->prep_dwnld_res->present) {
	case PrepareDownloadResponse_PR_downloadResponseOk:
		msg_to_eim.choice.getBoundProfilePackageRequestEsipa.prepareDownloadResponse.present =
		    SGP32_PrepareDownloadResponse_PR_downloadResponseOk;
		msg_to_eim.choice.getBoundProfilePackageRequestEsipa.prepareDownloadResponse.choice.downloadResponseOk =
		    req->prep_dwnld_res->choice.downloadResponseOk;
		break;
	case PrepareDownloadResponse_PR_downloadResponseError:
		msg_to_eim.choice.getBoundProfilePackageRequestEsipa.prepareDownloadResponse.present =
		    SGP32_PrepareDownloadResponse_PR_downloadResponseError;
		msg_to_eim.choice.getBoundProfilePackageRequestEsipa.prepareDownloadResponse.choice.
		    downloadResponseError = req->prep_dwnld_res->choice.downloadResponseError;
		break;
	default:
		IPA_LOGP_ESIPA("GetBoundProfilePackage", LINFO,
			       "prepare download response is empty, cannot encode request\n");
		return NULL;
	}

	transaction_id = ipa_esipa_get_bnd_prfle_pkg_transaction_id(req->prep_dwnld_res);
	if (!transaction_id) {
		IPA_LOGP_ESIPA("GetBoundProfilePackage", LERROR,
			       "prepare download response carries no transaction id, cannot encode request\n");
		return NULL;
	}
	msg_to_eim.choice.getBoundProfilePackageRequestEsipa.transactionId = *transaction_id;

	/* Encode */
	return ipa_esipa_msg_to_eim_enc(&msg_to_eim, "GetBoundProfilePackage");
}

static void *dec_get_bnd_prfle_pkg_res(const struct ipa_buf *msg_to_ipa_encoded, const void *req)
{
	struct EsipaMessageFromEimToIpa *msg_to_ipa = NULL;
	struct ipa_esipa_get_bnd_prfle_pkg_res *res = NULL;
	(void)req;

	msg_to_ipa =
	    ipa_esipa_msg_to_ipa_dec(msg_to_ipa_encoded, "GetBoundProfilePackage",
				     EsipaMessageFromEimToIpa_PR_getBoundProfilePackageResponseEsipa);
	if (!msg_to_ipa)
		return NULL;

	res = IPA_ALLOC_ZERO(struct ipa_esipa_get_bnd_prfle_pkg_res);
	res->msg_to_ipa = msg_to_ipa;

	switch (msg_to_ipa->choice.getBoundProfilePackageResponseEsipa.present) {
	case GetBoundProfilePackageResponseEsipa_PR_getBoundProfilePackageOkEsipa:
		IPA_LOGP_ESIPA("GetBoundProfilePackage", LINFO, "GetBoundProfilePackageResponseEsipa_PR_getBoundProfilePackageOkEsipa\n");
		res->get_bnd_prfle_pkg_ok =
		    &msg_to_ipa->choice.getBoundProfilePackageResponseEsipa.choice.getBoundProfilePackageOkEsipa;
		break;
	case GetBoundProfilePackageResponseEsipa_PR_getBoundProfilePackageErrorEsipa:
		IPA_LOGP_ESIPA("GetBoundProfilePackage", LERROR, "GetBoundProfilePackageResponseEsipa_PR_getBoundProfilePackageErrorEsipa\n");
		res->get_bnd_prfle_pkg_err =
		    msg_to_ipa->choice.getBoundProfilePackageResponseEsipa.choice.getBoundProfilePackageErrorEsipa;
		IPA_LOGP_ESIPA("GetBoundProfilePackage", LERROR, "function failed with error code %ld=%s!\n",
			       res->get_bnd_prfle_pkg_err, ipa_str_from_num(error_code_strings,
									    res->get_bnd_prfle_pkg_err, "(unknown)"));
		break;
	default:
		IPA_LOGP_ESIPA("GetBoundProfilePackage", LERROR, "unexpected response content!\n");
		res->get_bnd_prfle_pkg_err = -1;
		break;
	}

	return res;
}

#endif /* IPA_HAVE_ESIPA_ASN1 */

#ifdef IPA_HAVE_ESIPA_JSON		/* ESipa JSON binding, SGP.32 section 6.4 */
static struct ipa_buf *json_enc_get_bnd_prfle_pkg_req(struct ipa_context *ctx, const void *req)
{
	(void)ctx;
	return ipa_esipa_json_enc_get_bnd_prfle_pkg_req(req);
}

static void *json_dec_get_bnd_prfle_pkg_res(const struct ipa_buf *res, const void *req)
{
	(void)req;
	return ipa_esipa_json_dec_get_bnd_prfle_pkg_res(res);
}

#endif /* IPA_HAVE_ESIPA_JSON */

/*! Function: (ESipa) GetBoundProfilePackage.
 *  \param[inout] ctx pointer to ipa_context.
 *  \param[in] req pointer to struct that holds the function parameters.
 *  \returns pointer newly allocated struct with function result, NULL on error. */
struct ipa_esipa_get_bnd_prfle_pkg_res *ipa_esipa_get_bnd_prfle_pkg(struct ipa_context *ctx,
								    const struct ipa_esipa_get_bnd_prfle_pkg_req *req)
{
	IPA_LOGP_ESIPA("GetBoundProfilePackage", LINFO, "Requesting profile package from eIM\n");

	return ipa_esipa_call(ctx, "GetBoundProfilePackage", req,
			      IPA_ESIPA_ASN1_CB(enc_get_bnd_prfle_pkg_req, dec_get_bnd_prfle_pkg_res),
			      IPA_ESIPA_JSON_CB(json_enc_get_bnd_prfle_pkg_req, json_dec_get_bnd_prfle_pkg_res));
}

/*! Free results of function: (ESipa) GetBoundProfilePackage.
 *  \param[in] res pointer to function result. */
void ipa_esipa_get_bnd_prfle_pkg_res_free(struct ipa_esipa_get_bnd_prfle_pkg_res *res)
{
	IPA_ESIPA_RES_FREE(res);
}
