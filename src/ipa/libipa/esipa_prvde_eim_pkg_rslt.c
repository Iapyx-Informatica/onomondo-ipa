/*
 * Copyright (c) 2025 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Author: Philipp Maier <pmaier@sysmocom.de> / sysmocom - s.f.m.c. GmbH
 *
 * See also: GSMA SGP.32, section 5.14.6: Function (ESipa): ProvideEimPackageResult
 *
 * =====================================================================
 * v1.1/v1.2 migration notes for this file (MAJOR CHANGES — rewrite needed):
 * =====================================================================
 * UPDATE for v1.1: 5.14.6 / 6.3.2.7 — ProvideEimPackageResult was restructured
 *   from a top-level CHOICE to a SEQUENCE:
 *     ProvideEimPackageResult ::= [80] SEQUENCE {
 *       eidValue    [APPLICATION 26] Octet16 OPTIONAL,
 *       eimPackageResult EimPackageResult
 *     }
 *   where EimPackageResult is the CHOICE that used to be the outer type.
 *   All of the enc_prvde_eim_pkg_rslt_req() code below must be rewritten
 *   to populate the new wrapper: set .eidValue conditionally and assign
 *   the chosen branch into .eimPackageResult.choice.<branch>.
 *
 * UPDATE for v1.1: 6.3.2.7 — The eimPackageError INTEGER branch was replaced
 *   by eimPackageResultResponseError [0] EimPackageResultResponseError, which
 *   wraps the code with an optional eimTransactionId:
 *     EimPackageResultResponseError ::= SEQUENCE {
 *       eimTransactionId [0] TransactionId OPTIONAL,
 *       eimPackageResultErrorCode EimPackageResultErrorCode
 *     }
 *   The error-path fallback at the bottom of enc_prvde_eim_pkg_rslt_req()
 *   must be updated accordingly.
 *
 * UPDATE for v1.1: 6.3.2.7 — ePRAndNotifications.notificationList tag changed
 *   from [43] (SGP32-RetrieveNotificationsListResponse) to [0]
 *   (PendingNotificationList alias).  The existing field assignment of
 *   sgp32_notification_list into .notificationList will still compile but
 *   the wire format changes; consumer must extract the inner notification
 *   list rather than the full response.
 *
 * UPDATE for v1.1: 6.3.2.7 — ProvideEimPackageResultResponse changed from a
 *   SEQUENCE (with optional EimAcknowledgements) to a CHOICE with three
 *   branches: eimAcknowledgements, emptyResponse, provideEimPackageResultError.
 *   The decoder below unconditionally reads .eimAcknowledgements which will
 *   no longer type-check after regeneration.  Rewrite:
 *     switch (msg_to_ipa->choice.provideEimPackageResultResponse.present) {
 *     case ProvideEimPackageResultResponse_PR_eimAcknowledgements: ...
 *     case ProvideEimPackageResultResponse_PR_emptyResponse:       ...
 *     case ProvideEimPackageResultResponse_PR_provideEimPackageResultError: ...
 *     }
 *
 * UPDATE for v1.2: CR111002R00 — new error codes in provideEimPackageResultError:
 *   eidNotFound(2), invalidEid(3), missingEid(4).
 * UPDATE for v1.2: CR111003R00 — eimPackageResultErrorCode was removed from
 *   the old EimPackageResult; error now lives in eimPackageResultResponseError.
 * UPDATE for v1.2: CR12014R02 — clarified when EidValue must be included in
 *   ProvideEimPackageResult (see §5.14.6 procedure text).
 * =====================================================================
 */

#include <stdint.h>
#include <onomondo/ipa/http.h>
#include <onomondo/ipa/log.h>
#include <onomondo/ipa/ipad.h>
#include <EsipaMessageFromIpaToEim.h>
#include <ProvideEimPackageResult.h>
/* TODO v1.1: 6.3.2.7 — after libasn regeneration, replace the include below
 * with <PendingNotificationList.h> (the new alias).  The old
 * SGP32-RetrieveNotificationsListResponse is no longer used on this path. */
#include <SGP32-RetrieveNotificationsListResponse.h>
#include "utils.h"
#include "length.h"
#include "context.h"
#include "esipa.h"
#include "esipa_json.h"
#include "esipa_prvde_eim_pkg_rslt.h"

static struct ipa_buf *enc_prvde_eim_pkg_rslt_req(const struct ipa_context *ctx,
						   const struct ipa_esipa_prvde_eim_pkg_rslt_req *req)
{
	struct EsipaMessageFromIpaToEim msg_to_eim = { 0 };
	struct ProvideEimPackageResult *pepr;
	Octet16_t eidValue_hold;
	struct ipa_buf *enc;

	/* UPDATE for v1.1: 5.14.6 / 6.3.2.7 - ProvideEimPackageResult became a
	 * SEQUENCE wrapping an EimPackageResult CHOICE (instead of being the
	 * CHOICE directly).  All branches below now assign into
	 * pepr->eimPackageResult.*; the old eimPackageError INTEGER branch is
	 * gone - errors are flagged via the eimPackageResultResponseError wrapper. */
	msg_to_eim.present = EsipaMessageFromIpaToEim_PR_provideEimPackageResult;
	pepr = &msg_to_eim.choice.provideEimPackageResult;

	/* UPDATE for v1.2: CR12014R02 / §5.14.6 - include eidValue so the eIM
	 * can identify the originating eUICC (required unless the eIM already
	 * knows which eUICC is speaking).  We always include it for safety; the
	 * field is OPTIONAL in the schema so omitting it is legal but strongly
	 * discouraged.  ctx->eid is populated by ipa_init() from ES10c.GetEID. */
	eidValue_hold.buf = (uint8_t *)ctx->eid;
	eidValue_hold.size = IPA_LEN_EID;
	pepr->eidValue = &eidValue_hold;

	if (req->eim_pkg_err != 0) {
		/* UPDATE for v1.1: 6.3.2.7 - error now wrapped in
		 * EimPackageResultResponseError with optional eimTransactionId. */
		pepr->eimPackageResult.present = EimPackageResult_PR_eimPackageResultResponseError;
		pepr->eimPackageResult.choice.eimPackageResultResponseError.eimPackageResultErrorCode =
		    req->eim_pkg_err;
	} else if (req->euicc_package_result && req->sgp32_notification_list) {
		pepr->eimPackageResult.present = EimPackageResult_PR_ePRAndNotifications;
		pepr->eimPackageResult.choice.ePRAndNotifications.euiccPackageResult =
		    *req->euicc_package_result;
		/* UPDATE for v1.1: 6.3.2.7 - notificationList now uses
		 * SGP32-PendingNotificationList; callers still hand us the full
		 * SGP32-RetrieveNotificationsListResponse, from which we extract
		 * the inner notificationList. */
		if (req->sgp32_notification_list->present ==
		    SGP32_RetrieveNotificationsListResponse_PR_notificationList) {
			pepr->eimPackageResult.choice.ePRAndNotifications.notificationList =
			    req->sgp32_notification_list->choice.notificationList;
		}
	} else if (req->euicc_package_result) {
		pepr->eimPackageResult.present = EimPackageResult_PR_euiccPackageResult;
		pepr->eimPackageResult.choice.euiccPackageResult = *req->euicc_package_result;
	} else if (req->ipa_euicc_data_resp) {
		pepr->eimPackageResult.present = EimPackageResult_PR_ipaEuiccDataResponse;
		pepr->eimPackageResult.choice.ipaEuiccDataResponse = *req->ipa_euicc_data_resp;
	} else if (req->prfle_dwnld_trig_req_rslt) {
		pepr->eimPackageResult.present = EimPackageResult_PR_profileDownloadTriggerResult;
		pepr->eimPackageResult.choice.profileDownloadTriggerResult =
		    *req->prfle_dwnld_trig_req_rslt;
	} else {
		/* Fall back to signalling an undefined error to the eIM. */
		IPA_LOGP_ESIPA("ProvideEimPackageResult", LERROR,
			       "empty provideEimPackageResult request, setting eimPackageError to undefined\n");
		pepr->eimPackageResult.present = EimPackageResult_PR_eimPackageResultResponseError;
		pepr->eimPackageResult.choice.eimPackageResultResponseError.eimPackageResultErrorCode =
		    EimPackageResultErrorCode_undefinedError;
	}

	enc = ipa_esipa_msg_to_eim_enc(&msg_to_eim, "ProvideEimPackageResult");

	return enc;
}

struct ipa_esipa_prvde_eim_pkg_rslt_res *dec_prvde_eim_pkg_rslt_res(const struct ipa_buf *msg_to_ipa_encoded)
{
	struct EsipaMessageFromEimToIpa *msg_to_ipa = NULL;
	struct ipa_esipa_prvde_eim_pkg_rslt_res *res = NULL;

	msg_to_ipa =
	    ipa_esipa_msg_to_ipa_dec(msg_to_ipa_encoded, "ProvideEimPackageResult",
				     EsipaMessageFromEimToIpa_PR_provideEimPackageResultResponse);
	if (!msg_to_ipa)
		return NULL;

	res = IPA_ALLOC_ZERO(struct ipa_esipa_prvde_eim_pkg_rslt_res);
	res->msg_to_ipa = msg_to_ipa;

	/* UPDATE for v1.1: 6.3.2.7 - ProvideEimPackageResultResponse is now a CHOICE.
	 * UPDATE for v1.2: CR111002R00 - new provideEimPackageResultError branch. */
	switch (msg_to_ipa->choice.provideEimPackageResultResponse.present) {
	case ProvideEimPackageResultResponse_PR_eimAcknowledgements:
		res->eim_acknowledgements =
		    &msg_to_ipa->choice.provideEimPackageResultResponse.choice.eimAcknowledgements;
		break;
	case ProvideEimPackageResultResponse_PR_emptyResponse:
		/* eIM accepted with no acks to return */
		res->eim_acknowledgements = NULL;
		break;
	case ProvideEimPackageResultResponse_PR_provideEimPackageResultError:
		IPA_LOGP_ESIPA("ProvideEimPackageResult", LERROR,
			       "eIM rejected the result with error code %ld\n",
			       msg_to_ipa->choice.provideEimPackageResultResponse
				   .choice.provideEimPackageResultError);
		res->eim_acknowledgements = NULL;
		break;
	default:
		IPA_LOGP_ESIPA("ProvideEimPackageResult", LERROR, "unexpected response content!\n");
		res->eim_acknowledgements = NULL;
		break;
	}

	return res;
}

/*! Function (ESipa): ProvideEimPackageResult.
 *  \param[inout] ctx pointer to ipa_context.
 *  \param[in] req pointer to struct that holds the function parameters.
 *  \returns pointer newly allocated struct with function result, NULL on error. */
struct ipa_esipa_prvde_eim_pkg_rslt_res *ipa_esipa_prvde_eim_pkg_rslt(struct ipa_context *ctx, const struct ipa_esipa_prvde_eim_pkg_rslt_req
								      *req)
{
	struct ipa_buf *esipa_req = NULL;
	struct ipa_buf *esipa_res = NULL;
	struct ipa_esipa_prvde_eim_pkg_rslt_res *res = NULL;

	IPA_LOGP_ESIPA("ProvideEimPackageResult", LINFO,
		       "Providing eUICC package result and eUICC notifications to eIM\n");

	/* NEW v1.2 §6.4: JSON binding dispatcher. */
	if (ctx->cfg->esipa_binding == IPA_ESIPA_BINDING_JSON) {
		esipa_req = ipa_esipa_json_enc_prvde_eim_pkg_rslt_req(ctx, req);
		if (!esipa_req) goto error;
		esipa_res = ipa_esipa_req(ctx, esipa_req, "ProvideEimPackageResult");
		if (!esipa_res) goto error;
		res = ipa_esipa_json_dec_prvde_eim_pkg_rslt_res(esipa_res);
		goto error;
	}

	esipa_req = enc_prvde_eim_pkg_rslt_req(ctx, req);
	if (!esipa_req)
		goto error;

	esipa_res = ipa_esipa_req(ctx, esipa_req, "ProvideEimPackageResult");
	if (!esipa_res)
		goto error;

	res = dec_prvde_eim_pkg_rslt_res(esipa_res);
	if (!res)
		goto error;

error:
	IPA_FREE(esipa_req);
	IPA_FREE(esipa_res);
	return res;
}

/*! Free results of function (ESipa): ProvideEimPackageResult.
 *  \param[in] res pointer to function result. */
void ipa_esipa_prvde_eim_pkg_rslt_free(struct ipa_esipa_prvde_eim_pkg_rslt_res *res)
{
	IPA_ESIPA_RES_FREE(res);
}
