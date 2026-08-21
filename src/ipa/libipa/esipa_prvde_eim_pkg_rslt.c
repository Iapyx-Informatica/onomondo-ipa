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
#include <assert.h>
#include <string.h>
#include <onomondo/ipa/mem.h>
#include <onomondo/ipa/utils.h>
#include <onomondo/ipa/http.h>
#include <onomondo/ipa/log.h>
#include <onomondo/ipa/ipad.h>
#include <EsipaMessageFromIpaToEim.h>
#include <ProvideEimPackageResult.h>
#include <SGP32-PendingNotificationList.h>
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

/* -------------------------------------------------------------------------
 * DER length helpers
 * -------------------------------------------------------------------------
 * These are only used by the passthru encoder (enc_prvde_eim_pkg_rslt_req_passthru
 * and ipa_esipa_build_eim_pkg_result_der) which manually constructs TLV
 * rather than going through the asn1c DER encoder.  Keeping them private
 * avoids polluting the global namespace.
 */

/* Return the number of bytes required to DER-encode the length value `val`. */
static size_t der_length_size(size_t val)
{
	if (val < 0x80) return 1;
	if (val < 0x100) return 2;
	if (val < 0x10000) return 3;
	if (val < 0x1000000) return 4;
	return 5;
}

/* Write the DER encoding of length `val` to `p`.  Returns bytes written. */
static size_t der_write_length(uint8_t *p, size_t val)
{
	if (val < 0x80) { p[0] = (uint8_t)val; return 1; }
	if (val < 0x100) { p[0] = 0x81; p[1] = (uint8_t)val; return 2; }
	if (val < 0x10000) {
		p[0] = 0x82; p[1] = (uint8_t)(val >> 8); p[2] = (uint8_t)val;
		return 3;
	}
	if (val < 0x1000000) {
		p[0] = 0x83; p[1] = (uint8_t)(val >> 16);
		p[2] = (uint8_t)(val >> 8); p[3] = (uint8_t)val;
		return 4;
	}
	p[0] = 0x84; p[1] = (uint8_t)(val >> 24); p[2] = (uint8_t)(val >> 16);
	p[3] = (uint8_t)(val >> 8); p[4] = (uint8_t)val;
	return 5;
}

/*! Build a DER-encoded EimPackageResult buffer that embeds raw_euicc_pkg_result
 *  verbatim instead of re-encoding from the decoded C struct.
 *
 *  Wire format produced:
 *
 *  With notifications (ePRAndNotifications arm):
 *    30 <len>          UNIVERSAL SEQUENCE
 *      BF 51 ...       raw EuiccPackageResult bytes (already tagged)
 *      A0 <len> ...    notificationList [0] IMPLICIT SGP32-PendingNotificationList
 *
 *  Without notifications (euiccPackageResult arm):
 *    BF 51 ...         raw EuiccPackageResult bytes (identifies the CHOICE arm)
 *
 *  \param[in] raw_euicc_pkg_result  Raw BER bytes from ES10b.LoadEuiccPackage.
 *  \param[in] sgp32_notif_list      May be NULL; PR_notificationList is used.
 *  \returns heap-allocated ipa_buf with DER bytes, or NULL on error. */
struct ipa_buf *ipa_esipa_build_eim_pkg_result_der(
	const struct ipa_buf *raw_euicc_pkg_result,
	const struct SGP32_RetrieveNotificationsListResponse *sgp32_notif_list)
{
	struct ipa_buf *notif_enc = NULL;
	struct ipa_buf *result = NULL;
	size_t off = 0;
	size_t inner_len, seq_hdr_bytes, total_len;

	if (sgp32_notif_list &&
	    sgp32_notif_list->present == SGP32_RetrieveNotificationsListResponse_PR_notificationList) {
		/* DER-encode the SGP32-PendingNotificationList (SEQUENCE OF → tag 0x30).
		 * In ePRAndNotifications it appears as notificationList [0] IMPLICIT, so
		 * the UNIVERSAL SEQUENCE tag 0x30 is replaced by CONTEXT [0] CONSTRUCTED
		 * 0xA0. */
		der_encode(&asn_DEF_SGP32_PendingNotificationList,
			   IPA_ASN_PTR_RW(&sgp32_notif_list->choice.notificationList),
			   ipa_asn1c_consume_bytes_cb, &notif_enc);
		if (!notif_enc || notif_enc->len == 0) {
			IPA_FREE(notif_enc);
			notif_enc = NULL;
		} else {
			assert(notif_enc->data[0] == 0x30);
			notif_enc->data[0] = 0xA0;
		}
	}

	if (notif_enc) {
		/*
		 * Build ePRAndNotifications SEQUENCE:
		 *   30 <len>  <raw_BF51_bytes>  <A0_notif_bytes>
		 */
		inner_len = raw_euicc_pkg_result->len + notif_enc->len;
		seq_hdr_bytes = 1 + der_length_size(inner_len); /* 0x30 + encoded len */
		total_len = seq_hdr_bytes + inner_len;

		result = ipa_buf_alloc(total_len);
		if (!result)
			goto err;

		result->data[off++] = 0x30;
		off += der_write_length(result->data + off, inner_len);
		memcpy(result->data + off, raw_euicc_pkg_result->data, raw_euicc_pkg_result->len);
		off += raw_euicc_pkg_result->len;
		memcpy(result->data + off, notif_enc->data, notif_enc->len);
		off += notif_enc->len;
		result->len = total_len;
		assert(off == total_len);
	} else {
		/*
		 * euiccPackageResult arm: the raw bytes already carry the BF51 outer
		 * tag that identifies this CHOICE arm in EimPackageResult.
		 */
		result = ipa_buf_copy(raw_euicc_pkg_result);
	}

err:
	IPA_FREE(notif_enc);
	return result;
}

/*
 * Build the complete DER-encoded EsipaMessageFromIpaToEim.provideEimPackageResult
 * message using raw EuiccPackageResult bytes.
 *
 * Wire format:
 *   BF 50 <len>     [80] CONSTRUCTED  (ProvideEimPackageResult = EsipaMsg arm)
 *     5A 10 <eid>   APPLICATION 26    (eidValue, 16 bytes)
 *     <eim_pkg_der> EimPackageResult  (CHOICE, no outer tag — built by
 *                                      ipa_esipa_build_eim_pkg_result_der)
 */
#ifdef IPA_HAVE_ESIPA_ASN1		/* ESipa ASN.1 binding, SGP.32 section 6.3 */
static struct ipa_buf *enc_prvde_eim_pkg_rslt_req_passthru(
	const struct ipa_context *ctx,
	const struct ipa_esipa_prvde_eim_pkg_rslt_req *req)
{
	struct ipa_buf *eim_pkg_der = NULL;
	struct ipa_buf *result = NULL;
	size_t eid_tlv_len, pepr_body_len, total_len, off = 0;

	eim_pkg_der = ipa_esipa_build_eim_pkg_result_der(req->raw_euicc_package_result,
							 req->sgp32_notification_list);
	if (!eim_pkg_der) {
		IPA_LOGP_ESIPA("ProvideEimPackageResult", LERROR,
			       "passthru: failed to build EimPackageResult DER\n");
		goto err;
	}

	/* eidValue TLV: tag 5A (1 byte) + length 0x10 (1 byte) + 16 bytes = 18 */
	eid_tlv_len = 1 + 1 + IPA_LEN_EID;

	/* ProvideEimPackageResult SEQUENCE body */
	pepr_body_len = eid_tlv_len + eim_pkg_der->len;

	/* Outer [80] CONSTRUCTED tag = BF 50 (2 bytes) + DER length + body */
	total_len = 2 + der_length_size(pepr_body_len) + pepr_body_len;

	result = ipa_buf_alloc(total_len);
	if (!result)
		goto err;

	/* BF 50 <len> — [80] CONSTRUCTED (Context class, tag 80, long form) */
	result->data[off++] = 0xBF;
	result->data[off++] = 0x50;
	off += der_write_length(result->data + off, pepr_body_len);

	/* eidValue: 5A 10 <16-byte EID> (APPLICATION 26, primitive) */
	result->data[off++] = 0x5A;
	result->data[off++] = (uint8_t)IPA_LEN_EID;
	memcpy(result->data + off, ctx->eid, IPA_LEN_EID);
	off += IPA_LEN_EID;

	/* EimPackageResult (CHOICE encoding, no outer tag) */
	memcpy(result->data + off, eim_pkg_der->data, eim_pkg_der->len);
	off += eim_pkg_der->len;

	assert(off == total_len);
	result->len = total_len;

err:
	IPA_FREE(eim_pkg_der);
	return result;
}

static struct ipa_buf *enc_prvde_eim_pkg_rslt_req(const struct ipa_context *ctx,
						   const struct ipa_esipa_prvde_eim_pkg_rslt_req *req)
{
	struct EsipaMessageFromIpaToEim msg_to_eim = { 0 };
	struct ProvideEimPackageResult *pepr;
	Octet16_t eidValue_hold;
	struct ipa_buf *enc;

	/* When the caller has raw BER bytes from the eUICC, forward them verbatim
	 * instead of re-encoding the decoded C struct.  A BER→DER re-encode would
	 * alter euiccPackageResultDataSigned, breaking euiccSignEPR verification
	 * at the eIM. */
	if (req->raw_euicc_package_result && req->eim_pkg_err == 0)
		return enc_prvde_eim_pkg_rslt_req_passthru(ctx, req);

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

static struct ipa_buf *enc_prvde_eim_pkg_rslt_req_cb(struct ipa_context *ctx, const void *req)
{
	return enc_prvde_eim_pkg_rslt_req(ctx, req);
}

static void *dec_prvde_eim_pkg_rslt_res_cb(const struct ipa_buf *res, const void *req)
{
	(void)req;
	return dec_prvde_eim_pkg_rslt_res(res);
}

#endif /* IPA_HAVE_ESIPA_ASN1 */

#ifdef IPA_HAVE_ESIPA_JSON		/* ESipa JSON binding, SGP.32 section 6.4 */
static struct ipa_buf *json_enc_prvde_eim_pkg_rslt_req(struct ipa_context *ctx, const void *req)
{
	return ipa_esipa_json_enc_prvde_eim_pkg_rslt_req(ctx, req);
}

static void *json_dec_prvde_eim_pkg_rslt_res(const struct ipa_buf *res, const void *req)
{
	(void)req;
	return ipa_esipa_json_dec_prvde_eim_pkg_rslt_res(res);
}

#endif /* IPA_HAVE_ESIPA_JSON */

/*! Function (ESipa): ProvideEimPackageResult.
 *  \param[inout] ctx pointer to ipa_context.
 *  \param[in] req pointer to struct that holds the function parameters.
 *  \returns pointer newly allocated struct with function result, NULL on error. */
struct ipa_esipa_prvde_eim_pkg_rslt_res *ipa_esipa_prvde_eim_pkg_rslt(struct ipa_context *ctx, const struct ipa_esipa_prvde_eim_pkg_rslt_req
								      *req)
{
	IPA_LOGP_ESIPA("ProvideEimPackageResult", LINFO,
		       "Providing eUICC package result and eUICC notifications to eIM\n");

	return ipa_esipa_call(ctx, "ProvideEimPackageResult", req,
			      IPA_ESIPA_ASN1_CB(enc_prvde_eim_pkg_rslt_req_cb, dec_prvde_eim_pkg_rslt_res_cb),
			      IPA_ESIPA_JSON_CB(json_enc_prvde_eim_pkg_rslt_req, json_dec_prvde_eim_pkg_rslt_res));
}

/*! Free results of function (ESipa): ProvideEimPackageResult.
 *  \param[in] res pointer to function result. */
void ipa_esipa_prvde_eim_pkg_rslt_free(struct ipa_esipa_prvde_eim_pkg_rslt_res *res)
{
	IPA_ESIPA_RES_FREE(res);
}
