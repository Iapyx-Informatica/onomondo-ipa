/*
 * Copyright (c) 2025 Onomondo ApS & sysmocom - s.f.m.c. GmbH. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Author: Philipp Maier <pmaier@sysmocom.de> / sysmocom - s.f.m.c. GmbH
 *
 * See also: GSMA SGP.32, section 2.11.1.2: IpaEuiccDataRequest
 * (This is not described in the procedure section, so it is not an official
 *  procedure in terms of SGP.32)
 *
 * =====================================================================
 * v1.1/v1.2 migration notes for this file (see MIGRATION.md):
 * =====================================================================
 * UPDATE for v1.1: 2.11.1.2 — IpaEuiccDataRequest restructured:
 *   - euiccCiPKId (SubjectKeyIdentifier) -> euiccCiPKIdentifierToBeUsed
 *     (OCTET STRING, possibly truncated).  CAUTION: not just a rename —
 *     the element type changed.
 *   - searchCriteria -> searchCriteriaNotification; euiccPackageResults
 *     branch removed from it.
 *   - new searchCriteriaEuiccPackageResult [2] CHOICE { seqNumber [0] INTEGER }.
 *   - new eimTransactionId [3] TransactionId OPTIONAL.
 *
 * UPDATE for v1.1: 2.11.2.2 — IpaEuiccDataResponse restructured (MAJOR):
 *   - Error branch now IpaEuiccDataResponseError SEQUENCE { eimTransactionId,
 *     ipaEuiccDataErrorCode } instead of inline INTEGER error.
 *   - Adds named type IpaEuiccDataErrorCode with ecallActive(104).
 *   - IpaEuiccData: restructured field layout; notificationsList moved to
 *     tag [0] and uses new PendingNotificationList alias (not the full
 *     SGP32-RetrieveNotificationsListResponse); defaultSmdpAddress moved
 *     to [1]; new euiccPackageResultList [2]; euiccInfo2 now plain
 *     EUICCInfo2 (not SGP32-EUICCInfo2); new eimTransactionId [7];
 *     ipaCapabilities tag changed.
 *
 * UPDATE for v1.1: 5.9.2 — EUICCInfo2 gains euiccCiPKIdListForSigningV3,
 *   additionalEuiccInfo, highestSvn; IoTSpecificInfo gains ecallSupported
 *   and fallbackSupported.  Downstream consumers do not need to access these
 *   but should tolerate their presence (asn1c handles EXTENSIBILITY IMPLIED).
 *
 * TODO v1.1: rewrite this function to:
 *   1. [DONE] Use ipa_euicc_data_request->euiccCiPKIdentifierToBeUsed (the new
 *      OCTET STRING) where it previously read ->euiccCiPKId.  The old field
 *      is SubjectKeyIdentifier (OCTET STRING alias) so the value is
 *      compatible at the C level, only the name changes.
 *   2. [DONE] Split the searchCriteria branch: notifications tag 0xBF2B uses
 *      searchCriteriaNotification; euiccPackageResult seq lookups use
 *      searchCriteriaEuiccPackageResult.
 *   3. [DONE] Build the response using the new IpaEuiccData layout; populate
 *      eimTransactionId when the eIM supplied one.
 *   4. [DONE] On error, emit IpaEuiccDataResponseError rather than the old
 *      inline INTEGER.
 * =====================================================================
 */

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <onomondo/ipa/mem.h>
#include <onomondo/ipa/utils.h>
#include <onomondo/ipa/log.h>
#include <onomondo/ipa/ipad.h>
#include <IpaCapabilities.h>
#include <BIT_STRING.h>
#include <DeviceInfo.h>
#include <DeviceCapabilities.h>
#include <IpaEuiccDataResponse.h>
#include "context.h"
#include "utils.h"
#include "es10a_get_euicc_cfg_addr.h"
#include "es10b_get_euicc_info.h"
#include "es10b_get_eim_cfg_data.h"
#include "es10b_get_certs.h"
#include "es10b_retr_notif_from_lst.h"
#include "esipa_prvde_eim_pkg_rslt.h"
#include "proc_euicc_data_req.h"

/* See also SGP.32, section 4.1 */
static struct IpaCapabilities *make_ipa_capabilties(void)
{
	static struct IpaCapabilities ipa_capabilties = { 0 };
	static uint8_t ipa_ipaFeatures_buf[6];
	static struct BIT_STRING_s ipa_supported_protocols = { 0 };
	static uint8_t ipa_supported_protocols_buf[5];

	memset(ipa_ipaFeatures_buf, 0, sizeof(ipa_ipaFeatures_buf));
	ipa_capabilties.ipaFeatures.size = sizeof(ipa_ipaFeatures_buf);
	ipa_capabilties.ipaFeatures.buf = ipa_ipaFeatures_buf;
	/* We only support indirectRspServerCommunication, see also proc_indirect_prfle_dwnld.c */
	ipa_capabilties.ipaFeatures.buf[IpaCapabilities__ipaFeatures_directRspServerCommunication] = 0;
	ipa_capabilties.ipaFeatures.buf[IpaCapabilities__ipaFeatures_indirectRspServerCommunication] = 1;

	/* In eimDownloadDataHandling no AC is communicated, the eIM handles the identification of the download
	 * internally then, this is a mode we do not support. */
	ipa_capabilties.ipaFeatures.buf[IpaCapabilities__ipaFeatures_eimDownloadDataHandling] = 0;

	/* We do generate ctxParams1, see also proc_cmn_mtl_auth.c */
	ipa_capabilties.ipaFeatures.buf[IpaCapabilities__ipaFeatures_eimCtxParams1Generation] = 1;

	/* We do not yet support the ProfileMetadata verification, see TODO in proc_indirect_prfle_dwnld.c */
	ipa_capabilties.ipaFeatures.buf[IpaCapabilities__ipaFeatures_eimProfileMetadataVerification] = 0;

	/* This is a mode that uses more compact ESipa message to save some bytes/traffic. This feature is also not
	 * supported. */
	ipa_capabilties.ipaFeatures.buf[IpaCapabilities__ipaFeatures_minimizeEsipaBytes] = 0;

	ipa_capabilties.ipaSupportedProtocols = &ipa_supported_protocols;

	memset(ipa_supported_protocols_buf, 0, sizeof(ipa_supported_protocols_buf));
	ipa_supported_protocols.size = sizeof(ipa_supported_protocols_buf);
	ipa_supported_protocols.buf = ipa_supported_protocols_buf;
	ipa_supported_protocols.buf[IpaCapabilities__ipaSupportedProtocols_ipaRetrieveHttps] = 1;
	ipa_supported_protocols.buf[IpaCapabilities__ipaSupportedProtocols_ipaRetrieveCoaps] = 0;
	ipa_supported_protocols.buf[IpaCapabilities__ipaSupportedProtocols_ipaInjectHttps] = 0;
	ipa_supported_protocols.buf[IpaCapabilities__ipaSupportedProtocols_ipaInjectCoaps] = 0;
	ipa_supported_protocols.buf[IpaCapabilities__ipaSupportedProtocols_ipaProprietary] = 0;

	return &ipa_capabilties;
}

/* See also SGP.22, section 4.2 */
static struct DeviceInfo *make_device_info(struct ipa_context *ctx)
{
	static struct DeviceInfo device_info = { 0 };

	IPA_ASSIGN_BUF_TO_ASN(device_info.tac, ctx->cfg->tac, IPA_LEN_TAC);
	/* TODO: Optionally it would also be possible to submint the IMEI here, The question is: Do we need that? */

	/* TODO: The struct "device_info.deviceCapabilities" contains only optional parameters that refer supported
	 * features of the supported RAN. We should find a suitable way to present those fields to the user so that
	 * he can set the parameter via the ipa_context. For now we leave those parameters unpopulated. */

	return &device_info;
}

/*! Perform IpaEuiccDataRequest Procedure.
 *  \param[inout] ctx pointer to ipa_context.
 *  \param[in] pars pointer to struct that holds the procedure parameters.
 *  \returns 0 on success, negative on failure. */
int ipa_proc_euicc_data_req(struct ipa_context *ctx, const struct ipa_proc_euicc_data_req_pars *pars)
{
	struct ipa_buf *tag_list = NULL;
	struct ipa_es10a_euicc_cfg_addr *euicc_cfg_addr = NULL;
	struct ipa_es10b_euicc_info *euicc_info_1 = NULL;
	struct ipa_es10b_euicc_info *euicc_info_2 = NULL;
	struct ipa_es10b_eim_cfg_data *eim_cfg_data = NULL;
	struct ipa_es10b_get_certs_req get_certs_req = { 0 };
	struct ipa_es10b_get_certs_res *get_certs_res = NULL;
	struct ipa_es10b_retr_notif_from_lst_req retr_notif_from_lst_req = { 0 };
	struct ipa_es10b_retr_notif_from_lst_res *retr_notif_from_lst_res = NULL;
	/* FIX TODO 2: separate result holder for the euicc package result list lookup. */
	struct ipa_es10b_retr_notif_from_lst_res *retr_epr_from_lst_res = NULL;
	struct ipa_esipa_prvde_eim_pkg_rslt_req prvde_eim_pkg_rslt_req = { 0 };
	struct ipa_esipa_prvde_eim_pkg_rslt_res *prvde_eim_pkg_rslt_res = NULL;

	/* Final response */
	struct IpaEuiccDataResponse ipa_euicc_data_response = { 0 };

	/* Collect requested data */
	tag_list = IPA_BUF_FROM_ASN(&pars->ipa_euicc_data_request->tagList);
	if (ipa_tag_in_taglist(0x80, tag_list)) {
		IPA_LOGP(SIPA, LINFO, "eIM asks for Default SM-DP+ address\n");
		euicc_cfg_addr = ipa_es10a_get_euicc_cfg_addr(ctx);
		if (euicc_cfg_addr && euicc_cfg_addr->res->defaultDpAddress)
			ipa_euicc_data_response.choice.ipaEuiccData.defaultSmdpAddress = euicc_cfg_addr->res->defaultDpAddress;
	}

	if (ipa_tag_in_taglist(0xBF20, tag_list)) {
		IPA_LOGP(SIPA, LINFO, "eIM asks for eUICCInfo1\n");
		euicc_info_1 = ipa_es10b_get_euicc_info(ctx, false);
		if (euicc_info_1 && euicc_info_1->euicc_info_1)
			ipa_euicc_data_response.choice.ipaEuiccData.euiccInfo1 = euicc_info_1->euicc_info_1;
	}

	if (ipa_tag_in_taglist(0xBF22, tag_list)) {
		IPA_LOGP(SIPA, LINFO, "eIM asks for eUICCInfo2\n");
		euicc_info_2 = ipa_es10b_get_euicc_info(ctx, true);
		if (euicc_info_2 &&!euicc_info_2->sgp32_euicc_info_2)
			ipa_euicc_data_response.choice.ipaEuiccData.euiccInfo2 = euicc_info_2->sgp32_euicc_info_2;
	}

	if (ipa_tag_in_taglist(0x83, tag_list)) {
		if (euicc_cfg_addr)
			IPA_LOGP(SIPA, LINFO,
				 "eIM asks for Root SM-DS address (already known, no need to request it from eUICC)\n");
		else {
			IPA_LOGP(SIPA, LINFO, "eIM asks for Root SM-DS address\n");
			euicc_cfg_addr = ipa_es10a_get_euicc_cfg_addr(ctx);
			if (euicc_cfg_addr)
				ipa_euicc_data_response.choice.ipaEuiccData.rootSmdsAddress = &euicc_cfg_addr->res->rootDsAddress;
		}
	}

	if (ipa_tag_in_taglist(0x84, tag_list)) {
		struct EimConfigurationData *eim_cfg_data_item;
		IPA_LOGP(SIPA, LINFO, "eIM asks for Association token\n");
		eim_cfg_data = ipa_es10b_get_eim_cfg_data(ctx);
		if (eim_cfg_data && eim_cfg_data->res) {
			eim_cfg_data_item = ipa_es10b_get_eim_cfg_data_filter(eim_cfg_data, ctx->eim_id);
			if (eim_cfg_data_item)
				ipa_euicc_data_response.choice.ipaEuiccData.associationToken = eim_cfg_data_item->associationToken;
		}
	}

	if (ipa_tag_in_taglist(0xA5, tag_list)) {
		IPA_LOGP(SIPA, LINFO, "eIM asks for EUM certificate\n");
		/* FIX TODO 1 (SGP.32 §2.11.1.2): source field renamed from euiccCiPKId to
		 * euiccCiPKIdentifierToBeUsed (OCTET STRING; was SubjectKeyIdentifier).
		 * Destination GetCertsRequest.euiccCiPKId (SGP.22) is unchanged. */
		get_certs_req.req.euiccCiPKId = pars->ipa_euicc_data_request->euiccCiPKIdentifierToBeUsed;
		get_certs_res = ipa_es10b_get_certs(ctx, &get_certs_req);
		/* FIX TODO 4: on failure emit IpaEuiccDataResponseError (SGP.32 §2.11.2.2). */
		if (!get_certs_res || !get_certs_res->eum_certificate || !get_certs_res->euicc_certificate)
			goto send_cert_error;
		ipa_euicc_data_response.choice.ipaEuiccData.eumCertificate = get_certs_res->eum_certificate;
	}

	if (ipa_tag_in_taglist(0xA6, tag_list)) {
		if (get_certs_res) {
			IPA_LOGP(SIPA, LINFO,
				 "eIM asks for eUICC certificate (already known, no need to request it from eUICC)\n");
			ipa_euicc_data_response.choice.ipaEuiccData.euiccCertificate = get_certs_res->euicc_certificate;
		} else {
			IPA_LOGP(SIPA, LINFO, "eIM asks for eUICC certificate\n");
			/* FIX TODO 1 (SGP.32 §2.11.1.2): see rename note in 0xA5 block above. */
			get_certs_req.req.euiccCiPKId = pars->ipa_euicc_data_request->euiccCiPKIdentifierToBeUsed;
			get_certs_res = ipa_es10b_get_certs(ctx, &get_certs_req);
			/* FIX TODO 4: on failure emit IpaEuiccDataResponseError (SGP.32 §2.11.2.2). */
			if (!get_certs_res || !get_certs_res->eum_certificate || !get_certs_res->euicc_certificate)
				goto send_cert_error;
			ipa_euicc_data_response.choice.ipaEuiccData.euiccCertificate = get_certs_res->euicc_certificate;
		}
	}

	if (ipa_tag_in_taglist(0x88, tag_list)) {
		IPA_LOGP(SIPA, LINFO, "eIM asks for IPA Capabilities\n");
		ipa_euicc_data_response.choice.ipaEuiccData.ipaCapabilities = make_ipa_capabilties();
	} else {
		ipa_euicc_data_response.choice.ipaEuiccData.ipaCapabilities = NULL;
	}

	if (ipa_tag_in_taglist(0xA9, tag_list)) {
		IPA_LOGP(SIPA, LINFO, "eIM asks for Device Information\n");
		ipa_euicc_data_response.choice.ipaEuiccData.deviceInfo = make_device_info(ctx);
	} else {
		ipa_euicc_data_response.choice.ipaEuiccData.deviceInfo = NULL;
	}

	if (ipa_tag_in_taglist(0xBF2B, tag_list)) {
		IPA_LOGP(SIPA, LINFO, "eIM asks for List of Notifications and/or eUICC Package Results\n");

		/* FIX TODO 2 (SGP.32 §2.11.1.2): notifications use searchCriteriaNotification. */
		retr_notif_from_lst_req.dr_search_criteria =
		    pars->ipa_euicc_data_request->searchCriteriaNotification;
		retr_notif_from_lst_res = ipa_es10b_retr_notif_from_lst(ctx, &retr_notif_from_lst_req);
		if (retr_notif_from_lst_res && retr_notif_from_lst_res->sgp32_res &&
		    retr_notif_from_lst_res->sgp32_res->present ==
			SGP32_RetrieveNotificationsListResponse_PR_notificationList) {
			/* SGP.32 §2.11.2.2: IpaEuiccData.notificationsList is
			 * PendingNotificationList (SEQUENCE OF PendingNotification) at tag [0]. */
			ipa_euicc_data_response.choice.ipaEuiccData.notificationsList =
			    &retr_notif_from_lst_res->sgp32_res->choice.notificationList;
		}

		/* FIX TODO 2 (SGP.32 §2.11.1.2): eUICC package results use the SEPARATE
		 * searchCriteriaEuiccPackageResult field; result goes into euiccPackageResultList. */
		if (pars->ipa_euicc_data_request->searchCriteriaEuiccPackageResult) {
			struct ipa_es10b_retr_notif_from_lst_req epr_req = { 0 };
			switch (pars->ipa_euicc_data_request->searchCriteriaEuiccPackageResult->present) {
			case IpaEuiccDataRequest__searchCriteriaEuiccPackageResult_PR_seqNumber:
				epr_req.search_criteria.present =
				    SGP32_RetrieveNotificationsListRequest__searchCriteria_PR_seqNumber;
				epr_req.search_criteria.choice.seqNumber =
				    pars->ipa_euicc_data_request->searchCriteriaEuiccPackageResult->choice.seqNumber;
				break;
			default:
				IPA_LOGP(SIPA, LINFO,
					 "searchCriteriaEuiccPackageResult has unrecognised branch, skipping lookup\n");
				break;
			}
			if (epr_req.search_criteria.present !=
			    SGP32_RetrieveNotificationsListRequest__searchCriteria_PR_NOTHING) {
				retr_epr_from_lst_res = ipa_es10b_retr_notif_from_lst(ctx, &epr_req);
				if (retr_epr_from_lst_res && retr_epr_from_lst_res->sgp32_res &&
				    retr_epr_from_lst_res->sgp32_res->present ==
					SGP32_RetrieveNotificationsListResponse_PR_euiccPackageResultList) {
					ipa_euicc_data_response.choice.ipaEuiccData.euiccPackageResultList =
					    &retr_epr_from_lst_res->sgp32_res->choice.euiccPackageResultList;
				}
			}
		}
	}

	/* FIX TODO 3 (SGP.32 §2.11.2.2): echo eimTransactionId from the request into
	 * IpaEuiccData field [7].  The eIM uses this to correlate the response with its
	 * original request and to verify signature coverage of the transaction.
	 * Both sides are TransactionId_t * (OCTET STRING alias); NULL pointer is fine —
	 * asn1c omits OPTIONAL fields whose pointer is NULL from the DER encoding. */
	ipa_euicc_data_response.choice.ipaEuiccData.eimTransactionId =
	    pars->ipa_euicc_data_request->eimTransactionId;
	ipa_euicc_data_response.present = IpaEuiccDataResponse_PR_ipaEuiccData;
	goto send_response;

	/* FIX TODO 4 (SGP.32 §2.11.2.2): certificate retrieval failed — build an
	 * IpaEuiccDataResponseError and fall through to send_response.
	 * GetCertsResponse__getCertsError_invalidCiPKId maps to
	 * IpaEuiccDataErrorCode_euiccCiPKIdNotFound(5); everything else maps to
	 * IpaEuiccDataErrorCode_undefinedError(127).
	 * eimTransactionId is echoed into the error response for the same reason
	 * as in the success path (correlation + signature coverage). */
send_cert_error: {
		IpaEuiccDataErrorCode_t err_code =
		    (get_certs_res &&
		     get_certs_res->get_certs_err == GetCertsResponse__getCertsError_invalidCiPKId)
		    ? IpaEuiccDataErrorCode_euiccCiPKIdNotFound
		    : IpaEuiccDataErrorCode_undefinedError;
		IPA_LOGP(SIPA, LINFO,
			 "GetCerts failed (eIM error code %ld), sending IpaEuiccDataResponseError\n",
			 (long)err_code);
		ipa_euicc_data_response.choice.ipaEuiccDataResponseError.eimTransactionId =
		    pars->ipa_euicc_data_request->eimTransactionId;
		ipa_euicc_data_response.choice.ipaEuiccDataResponseError.ipaEuiccDataErrorCode = err_code;
		ipa_euicc_data_response.present = IpaEuiccDataResponse_PR_ipaEuiccDataResponseError;
	}
	/* fall through to send_response */

send_response:
	prvde_eim_pkg_rslt_req.ipa_euicc_data_resp = &ipa_euicc_data_response;
	prvde_eim_pkg_rslt_res = ipa_esipa_prvde_eim_pkg_rslt(ctx, &prvde_eim_pkg_rslt_req);
	if (!prvde_eim_pkg_rslt_res)
		goto error;

	if (ipa_euicc_data_response.present == IpaEuiccDataResponse_PR_ipaEuiccDataResponseError)
		IPA_LOGP(SIPA, LINFO, "IPA get EUICC data failed, eIM is informed about the failure!\n");
	else
		IPA_LOGP(SIPA, LINFO, "IPA get EUICC data succeeded!\n");

	IPA_FREE(tag_list);
	ipa_es10a_get_euicc_cfg_addr_free(euicc_cfg_addr);
	ipa_es10b_get_euicc_info_free(euicc_info_1);
	ipa_es10b_get_euicc_info_free(euicc_info_2);
	ipa_es10b_get_eim_cfg_data_free(eim_cfg_data);
	ipa_es10b_get_certs_res_free(get_certs_res);
	ipa_es10b_retr_notif_from_lst_res_free(retr_notif_from_lst_res);
	ipa_es10b_retr_notif_from_lst_res_free(retr_epr_from_lst_res);
	ipa_esipa_prvde_eim_pkg_rslt_free(prvde_eim_pkg_rslt_res);
	return 0;
error:
	IPA_FREE(tag_list);
	ipa_es10a_get_euicc_cfg_addr_free(euicc_cfg_addr);
	ipa_es10b_get_euicc_info_free(euicc_info_1);
	ipa_es10b_get_euicc_info_free(euicc_info_2);
	ipa_es10b_get_eim_cfg_data_free(eim_cfg_data);
	ipa_es10b_get_certs_res_free(get_certs_res);
	ipa_es10b_retr_notif_from_lst_res_free(retr_notif_from_lst_res);
	ipa_es10b_retr_notif_from_lst_res_free(retr_epr_from_lst_res);
	ipa_esipa_prvde_eim_pkg_rslt_free(prvde_eim_pkg_rslt_res);
	IPA_LOGP(SIPA, LINFO, "IPA get EUICC data failed!\n");
	return -EINVAL;
}
