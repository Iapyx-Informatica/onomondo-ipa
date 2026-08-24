/*
 * Copyright (c) 2025 Onomondo ApS & sysmocom - s.f.m.c. GmbH. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Author: Philipp Maier <pmaier@sysmocom.de> / sysmocom - s.f.m.c. GmbH
 *
 * See also: GSMA SGP.32, section 3.3.1: Generic eUICC Package Download and Execution
 *
 * =====================================================================
 * v1.1/v1.2 migration notes for this file (see MIGRATION.md):
 * =====================================================================
 * UPDATE for v1.1: 2.11.2.1 — HIGH RISK: the signing input for euiccSignEPR /
 *   euiccSignEPE changed.  In v1.0 the eUICC signs over
 *   `euiccPackageResultDataSigned || eimSignature`; in v1.2 it signs over
 *   `euiccPackageResultDataSigned || associationToken` (integer, zero if none).
 *   This is eUICC-side signing, so the IPAd normally does not compute the
 *   signature.  BUT the consumer-eUICC emulation path used by this project
 *   (when -E is supplied) DOES synthesise eUICC signatures; that synthesis
 *   code must be updated accordingly.  TODO v1.1: locate signing helper and
 *   switch the TBS construction.
 *
 * UPDATE for v1.1: 2.11.1.1 — EuiccPackageSigned.transactionId renamed to
 *   eimTransactionId.  Propagate rename wherever this field is accessed.
 *
 * UPDATE for v1.1: 2.11.2 — EuiccPackageResultDataSigned renames (transactionId
 *   -> eimTransactionId, configureAutoEnableResult ->
 *   configureImmediateEnableResult, new setFallbackAttributeResult /
 *   unsetFallbackAttributeResult / setDefaultDpAddressResult branches).
 *   Any switch on EuiccResultData_PR must handle the new branches.
 *
 * UPDATE for v1.1: 5.9.11 — RetrieveNotificationsListResponse dropped the
 *   notificationAndEprList branch; the code below always uses seqNumber
 *   search criteria so this is safe, but the response consumer in
 *   es10b_retr_notif_from_lst.c must drop that branch.
 *
 * UPDATE for v1.1: 5.9.4 — CR12010R00 clarifies behaviour when optional
 *   EimConfigurationData subfields are absent; review call sites in
 *   es10b_add_init_eim.c (not here).
 * =====================================================================
 */

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <onomondo/ipa/mem.h>
#include <onomondo/ipa/utils.h>
#include <onomondo/ipa/log.h>
#include "context.h"
#include "utils.h"
#include "esipa_get_eim_pkg.h"
#include "es10b_load_euicc_pkg.h"
#include "es10b_retr_notif_from_lst.h"
#include "esipa_prvde_eim_pkg_rslt.h"
#include "es10b_rm_notif_from_lst.h"
#include "proc_euicc_pkg_dwnld_exec.h"
#include "es10b_prfle_rollback.h"

static int remove_notifications(struct ipa_context *ctx, struct EimAcknowledgements *eim_acknowledgements)
{
	unsigned int i;
	int rc;

	/* In case the eIM Has not requested to remove any pending notifications, so there is nothing to do
	 * for us here. The eIM may use the "Notification Delivery to Notification Receivers" procedure later
	 * to remove the pending notifications later. */
	if (!eim_acknowledgements)
		return 0;

	for (i = 0; i < eim_acknowledgements->list.count; i++) {
		rc = ipa_es10b_rm_notif_from_lst(ctx, *eim_acknowledgements->list.array[i]);
		if (rc < 0)
			return -EINVAL;
	}

	return 0;
}

/* Does this eUICC Package Result describe the execution of at least one PSMO?
 *
 * SGP.32, section 3.3.1 step 9 makes the retrieval of pending Notifications conditional on the eUICC Package
 * containing PSMO(s). Only PSMOs can lead to Notifications (step 8 generates them when a Profile is enabled,
 * disabled or deleted), so a package that carries eCOs alone -- addEim, deleteEim, updateEim, listEim -- has
 * nothing for ES10b.RetrieveNotificationsList to find and the call is skipped.
 *
 * The decision is taken on the result rather than on the request because the result is what the eUICC actually
 * executed: step 5 stops at the first failing operation, so a PSMO further down the list may never have run. */
bool ipa_euicc_pkg_contains_psmo(const struct EuiccPackageResult *res)
{
	unsigned int i;

	/* Only euiccPackageResultSigned carries a list of executed operations; the two error branches mean the
	 * eUICC rejected the package outright, so nothing was executed. */
	if (!res || res->present != EuiccPackageResult_PR_euiccPackageResultSigned)
		return false;

	for (i = 0; i < res->choice.euiccPackageResultSigned.euiccPackageResultDataSigned.euiccResult.list.count; i++) {
		const struct EuiccResultData *result_data =
		    res->choice.euiccPackageResultSigned.euiccPackageResultDataSigned.euiccResult.list.array[i];

		switch (result_data->present) {
		/* The PSMOs of SGP.32, section 2.11.1.1.3 */
		case EuiccResultData_PR_enableResult:
		case EuiccResultData_PR_disableResult:
		case EuiccResultData_PR_deleteResult:
		case EuiccResultData_PR_listProfileInfoResult:
		case EuiccResultData_PR_getRATResult:
		case EuiccResultData_PR_configureImmediateEnableResult:
		case EuiccResultData_PR_rollbackResult:
		case EuiccResultData_PR_setFallbackAttributeResult:
		case EuiccResultData_PR_unsetFallbackAttributeResult:
		case EuiccResultData_PR_setDefaultDpAddressResult:
			return true;
		/* The eCOs of SGP.32, section 2.11.1.1.2, plus the abort marker: neither touches a Profile. */
		case EuiccResultData_PR_addEimResult:
		case EuiccResultData_PR_deleteEimResult:
		case EuiccResultData_PR_updateEimResult:
		case EuiccResultData_PR_listEimResult:
		case EuiccResultData_PR_processingTerminated:
		default:
			break;
		}
	}

	return false;
}

/* Sequence number of a eUICC Package Result, or a negative value when the result is one of the error branches
 * that has none. EuiccPackageResult is a CHOICE, so the union member must not be read without checking. */
long ipa_euicc_pkg_result_seq_number(const struct EuiccPackageResult *res)
{
	if (!res || res->present != EuiccPackageResult_PR_euiccPackageResultSigned)
		return -1;

	return res->choice.euiccPackageResultSigned.euiccPackageResultDataSigned.seqNumber;
}

/* Is this a notification list that is worth sending to the eIM?
 *
 * SGP.32, section 3.3.1 step 10 asks for the list to be included "in case of a non-empty list of pending
 * Notifications". The notificationList of the ePRAndNotifications CHOICE is not OPTIONAL, so an empty list
 * cannot be represented there: the plain euiccPackageResult branch has to be used instead. */
bool ipa_notification_list_is_useful(const struct SGP32_RetrieveNotificationsListResponse *lst)
{
	if (!lst || lst->present != SGP32_RetrieveNotificationsListResponse_PR_notificationList)
		return false;

	return lst->choice.notificationList.list.count > 0;
}

/*! Continue Generic eUICC Package Download and Execution Procedure.
 *  \param[inout] ctx pointer to ipa_context.
 *  \param[in] res pointer to intermediate result from ipa_proc_eucc_pkg_dwnld_exec.
 *  \returns 0 on success, negative on failure. */
int ipa_proc_eucc_pkg_dwnld_exec_onset(struct ipa_context *ctx, struct ipa_proc_eucc_pkg_dwnld_exec_res *res)
{
	struct ipa_es10b_retr_notif_from_lst_req retr_notif_from_lst_req = { 0 };
	struct ipa_es10b_retr_notif_from_lst_res *retr_notif_from_lst_res = NULL;
	struct ipa_esipa_prvde_eim_pkg_rslt_req prvde_eim_pkg_rslt_req = { 0 };
	struct ipa_esipa_prvde_eim_pkg_rslt_res *prvde_eim_pkg_rslt_res = NULL;
	long seq_number;
	int rc;

	/* This function should not be called without a result from ipa_proc_eucc_pkg_dwnld_exec. */
	assert(res);

	res->call_onset = false;

	/* Make sure Step #3-#8 (ES10b.LoadEuiccPackage) was successful */
	if (!res->load_euicc_pkg_res)
		goto error;

	seq_number = ipa_euicc_pkg_result_seq_number(res->load_euicc_pkg_res->res);

	/* Step #9 (ES10b.RetrieveNotificationsList)
	 *
	 * "If the IPAd sends eUICC Package Result and Notifications to the eIM in a single eIM Package Result and
	 * if the eUICC Package contains PSMO(s), the IPAd SHALL retrieve pending Notifications by calling
	 * ES10b.RetrieveNotificationsList function." A package of eCOs alone cannot have produced a Notification,
	 * so the eUICC is not asked for one.
	 *
	 * UPDATE for v1.1: 5.9.11 — request type name retained; response parsing
	 * must drop notificationAndEprList branch (see es10b_retr_notif_from_lst.c). */
	if (seq_number >= 0 && ipa_euicc_pkg_contains_psmo(res->load_euicc_pkg_res->res)) {
		retr_notif_from_lst_req.search_criteria.choice.seqNumber = seq_number;
		retr_notif_from_lst_req.search_criteria.present =
		    RetrieveNotificationsListRequest__searchCriteria_PR_seqNumber;
		retr_notif_from_lst_res = ipa_es10b_retr_notif_from_lst(ctx, &retr_notif_from_lst_req);

		/* A failure here is not fatal. The eUICC Package Result is the payload that matters, and the
		 * eUICC has already executed the package and moved its replay counter on, so dropping the whole
		 * procedure would leave the eIM with no idea of the outcome. Step 10 allows the Notifications to
		 * travel separately ("the IPAd MAY use ESipa.HandleNotification instead"), and the eIM can also
		 * collect them later with the Notification Delivery procedure. */
		if (!retr_notif_from_lst_res || retr_notif_from_lst_res->notif_lst_result_err
		    || !retr_notif_from_lst_res->sgp32_res)
			IPA_LOGP(SIPA, LERROR,
				 "unable to retrieve the pending notifications, sending the eUICC Package Result "
				 "on its own (the notifications stay pending in the eUICC)\n");
	} else if (seq_number < 0) {
		IPA_LOGP(SIPA, LDEBUG,
			 "the eUICC rejected the package, so there are no pending notifications to retrieve.\n");
	} else {
		IPA_LOGP(SIPA, LDEBUG,
			 "the eUICC package contains no PSMOs, skipping the retrieval of pending notifications.\n");
	}

	/* Step #10-#14 (ESipa.ProvideEimPackageResult) */
	if (res->prfle_rollback_res && res->prfle_rollback_res->res->eUICCPackageResult) {
		/* Rollback result comes from a separate command; no raw bytes available. */
		prvde_eim_pkg_rslt_req.euicc_package_result = res->prfle_rollback_res->res->eUICCPackageResult;
		prvde_eim_pkg_rslt_req.raw_euicc_package_result = NULL;
	} else {
		prvde_eim_pkg_rslt_req.euicc_package_result = res->load_euicc_pkg_res->res;
		/* Pass raw BER bytes from the eUICC verbatim so the eIM can verify
		 * euiccSignEPR without a BER→DER re-encode corrupting the signed
		 * euiccPackageResultDataSigned content.  NULL on the emulation path
		 * (load_euicc_pkg_iot_emu does not populate raw_res). */
		prvde_eim_pkg_rslt_req.raw_euicc_package_result = res->load_euicc_pkg_res->raw_res;
	}
	/* Only a non-empty list may travel with the result, see ipa_notification_list_is_useful(). */
	if (retr_notif_from_lst_res && ipa_notification_list_is_useful(retr_notif_from_lst_res->sgp32_res))
		prvde_eim_pkg_rslt_req.sgp32_notification_list = retr_notif_from_lst_res->sgp32_res;
	prvde_eim_pkg_rslt_res = ipa_esipa_prvde_eim_pkg_rslt(ctx, &prvde_eim_pkg_rslt_req);

	/* A provideEimPackageResultError means the eIM received the result but could not attribute it to an
	 * eUICC (SGP.32, section 6.3.2.7), so it did not process it -- the same outcome as never reaching the
	 * eIM at all, and handled the same way here. Treating it as success would delete the eUICC Package
	 * Result notification below and lose the result for good, since the eUICC cannot reproduce it. */
	if (!prvde_eim_pkg_rslt_res || prvde_eim_pkg_rslt_res->prvde_eim_pkg_rslt_err) {
		/* In case we fail to communicate the EuiccPackageResult back to the eIM we may try to perform a
		 * profile rollback. However, this maneuver only makes sense when the profile has actually changed.
		 * The profile rollback can only be tried once and the eIM also must have allowed the profile rollback
		 * maneuver explicitly.*/
		if (!res->load_euicc_pkg_res->profile_changed) {
			IPA_LOGP(SIPA, LERROR,
				 "unable to send the EuiccPackageResult to the eIM. (active profile not changed, no profile rollback will be performed)\n");
			goto error;
		} else if (!res->load_euicc_pkg_res->rollback_allowed) {
			IPA_LOGP(SIPA, LERROR,
				 "unable to send the EuiccPackageResult to the eIM. (profile rollback not allowed by eIM)\n");
			goto error;
		} else if (res->prfle_rollback_res) {
			IPA_LOGP(SIPA, LERROR,
				 "unable to send the EuiccPackageResult to the eIM. (profile rollback already tried)\n");
			goto error;
		}

		IPA_LOGP(SIPA, LERROR,
			 "unable to send the EuiccPackageResult to the eIM. (attempting profile rollback)\n");
		/* This refreshFlag is ProfileRollback's own (SGP.32, section 5.9.16): it selects whether the
		 * eUICC swaps the Profiles straight away or through a REFRESH, and is unrelated to the flag of
		 * the same name in sections 5.9.15/5.9.20/5.9.22/5.9.23. Section 5.9.16 puts the choice on the
		 * device ("the IoT Device has the responsibility to ensure that the relevant conditions for use
		 * are met"), which is why it comes from the configuration rather than from the eUICC Package. */
		res->prfle_rollback_res = ipa_es10b_prfle_rollback(ctx, ctx->cfg->refresh_flag);
		if (!res->prfle_rollback_res
		    || res->prfle_rollback_res->res->cmdResult != ProfileRollbackResponse__cmdResult_ok) {
			IPA_LOGP(SIPA, LERROR, "profile rollback failed!\n");
			goto error;
		}

		IPA_LOGP(SIPA, LINFO, "profile rollback successful!\n");
		res->call_onset = true;
		goto error;
	}

	/* Step #15-17 (ES10b.RemoveNotificationFromList) */
	/* Remove the notification for the euiccPackageResult. There is none to remove when the eUICC rejected
	 * the package outright, since then it never allocated a sequence number for a result. */
	if (seq_number >= 0) {
		rc = ipa_es10b_rm_notif_from_lst(ctx, seq_number);
		if (rc < 0)
			goto error;
	}
	/* Remove the notifications that the eIM has requested to remove in the provideEimPackageResultResponse. */
	rc = remove_notifications(ctx, prvde_eim_pkg_rslt_res->eim_acknowledgements);
	if (rc < 0)
		goto error;

	/* Ensure that ctx->iccid is updated with the ICCID of the currently active profile */
	ipa_es10b_retr_notif_from_lst_res_free(retr_notif_from_lst_res);
	ipa_esipa_prvde_eim_pkg_rslt_free(prvde_eim_pkg_rslt_res);
	IPA_LOGP(SIPA, LINFO, "Generic eUICC Package Download and Execution succeeded!\n");
	return 0;
error:
	ipa_es10b_retr_notif_from_lst_res_free(retr_notif_from_lst_res);
	ipa_esipa_prvde_eim_pkg_rslt_free(prvde_eim_pkg_rslt_res);
	if (res->call_onset) {
		IPA_LOGP(SIPA, LERROR,
			 "Generic eUICC Package Download and Execution failed to provide the eIM package result to the eIM, retry in progress...\n");
		return 0;
	} else {
		IPA_LOGP(SIPA, LERROR, "Generic eUICC Package Download and Execution failed!\n");
		res->call_onset = false;
		return -EINVAL;
	}
}

/*! Perform Generic eUICC Package Download and Execution Procedure.
 *  \param[inout] ctx pointer to ipa_context.
 *  \param[in] euicc_package_request pointer to struct that holds the EuiccPackageRequest.
 *  \returns struct with intermediate result on success, NULL on failure. */
struct ipa_proc_eucc_pkg_dwnld_exec_res *ipa_proc_eucc_pkg_dwnld_exec(struct ipa_context *ctx, const struct EuiccPackageRequest
								      *euicc_package_request)
{
	struct ipa_es10b_load_euicc_pkg_req load_euicc_pkg_req = { 0 };
	struct ipa_proc_eucc_pkg_dwnld_exec_res *res = IPA_ALLOC_ZERO(struct ipa_proc_eucc_pkg_dwnld_exec_res);
	int rc;

	/* Step #3-#8 (ES10b.LoadEuiccPackage) */
	load_euicc_pkg_req.req = *euicc_package_request;
	res->load_euicc_pkg_res = ipa_es10b_load_euicc_pkg(ctx, &load_euicc_pkg_req);
	if (!res->load_euicc_pkg_res)
		goto error;
	else if (!res->load_euicc_pkg_res->res)
		goto error;

	if (res->load_euicc_pkg_res->profile_changed) {
		/* In case the execution of the eUICC package has done any changes to the currently selected profile
		 * we will stop here. The caller will notice that ctx->load_euicc_pkg_res is still populated and call
		 * ipa_proc_eucc_pkg_dwnld_exec_onset once the IP connection has resettled. */
		IPA_LOGP(SIPA, LINFO, "Generic eUICC Package Download and Execution progressing successfully...\n");
		res->call_onset = true;
		return res;
	} else {
		/* There were no changes to the currently selected profile, so we may continue normally. */
		rc = ipa_proc_eucc_pkg_dwnld_exec_onset(ctx, res);
		if (rc < 0)
			goto error_silent;
		return res;
	}
error:
	IPA_LOGP(SIPA, LERROR, "Generic eUICC Package Download and Execution failed!\n");
error_silent:
	ipa_proc_eucc_pkg_dwnld_exec_res_free(res);
	return NULL;
}

void ipa_proc_eucc_pkg_dwnld_exec_res_free(struct ipa_proc_eucc_pkg_dwnld_exec_res *res)
{
	if (!res)
		return;

	ipa_es10b_prfle_rollback_res_free(res->prfle_rollback_res);
	ipa_es10b_load_euicc_pkg_res_free(res->load_euicc_pkg_res);
	IPA_FREE(res);
}
