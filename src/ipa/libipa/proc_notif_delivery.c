/*
 * Copyright (c) 2025 Onomondo ApS & sysmocom - s.f.m.c. GmbH. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Author: Philipp Maier <pmaier@sysmocom.de> / sysmocom - s.f.m.c. GmbH
 *
 * See also: GSMA SGP.32, section 3.7: Notification Delivery to Notification Receivers
 *           GSMA SGP.32, section 5.7.4 (HandleNotification, expanded description).
 *
 * =====================================================================
 * v1.1/v1.2 migration notes for this file:
 * =====================================================================
 * UPDATE for v1.1: 5.7.4 — HandleNotification procedure text was expanded;
 *   review against v1.2 to ensure the order of operations matches (this
 *   implementation batches and forwards; v1.2 may require per-notification
 *   delivery semantics).
 * UPDATE for v1.2: CR12008R01 / §5.14.7 — CompactOtherSignedNotification gained
 *   an optional eidValue so the eIM can identify the originating eUICC.  Not
 *   applicable here as things stand, and not a forwarding matter: the eUICC only
 *   ever produces the SGP.22 forms, so a CompactOtherSignedNotification would
 *   have to be built by re-encoding one.  §5.14.7 asks for that re-encoding only
 *   from "an IPA with IPA Capability minimizeEsipaBytes", which this IPA leaves
 *   cleared (see proc_euicc_data_req.c), so no compact notification is ever
 *   constructed and there is no eidValue to populate.  The loop below hands each
 *   notification to ipa_esipa_handle_notif() exactly as the eUICC returned it.
 *   Note also that §5.14.7 only recommends the field, and only where no
 *   underlying transport already identifies the EID to the eIM.  If
 *   minimizeEsipaBytes is ever implemented, setting eidValue from ctx->eid
 *   belongs to that work, together with the seqNumber extraction in the switch
 *   below, which has no case for the compact branches.
 * UPDATE for v1.1: 5.9.11 — the underlying RetrieveNotificationsList response
 *   dropped the notificationAndEprList branch; see es10b_retr_notif_from_lst.c
 *   for the code affected.  This procedure only reads notificationList so the
 *   change is transparent here after libasn regeneration.
 * =====================================================================
 */

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <onomondo/ipa/mem.h>
#include <onomondo/ipa/utils.h>
#include <onomondo/ipa/log.h>
#include "context.h"
#include "utils.h"
#include "proc_notif_delivery.h"
#include "es10b_retr_notif_from_lst.h"
#include "esipa_handle_notif.h"
#include "es10b_rm_notif_from_lst.h"

/*! Perform Notification Delivery to Notification Receivers Procedure.
 *  \param[inout] ctx pointer to ipa_context.
 *  \returns 0 on success, negative on failure. */
int ipa_notif_delivery(struct ipa_context *ctx)
{
	struct ipa_es10b_retr_notif_from_lst_req retr_notif_from_lst_req = { 0 };
	struct ipa_es10b_retr_notif_from_lst_res *retr_notif_from_lst_res = NULL;
	struct ipa_esipa_handle_notif_req handle_notif_req = { 0 };
	unsigned int i;
	int rc;
	long seq_number;

	retr_notif_from_lst_res = ipa_es10b_retr_notif_from_lst(ctx, &retr_notif_from_lst_req);
	if (!retr_notif_from_lst_res)
		goto error;
	else if (retr_notif_from_lst_res->notif_lst_result_err)
		goto error;
	else if (!retr_notif_from_lst_res->sgp32_res)
		goto error;

	/* In this procedure we expect to get a notificationList, all other types of lists are not suitable for this
	 * procedure. */
	else if (retr_notif_from_lst_res->sgp32_res->present !=
		 SGP32_RetrieveNotificationsListResponse_PR_notificationList) {
		IPA_LOGP(SIPA, LERROR, "Expecting a notificationList, but got something different!\n");
		goto error;
	}

	for (i = 0; i < retr_notif_from_lst_res->sgp32_res->choice.notificationList.list.count; i++) {
		IPA_LOGP(SIPA, LERROR, "Delivery of notification No.%u:\n", i);
		handle_notif_req.pending_notification =
		    retr_notif_from_lst_res->sgp32_res->choice.notificationList.list.array[i];
		rc = ipa_esipa_handle_notif(ctx, &handle_notif_req);
		if (rc < 0)
			IPA_LOGP(SIPA, LERROR, "Delivery of notification No.%u failed, will try again later!\n", i);
		else {
			switch (handle_notif_req.pending_notification->present) {
			case SGP32_PendingNotification_PR_profileInstallationResult:
				seq_number =
				    handle_notif_req.pending_notification->choice.profileInstallationResult.
				    profileInstallationResultData.notificationMetadata.seqNumber;
				ipa_es10b_rm_notif_from_lst(ctx, seq_number);
				break;
			case SGP32_PendingNotification_PR_otherSignedNotification:
				seq_number =
				    handle_notif_req.pending_notification->choice.otherSignedNotification.
				    tbsOtherNotification.seqNumber;
				ipa_es10b_rm_notif_from_lst(ctx, seq_number);
				break;
			default:
				/* This should not happen, the eUICC should only return the two notification types listed above */
				IPA_LOGP(SIPA, LERROR,
					 "Unknown type of notification, removal of notification No.%u failed\n", i);
			}
		}
	}

	IPA_LOGP(SIPA, LDEBUG, "Notification Delivery to Notification Receivers Procedure succeeded!\n");
	ipa_es10b_retr_notif_from_lst_res_free(retr_notif_from_lst_res);
	return 0;
error:
	IPA_LOGP(SIPA, LERROR, "Notification Delivery to Notification Receivers Procedure failed!\n");
	ipa_es10b_retr_notif_from_lst_res_free(retr_notif_from_lst_res);
	return -EINVAL;
}
