/*
 * Copyright (c) 2025 Onomondo ApS & sysmocom - s.f.m.c. GmbH. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#pragma once

#include <stdbool.h>
#include <EuiccPackageRequest.h>
#include <EuiccPackageResult.h>
#include <SGP32-RetrieveNotificationsListResponse.h>
struct ipa_context;

struct ipa_proc_eucc_pkg_dwnld_exec_res {
	/*! flag to tell the caller that ipa_proc_eucc_pkg_dwnld_exec_onset must be called in order to complete the
	 *  procedure. */
	int call_onset;

	/*! cached EuiccPackageResult */
	struct ipa_es10b_load_euicc_pkg_res *load_euicc_pkg_res;

	struct ipa_es10b_prfle_rollback_res *prfle_rollback_res;

};

/* Helpers behind the conditional retrieval of pending Notifications (SGP.32, section 3.3.1 steps 9 and 10).
 * Exposed for the unit tests; the procedure below is their only other caller. */

/* True when the eUICC Package Result reports at least one executed PSMO, which is the condition step 9 puts on
 * calling ES10b.RetrieveNotificationsList. False for a package of eCOs alone and for the error branches. */
bool ipa_euicc_pkg_contains_psmo(const struct EuiccPackageResult *res);

/* Sequence number of a eUICC Package Result, or negative when the CHOICE carries none. */
long ipa_euicc_pkg_result_seq_number(const struct EuiccPackageResult *res);

/* True when the list may accompany the result, i.e. it is a notificationList and it is not empty. Step 10 only
 * asks for the list to be sent "in case of a non-empty list of pending Notifications". */
bool ipa_notification_list_is_useful(const struct SGP32_RetrieveNotificationsListResponse *lst);

struct ipa_proc_eucc_pkg_dwnld_exec_res *ipa_proc_eucc_pkg_dwnld_exec(struct ipa_context *ctx, const struct EuiccPackageRequest
								      *euicc_package_request);
int ipa_proc_eucc_pkg_dwnld_exec_onset(struct ipa_context *ctx, struct ipa_proc_eucc_pkg_dwnld_exec_res *res);
void ipa_proc_eucc_pkg_dwnld_exec_res_free(struct ipa_proc_eucc_pkg_dwnld_exec_res *res);
