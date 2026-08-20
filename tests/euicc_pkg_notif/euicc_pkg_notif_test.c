/*
 * Copyright (c) 2026 Onomondo ApS & sysmocom - s.f.m.c. GmbH & Iapyx Informatica Ltda. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * The cases below follow steps 9 and 10 of GSMA SGP.32, section 3.3.1 (Generic eUICC Package Download and
 * Execution): retrieving pending Notifications is conditional on the eUICC Package containing PSMO(s), and the
 * list only travels with the result when it is not empty.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <stdbool.h>
#include <onomondo/ipa/utils.h>
#include "src/ipa/libipa/proc_euicc_pkg_dwnld_exec.h"

/* A signed eUICC Package Result carrying the given result branches. */
static struct EuiccPackageResult *result_with(const EuiccResultData_PR *branches, int count, long seq_number)
{
	struct EuiccPackageResult *res = calloc(1, sizeof(*res));
	int i;

	assert(res);
	res->present = EuiccPackageResult_PR_euiccPackageResultSigned;
	res->choice.euiccPackageResultSigned.euiccPackageResultDataSigned.seqNumber = seq_number;

	for (i = 0; i < count; i++) {
		struct EuiccResultData *data = calloc(1, sizeof(*data));

		assert(data);
		data->present = branches[i];
		ASN_SEQUENCE_ADD(&res->choice.euiccPackageResultSigned.euiccPackageResultDataSigned.euiccResult.list,
				 data);
	}

	return res;
}

/* Step 9: "if the eUICC Package contains PSMO(s), the IPAd SHALL retrieve pending Notifications". */
static void psmo_detection_test(void)
{
	/* Every PSMO of SGP.32, section 2.11.1.1.3, plus the rollback result. */
	static const EuiccResultData_PR psmo[] = {
		EuiccResultData_PR_enableResult,
		EuiccResultData_PR_disableResult,
		EuiccResultData_PR_deleteResult,
		EuiccResultData_PR_listProfileInfoResult,
		EuiccResultData_PR_getRATResult,
		EuiccResultData_PR_configureImmediateEnableResult,
		EuiccResultData_PR_rollbackResult,
		EuiccResultData_PR_setFallbackAttributeResult,
		EuiccResultData_PR_unsetFallbackAttributeResult,
		EuiccResultData_PR_setDefaultDpAddressResult,
	};
	/* Every eCO of SGP.32, section 2.11.1.1.2, plus the abort marker. */
	static const EuiccResultData_PR eco[] = {
		EuiccResultData_PR_addEimResult,
		EuiccResultData_PR_deleteEimResult,
		EuiccResultData_PR_updateEimResult,
		EuiccResultData_PR_listEimResult,
		EuiccResultData_PR_processingTerminated,
	};
	unsigned int i;

	printf("== psmo_detection_test ==\n");

	/* Each PSMO on its own is enough to make the retrieval mandatory. */
	for (i = 0; i < sizeof(psmo) / sizeof(psmo[0]); i++)
		assert(ipa_euicc_pkg_contains_psmo(result_with(&psmo[i], 1, 5)) == true);

	/* No eCO ever is. */
	for (i = 0; i < sizeof(eco) / sizeof(eco[0]); i++)
		assert(ipa_euicc_pkg_contains_psmo(result_with(&eco[i], 1, 5)) == false);

	/* A whole package of eCOs -- the addEim / deleteEim / updateEim / listEim case that used to cost an
	 * ES10b round trip for nothing. */
	assert(ipa_euicc_pkg_contains_psmo(result_with(eco, sizeof(eco) / sizeof(eco[0]), 5)) == false);

	/* All PSMOs together, and a mixed package: one PSMO anywhere in the list is enough. */
	assert(ipa_euicc_pkg_contains_psmo(result_with(psmo, sizeof(psmo) / sizeof(psmo[0]), 5)) == true);
	{
		EuiccResultData_PR mixed[] = {
			EuiccResultData_PR_addEimResult,
			EuiccResultData_PR_updateEimResult,
			EuiccResultData_PR_enableResult,	/* last position on purpose */
		};
		assert(ipa_euicc_pkg_contains_psmo(result_with(mixed, 3, 5)) == true);
	}

	/* An empty result list has no PSMO either. */
	assert(ipa_euicc_pkg_contains_psmo(result_with(NULL, 0, 5)) == false);
	assert(ipa_euicc_pkg_contains_psmo(NULL) == false);
}

/* EuiccPackageResult is a CHOICE: the two error branches carry no result data and no sequence number. */
static void error_choice_test(void)
{
	struct EuiccPackageResult res = { 0 };
	static const EuiccResultData_PR enable = EuiccResultData_PR_enableResult;

	printf("== error_choice_test ==\n");

	/* The signed branch: sequence number readable, PSMO visible. */
	assert(ipa_euicc_pkg_result_seq_number(result_with(&enable, 1, 42)) == 42);
	assert(ipa_euicc_pkg_result_seq_number(result_with(&enable, 1, 0)) == 0);

	/* The eUICC refused the package: nothing was executed, so nothing is asked of it afterwards. Reading
	 * the union without checking the CHOICE is what used to produce a garbage sequence number here. */
	res.present = EuiccPackageResult_PR_euiccPackageErrorSigned;
	assert(ipa_euicc_pkg_result_seq_number(&res) < 0);
	assert(ipa_euicc_pkg_contains_psmo(&res) == false);

	res.present = EuiccPackageResult_PR_euiccPackageErrorUnsigned;
	assert(ipa_euicc_pkg_result_seq_number(&res) < 0);
	assert(ipa_euicc_pkg_contains_psmo(&res) == false);

	res.present = EuiccPackageResult_PR_NOTHING;
	assert(ipa_euicc_pkg_result_seq_number(&res) < 0);
	assert(ipa_euicc_pkg_contains_psmo(&res) == false);

	assert(ipa_euicc_pkg_result_seq_number(NULL) < 0);
}

/* Step 10: the list is included "in case of a non-empty list of pending Notifications". */
static void notification_list_test(void)
{
	struct SGP32_RetrieveNotificationsListResponse lst = { 0 };
	struct SGP32_PendingNotification *item;

	printf("== notification_list_test ==\n");

	/* Nothing retrieved at all, because step 9 was skipped. */
	assert(ipa_notification_list_is_useful(NULL) == false);

	/* A notificationList that came back empty. The ePRAndNotifications CHOICE cannot carry it: its
	 * notificationList is not OPTIONAL, so an empty one would go on the wire as an empty SEQUENCE OF. */
	lst.present = SGP32_RetrieveNotificationsListResponse_PR_notificationList;
	assert(lst.choice.notificationList.list.count == 0);
	assert(ipa_notification_list_is_useful(&lst) == false);

	/* One pending notification is enough to make it worth sending. */
	item = calloc(1, sizeof(*item));
	assert(item);
	item->present = SGP32_PendingNotification_PR_otherSignedNotification;
	ASN_SEQUENCE_ADD(&lst.choice.notificationList.list, item);
	assert(ipa_notification_list_is_useful(&lst) == true);

	/* The other branches never travel with the result. */
	lst.present = SGP32_RetrieveNotificationsListResponse_PR_notificationsListResultError;
	assert(ipa_notification_list_is_useful(&lst) == false);

	lst.present = SGP32_RetrieveNotificationsListResponse_PR_euiccPackageResultList;
	assert(ipa_notification_list_is_useful(&lst) == false);

	lst.present = SGP32_RetrieveNotificationsListResponse_PR_NOTHING;
	assert(ipa_notification_list_is_useful(&lst) == false);
}

int main(int argc, char **argv)
{
	psmo_detection_test();
	error_choice_test();
	notification_list_test();
	printf("euicc_pkg_notif_test: all checks passed\n");
	return 0;
}

/* Stubs */
void *ipa_http_init(const char *cabundle, bool no_verif)
{
	return NULL;
}

struct ipa_buf *ipa_http_req(void *http_ctx, const struct ipa_buf *req, const char *url)
{
	return NULL;
}

struct ipa_buf *ipa_http_req_with_ct(void *http_ctx, const struct ipa_buf *req, const char *url,
				     const char *content_type)
{
	return NULL;
}

void ipa_http_close(void *http_ctx)
{
	return;
}

void ipa_http_free(void *http_ctx)
{
	return;
}

void *ipa_scard_init(unsigned int reader_num)
{
	return NULL;
}

int ipa_scard_reset(void *scard_ctx)
{
	return 0;
}

int ipa_scard_atr(void *scard_ctx, struct ipa_buf *atr)
{
	return 0;
}

int ipa_scard_transceive(void *scard_ctx, struct ipa_buf *res, const struct ipa_buf *req)
{
	return 0;
}

int ipa_scard_free(void *scard_ctx)
{
	return 0;
}
