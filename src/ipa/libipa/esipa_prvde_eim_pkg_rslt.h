/*
 * Copyright (c) 2025 Onomondo ApS & sysmocom - s.f.m.c. GmbH. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#pragma once

#include <stdint.h>
#include <EuiccPackageResult.h>
#include <RetrieveNotificationsListResponse.h>
#include <IpaEuiccDataResponse.h>
#include <ProfileDownloadTriggerResult.h>
#include <EsipaMessageFromEimToIpa.h>
#include <EimAcknowledgements.h>
struct ipa_buf;
struct ipa_context;

struct ipa_esipa_prvde_eim_pkg_rslt_req {
	long eim_pkg_err;
	const struct EuiccPackageResult *euicc_package_result;
	/*! Raw BER bytes of the EuiccPackageResult as received from the eUICC.
	 *  When non-NULL these bytes are forwarded verbatim so the eUICC's
	 *  euiccSignEPR signature over euiccPackageResultDataSigned is not
	 *  broken by a BER→DER re-encoding round-trip.  Only set on the
	 *  real-eUICC (non-emulation, non-rollback) path. */
	const struct ipa_buf *raw_euicc_package_result;
	struct SGP32_RetrieveNotificationsListResponse *sgp32_notification_list;
	const struct IpaEuiccDataResponse *ipa_euicc_data_resp;
	const struct ProfileDownloadTriggerResult *prfle_dwnld_trig_req_rslt;
};

struct ipa_esipa_prvde_eim_pkg_rslt_res {
	struct EsipaMessageFromEimToIpa *msg_to_ipa;
	struct EimAcknowledgements *eim_acknowledgements;
	/*! provideEimPackageResultError from the eIM, 0 when the result was accepted (SGP.32, section
	 *  6.3.2.7; the codes were added by CR111002R00). An acceptance carrying no acknowledgements and a
	 *  rejection both leave eim_acknowledgements NULL, so this is the only way to tell them apart, and
	 *  the difference matters: on a rejection the eIM did not process the eIM Package Result, so the
	 *  IPA must keep it rather than retire it. Always 0 on the JSON binding, which carries the failure
	 *  as an HTTP status code instead (section 6.4.1.6). */
	long prvde_eim_pkg_rslt_err;
};

struct ipa_esipa_prvde_eim_pkg_rslt_res *ipa_esipa_prvde_eim_pkg_rslt(struct ipa_context *ctx, const struct ipa_esipa_prvde_eim_pkg_rslt_req
								      *req);
void ipa_esipa_prvde_eim_pkg_rslt_free(struct ipa_esipa_prvde_eim_pkg_rslt_res *res);

/*! Build a DER-encoded EimPackageResult buffer that embeds raw_euicc_pkg_result
 *  verbatim instead of re-encoding from the decoded C struct.  Used by both the
 *  ASN.1 (BER) and JSON binding paths to avoid corrupting the byte representation
 *  of euiccPackageResultDataSigned that euiccSignEPR was computed over.
 *
 *  A notification list that cannot be encoded is dropped rather than failing the
 *  whole message: the notifications stay pending and are retried, whereas an
 *  undelivered EuiccPackageResult is lost for good.
 *
 *  \param[in] raw_euicc_pkg_result  Raw BER bytes of the EuiccPackageResult; must be non-empty.
 *  \param[in] sgp32_notif_list      Notification list (may be NULL).
 *  \returns heap-allocated ipa_buf with DER bytes, or NULL on error.
 *           Caller frees with IPA_FREE(). */
struct ipa_buf *ipa_esipa_build_eim_pkg_result_der(
	const struct ipa_buf *raw_euicc_pkg_result,
	const struct SGP32_RetrieveNotificationsListResponse *sgp32_notif_list);
