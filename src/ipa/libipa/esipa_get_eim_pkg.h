/*
 * Copyright (c) 2025 Onomondo ApS & sysmocom - s.f.m.c. GmbH. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#pragma once

#include <stdint.h>
#include <EsipaMessageFromEimToIpa.h>
#include <EuiccPackageRequest.h>
#include <IpaEuiccDataRequest.h>
#include <ProfileDownloadTriggerRequest.h>
struct ipa_context;

struct ipa_esipa_get_eim_pkg_res {
	struct EsipaMessageFromEimToIpa *msg_to_ipa;
	struct EuiccPackageRequest *euicc_package_request;
	struct IpaEuiccDataRequest *ipa_euicc_data_request;
	struct ProfileDownloadTriggerRequest *dwnld_trigger_request;
	long eim_pkg_err;
};

struct ipa_esipa_get_eim_pkg_res *ipa_esipa_get_eim_pkg(struct ipa_context *ctx, const uint8_t *eid);

/*! Record why the eUICC state changed, to be reported on the next ESipa.GetEimPackage
 *  (SGP.32, sections 5.14.5 and 6.3.2.6).
 *  The most recent cause wins: notifyStateChange asks the eIM to re-read the eUICC wholesale, so the
 *  cause describes the latest event rather than a log of everything since the last poll.
 *  \param[inout] ctx pointer to ipa_context.
 *  \param[in] cause what happened; IPA_STATE_CHANGE_NONE clears a pending report. */
void ipa_esipa_note_state_change(struct ipa_context *ctx, enum ipa_state_change_cause cause);

/*! Record the last registered PLMN, reported on every ESipa.GetEimPackage. See ipa_set_rplmn() in
 *  onomondo/ipa/ipad.h. */
int ipa_esipa_set_rplmn(struct ipa_context *ctx, const char *mcc, const char *mnc);
void ipa_esipa_get_eim_pkg_free(struct ipa_esipa_get_eim_pkg_res *res);
