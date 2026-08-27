/*
 * Copyright (c) 2025 Onomondo ApS & sysmocom - s.f.m.c. GmbH. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Author: Philipp Maier <pmaier@sysmocom.de> / sysmocom - s.f.m.c. GmbH
 *
 * See also: GSMA SGP.32, section 3.1.1.1: eIM Package Retrieval
 *
 * =====================================================================
 * v1.1/v1.2 migration notes for this file:
 * =====================================================================
 * UPDATE for v1.1: 5.14.5 / 6.3.2.6 — GetEimPackage request/response changed:
 *   - Request adds optional stateChangeCause (tag [1]) and shifts rPLMN to [2].
 *   - Response gains eidNotFound(2), invalidEid(3), missingEid(4) errors.
 *   Done: ipa_esipa_note_state_change() records the cause at each local state
 *   change and esipa_get_eim_pkg.c reports it on the next poll, so nothing has
 *   to be threaded through this file.
 * UPDATE for v1.1: 3.5.2 — "More error conditions specified in the procedure".
 *   Review v1.2 §3.5.2 for new failure modes the retrieval loop should handle.
 * UPDATE for v1.1: 3.2.3.1 — Start Conditions changed.  The preconditions
 *   under which this procedure is entered (device power-on, timer, event)
 *   differ; cross-reference ipad.c trigger points against v1.2 §3.2.3.1.
 * UPDATE for v1.2: CR111006R00 / §3.2.3.1 — Step 10 of direct profile download
 *   was clarified to resolve an SGP.22 / SGP.32 conflict.  That procedure is
 *   not entered from this file, but if an eIM package points to a direct
 *   download the dispatch to proc_prfle_dwnld.c must honour the clarification.
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
#include "context.h"
#include "utils.h"
#include "esipa.h"
#include "esipa_get_eim_pkg.h"
#include "es10b_get_eim_cfg_data.h"
#include "proc_cmn_mtl_auth.h"
#include "proc_cmn_cancel_sess.h"
#include "proc_indirect_prfle_dwnld.h"
#include "proc_euicc_pkg_dwnld_exec.h"
#include "esipa_prvde_eim_pkg_rslt.h"
#include "proc_euicc_data_req.h"
#include "proc_eim_pkg_retr.h"

static int get_euicc_ci_pkid(struct ipa_context *ctx, struct ipa_buf **pkid)
{
	struct ipa_es10b_eim_cfg_data *eim_cfg_data = NULL;
	struct EimConfigurationData *eim_cfg_data_item = NULL;

	*pkid = NULL;

	eim_cfg_data = ipa_es10b_get_eim_cfg_data(ctx, ctx->eim_id);
	if (!eim_cfg_data) {
		IPA_LOGP(SIPA, LERROR, "cannot read EimConfigurationData from eUICC\n");
		goto error;
	}

	eim_cfg_data_item = ipa_es10b_get_eim_cfg_data_filter(eim_cfg_data, ctx->eim_id);
	if (!eim_cfg_data_item) {
		IPA_LOGP(SIPA, LERROR, "no EimConfigurationData item for eimId %s present!\n", ctx->eim_id);
		goto error;
	}

	if (eim_cfg_data_item->euiccCiPKId)
		*pkid = IPA_BUF_FROM_ASN(eim_cfg_data_item->euiccCiPKId);

	ipa_es10b_get_eim_cfg_data_free(eim_cfg_data);
	return 0;
error:
	IPA_LOGP(SIPA, LERROR, "unable to retrieve EimConfigurationData\n");
	ipa_es10b_get_eim_cfg_data_free(eim_cfg_data);
	return -EINVAL;
}

/* Relay package contents to suitable handler procedure */
int eim_pkg_exec(struct ipa_context *ctx, const struct ipa_esipa_get_eim_pkg_res *get_eim_pkg_res)
{
	struct ipa_buf *allowed_ca_pkid = NULL;
	/* Pre-existing, unrelated to the error reporting below: the euiccPackageRequest branch reaches the
	 * error label without ever assigning rc, so the function returned an indeterminate value.  Visible
	 * only under NDEBUG, where the assert() above that goto disappears. */
	int rc = -EINVAL;

	if (get_eim_pkg_res->euicc_package_request) {
		/* This must not happen. The internal logic in ipad_poll must make sure that
		 * ipa_proc_eucc_pkg_dwnld_exec_onset runs first in case ctx->proc_eucc_pkg_dwnld_exec_res is
		 * populated. */
		assert(!ctx->proc_eucc_pkg_dwnld_exec_res);

		ctx->proc_eucc_pkg_dwnld_exec_res =
		    ipa_proc_eucc_pkg_dwnld_exec(ctx, get_eim_pkg_res->euicc_package_request);
		if (!ctx->proc_eucc_pkg_dwnld_exec_res)
			goto error;

		/* In case the result of ipa_proc_eucc_pkg_dwnld_exec indicates that calling of
		 * ipa_proc_eucc_pkg_dwnld_exec_onset is not required, we throw away proc_eucc_pkg_dwnld_exec_res
		 * immediately. */
		if (ctx->proc_eucc_pkg_dwnld_exec_res && !ctx->proc_eucc_pkg_dwnld_exec_res->call_onset) {
			ipa_proc_eucc_pkg_dwnld_exec_res_free(ctx->proc_eucc_pkg_dwnld_exec_res);
			ctx->proc_eucc_pkg_dwnld_exec_res = NULL;
		}
	} else if (get_eim_pkg_res->ipa_euicc_data_request) {
		struct ipa_proc_euicc_data_req_pars euicc_data_req_pars = { 0 };
		euicc_data_req_pars.ipa_euicc_data_request = get_eim_pkg_res->ipa_euicc_data_request;
		rc = ipa_proc_euicc_data_req(ctx, &euicc_data_req_pars);
		if (rc < 0)
			goto error;
	} else if (get_eim_pkg_res->dwnld_trigger_request) {
		struct ipa_proc_indirect_prfle_dwnlod_pars indirect_prfle_dwnlod_pars = { 0 };
		/* SGP.32, section 5.14.1 / 6.3.2.7: the eIM identifies the operation it dispatched by this id,
		 * so it has to be echoed on the way back -- on the result and, just as much, on a rejection.
		 * Read once here because both of the step 3 checks below report with it. */
		const TransactionId_t *eim_transaction_id = get_eim_pkg_res->dwnld_trigger_request->eimTransactionId;

		if (!get_eim_pkg_res->dwnld_trigger_request->profileDownloadData) {
			/* In case the IPA capability eimDownloadDataHandling used, profileDownloadData would not be
			 * present. However, this is feature this IPAd implementation does not support.
			 *
			 * Section 3.2.3.2 step 3 lets a conforming IPA continue at step 5 with an empty trigger,
			 * relying on the eIM-handled Activation Code or on a default SM-DP+ address. This IPAd has
			 * neither, so for it the same step's other clause applies: "data needed by IPA to perform
			 * the profile download is missing the IPA SHALL return invalidPackageFormat error". */
			IPA_LOGP(SIPA, LERROR,
				 "the ProfileDownloadTriggerRequest does not contain ProfileDownloadData -- cannot continue!\n");
			ipa_esipa_report_eim_pkg_err(ctx, EimPackageResultErrorCode_invalidPackageFormat, eim_transaction_id);
			rc = -EINVAL;
			goto error;
		}
		if (get_eim_pkg_res->dwnld_trigger_request->profileDownloadData->present !=
		    ProfileDownloadData_PR_activationCode) {
			/* (see comment above) */
			IPA_LOGP(SIPA, LERROR,
				 "the ProfileDownloadData does not contain an activationCode -- cannot continue!\n");
			ipa_esipa_report_eim_pkg_err(ctx, EimPackageResultErrorCode_invalidPackageFormat, eim_transaction_id);
			rc = -EINVAL;
			goto error;
		}

		rc = get_euicc_ci_pkid(ctx, &allowed_ca_pkid);
		if (rc < 0) {
			/* The trigger was usable; this IPA could not read what it needs from its own eUICC.
			 * undefinedError says exactly that -- the package is not at fault, so the eIM should
			 * not be told it was malformed. */
			ipa_esipa_report_eim_pkg_err(ctx, EimPackageResultErrorCode_undefinedError,
						     eim_transaction_id);
			rc = -EINVAL;
			goto error;
		}

		indirect_prfle_dwnlod_pars.allowed_ca = allowed_ca_pkid;
		indirect_prfle_dwnlod_pars.tac = ctx->cfg->tac;
		/* SGP.32, section 5.14.1: the eIM identifies the session by the eimTransactionId it sent here, so
		 * it has to travel all the way to ESipa.InitiateAuthentication. It is OPTIONAL, and absent when
		 * the eIM does not use one. */
		indirect_prfle_dwnlod_pars.eim_transaction_id = eim_transaction_id;
		indirect_prfle_dwnlod_pars.ac =
		    IPA_STR_FROM_ASN(&get_eim_pkg_res->dwnld_trigger_request->profileDownloadData->
				     choice.activationCode);
		rc = ipa_proc_indirect_prfle_dwnlod(ctx, &indirect_prfle_dwnlod_pars);
		IPA_FREE((void *)indirect_prfle_dwnlod_pars.ac);
		if (rc == -EBADMSG) {
			/* Section 3.2.3.2 step 4: the Activation Code the eIM sent could not be parsed. That is
			 * still an eIM Package the IPA cannot use, and step 4 asks for the same error code as
			 * step 3. Reported from here rather than from inside the sub-procedure: everything past
			 * step 5 belongs to the RSP session and fails through the cancel-session path instead,
			 * so the sub-procedure only has to say which of the two kinds of failure it hit. */
			IPA_LOGP(SIPA, LERROR,
				 "the activationCode in the ProfileDownloadTriggerRequest could not be parsed -- cannot continue!\n");
			ipa_esipa_report_eim_pkg_err(ctx, EimPackageResultErrorCode_invalidPackageFormat, eim_transaction_id);
			goto error;
		}
		if (rc < 0)
			goto error;
	} else {
		IPA_LOGP(SIPA, LERROR,
			 "the GetEimPackageResponse contains an unsupported request -- cannot continue!\n");
		/* unknownPackage is the code for this and not invalidPackageFormat: the response parsed, it
		 * simply asked for something this IPA does not implement -- "The eIM Package is not supported
		 * by the IPA", as SGP.32 section 5.14.4 Table 15a glosses the same code.  No eimTransactionId
		 * to echo: the id lives inside the request type, and which one this is is the very thing that
		 * could not be established. */
		ipa_esipa_report_eim_pkg_err(ctx, EimPackageResultErrorCode_unknownPackage, NULL);
		rc = -EINVAL;
		goto error;
	}

	IPA_FREE(allowed_ca_pkid);
	IPA_LOGP(SIPA, LINFO, "eIM Package Execution finished!\n");
	return 0;
error:
	IPA_FREE(allowed_ca_pkid);
	IPA_LOGP(SIPA, LERROR, "eIM Package Execution failed!\n");
	return rc;
}

/*! Perform eIM Package Retrieval Procedure.
 *  \param[inout] ctx pointer to ipa_context.
 *  \returns 0 on success, negative on failure. */
int ipa_proc_eim_pkg_retr(struct ipa_context *ctx)
{
	struct ipa_esipa_get_eim_pkg_res *get_eim_pkg_res = NULL;
	int rc;

	/* Ensure that we start with a fresh connection */
	ipa_esipa_close(ctx);

	/* Poll eIM */
	get_eim_pkg_res = ipa_esipa_get_eim_pkg(ctx, ctx->eid);
	if (!get_eim_pkg_res) {
		rc = -EINVAL;
		goto error;
	} else if (get_eim_pkg_res->eim_pkg_err == GetEimPackageResponse__eimPackageError_noEimPackageAvailable) {
		rc = -GetEimPackageResponse__eimPackageError_noEimPackageAvailable;
		goto error;
	} else if (get_eim_pkg_res->eim_pkg_err) {
		rc = -EINVAL;
		goto error;
	}

	IPA_LOGP(SIPA, LINFO, "eIM Package Retrieval succeeded!\n");
	rc = eim_pkg_exec(ctx, get_eim_pkg_res);
	ipa_esipa_get_eim_pkg_free(get_eim_pkg_res);
	ipa_esipa_close(ctx);
	return rc;
error:
	ipa_esipa_get_eim_pkg_free(get_eim_pkg_res);
	IPA_LOGP(SIPA, LINFO, "eIM Package Retrieval failed!\n");
	ipa_esipa_close(ctx);
	return rc;
}
