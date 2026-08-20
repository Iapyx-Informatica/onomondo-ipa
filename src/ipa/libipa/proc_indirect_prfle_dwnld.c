/*
 * Copyright (c) 2025 Onomondo ApS & sysmocom - s.f.m.c. GmbH. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Author: Philipp Maier <pmaier@sysmocom.de> / sysmocom - s.f.m.c. GmbH
 *
 * See also: GSMA SGP.32, section 3.2.3.2: Indirect Profile Download
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
#include "activation_code.h"
#include "esipa_auth_clnt.h"
#include "proc_cmn_mtl_auth.h"
#include "proc_prfle_dwnld.h"
#include "esipa_get_bnd_prfle_pkg.h"
#include "proc_cmn_cancel_sess.h"
#include "proc_prfle_inst.h"
#include "ppr.h"
#include "proc_indirect_prfle_dwnld.h"

/*! Perform Indirect Profile Download Procedure.
 *  \param[inout] ctx pointer to ipa_context.
 *  \param[in] pars pointer to struct that holds the procedure parameters.
 *  \returns 0 on success, negative on failure. */
int ipa_proc_indirect_prfle_dwnlod(struct ipa_context *ctx, const struct ipa_proc_indirect_prfle_dwnlod_pars *pars)
{
	struct ipa_activation_code *activation_code = NULL;
	struct ipa_esipa_auth_clnt_res *auth_clnt_res = NULL;
	struct ipa_esipa_get_bnd_prfle_pkg_res *get_bnd_prfle_pkg_res = NULL;
	struct ipa_proc_cmn_mtl_auth_pars cmn_mtl_auth_pars = { 0 };
	struct ipa_proc_cmn_cancel_sess_pars cmn_cancel_sess_pars = { 0 };
	struct ipa_proc_prfle_dwnlod_pars prfle_dwnlod_pars = { 0 };
	struct ipa_proc_prfle_inst_pars prfle_inst_pars = { 0 };
	int rc = -EINVAL;
	int ppr_rc;

	/* This procedure is called when the IPAd receives an eIM package with a download trigger request
	 * (which contains the activation code) */

	activation_code = ipa_activation_code_parse(pars->ac);
	ipa_activation_code_dump(activation_code, 0, SIPA, LDEBUG);
	if (!activation_code) {
		IPA_LOGP(SIPA, LERROR, "cannot continue, activation code invalid or missing!\n");
		goto error;
	}

	/* Execute sub procedure: Common Mutual Authentication Procedure */
	cmn_mtl_auth_pars.tac = pars->tac;
	cmn_mtl_auth_pars.allowed_ca = pars->allowed_ca;
	cmn_mtl_auth_pars.smdp_addr = activation_code->sm_dp_plus_address;
	cmn_mtl_auth_pars.ac_token = activation_code->ac_token;
	cmn_mtl_auth_pars.eim_transaction_id = pars->eim_transaction_id;
	auth_clnt_res = ipa_proc_cmn_mtl_auth(ctx, &cmn_mtl_auth_pars);
	if (!auth_clnt_res) {
		IPA_LOGP(SIPA, LERROR, "cannot continue, mutual authentication failed!\n");
		goto error;
	}

	/* Everything below needs the SM-DP+ side of the AuthenticateClient response and the transaction id that goes
	 * with it. Both are optional on the wire (an SM-DS result carries neither), so check once here rather than
	 * dereferencing them blind at each of the steps that follow. */
	if (!auth_clnt_res->auth_clnt_ok_dpe || !auth_clnt_res->transaction_id) {
		IPA_LOGP(SIPA, LERROR, "cannot continue, no usable SM-DP+ authentication result from the eIM!\n");
		goto error;
	}

	/* Verify the Profile Metadata before anything is downloaded (SGP.32, section 3.2.3.2, step 15, which refers
	 * to step 7 of SGP.22, section 3.1.3): the Profile Policy Rules the SM-DP+ set in the metadata have to be
	 * allowed by the Rules Authorisation Table of this eUICC. We announce that we do this ourselves rather than
	 * leaving it to the eIM (IPA Capability eimProfileMetadataVerification stays cleared, see
	 * proc_euicc_data_req.c), so the eIM sends us the metadata and does not check it.
	 *
	 * The metadata is optional in the response: an eIM that verified it on our behalf is not obliged to pass it
	 * on. ipa_ppr_verify_metadata() treats that as "nothing to check", which is what it is -- the check has
	 * already happened, one hop further up. */
	ppr_rc = ipa_ppr_verify_metadata(ctx, auth_clnt_res->auth_clnt_ok_dpe->profileMetaData);
	if (ppr_rc < 0) {
		/* Each outcome gets the reason that describes it. pprNotAllowed says a rule of this very profile was
		 * refused, endUserRejection that the end user said no, and undefinedReason covers the case where the
		 * eUICC could not be asked at all -- there nothing was refused, and saying otherwise would misinform
		 * the operator on the other end. */
		switch (ppr_rc) {
		case -EPERM:
			IPA_LOGP(SIPA, LERROR,
				 "the profile policy rules of this profile are not allowed by this eUICC -- canceling session!\n");
			cmn_cancel_sess_pars.reason = CancelSessionReason_pprNotAllowed;
			break;
		case -EACCES:
			IPA_LOGP(SIPA, LERROR,
				 "no end user consent for the profile policy rules of this profile -- canceling session!\n");
			cmn_cancel_sess_pars.reason = CancelSessionReason_endUserRejection;
			break;
		default:
			IPA_LOGP(SIPA, LERROR,
				 "unable to verify the profile policy rules of this profile -- canceling session!\n");
			cmn_cancel_sess_pars.reason = CancelSessionReason_undefinedReason;
			break;
		}
		cmn_cancel_sess_pars.transaction_id = *auth_clnt_res->transaction_id;
		ipa_proc_cmn_cancel_sess(ctx, &cmn_cancel_sess_pars);
		goto error;
	}

	/* TODO: remove this part as it is not required (see also github issue #5) */
	/* Execute sub procedure: Sub-procedure Profile Download and Installation – Download Confirmation */
	prfle_dwnlod_pars.auth_clnt_ok_dpe = auth_clnt_res->auth_clnt_ok_dpe;
	get_bnd_prfle_pkg_res = ipa_proc_prfle_dwnlod(ctx, &prfle_dwnlod_pars);
	if (!get_bnd_prfle_pkg_res) {
		IPA_LOGP(SIPA, LERROR, "sub procedure profile download has failed -- canceling session!\n");
		cmn_cancel_sess_pars.reason = CancelSessionReason_loadBppExecutionError;
		cmn_cancel_sess_pars.transaction_id = *auth_clnt_res->transaction_id;
		ipa_proc_cmn_cancel_sess(ctx, &cmn_cancel_sess_pars);
		goto error;
	}

	/* At this point we must ask the user for consent before we proceed with the profile installation. In case the
	 * user does not consent, we must abort by calling the common cancel session procedure. This is the consent to
	 * the download as such; consent to the profile policy rules is a separate question and was settled above
	 * (SGP.22, section 3.1.3, step 8, calls the two Simple and Strong Confirmation). */
	if (ctx->cfg->prfle_inst_consent_cb
	    && !ctx->cfg->prfle_inst_consent_cb(activation_code->sm_dp_plus_address, activation_code->ac_token)) {
		IPA_LOGP(SIPA, LERROR, "no end user consent for profile installation -- canceling session!\n");
		cmn_cancel_sess_pars.reason = CancelSessionReason_endUserRejection;
		cmn_cancel_sess_pars.transaction_id = *auth_clnt_res->transaction_id;
		ipa_proc_cmn_cancel_sess(ctx, &cmn_cancel_sess_pars);
		goto error;
	}

	/* Execute sub procedure: Sub-procedure Profile Installation (See also section 3.1.3.3 of SGP.22) */
	prfle_inst_pars.bound_profile_package = &get_bnd_prfle_pkg_res->get_bnd_prfle_pkg_ok->boundProfilePackage;
	if (ipa_proc_prfle_inst(ctx, &prfle_inst_pars) < 0) {
		IPA_LOGP(SIPA, LERROR, "sub procedure profile installation has failed -- canceling session!\n");
		cmn_cancel_sess_pars.reason = CancelSessionReason_loadBppExecutionError;
		cmn_cancel_sess_pars.transaction_id = *auth_clnt_res->transaction_id;
		ipa_proc_cmn_cancel_sess(ctx, &cmn_cancel_sess_pars);
		goto error;
	}

	/* Reached only once the profile has actually been installed. */
	rc = 0;

error:
	ipa_activation_code_free(activation_code);
	ipa_esipa_auth_clnt_res_free(auth_clnt_res);
	ipa_esipa_get_bnd_prfle_pkg_res_free(get_bnd_prfle_pkg_res);
	return rc;
}
