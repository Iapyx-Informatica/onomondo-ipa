/*
 * Copyright (c) 2025 Onomondo ApS & sysmocom - s.f.m.c. GmbH. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Author: Philipp Maier <pmaier@sysmocom.de> / sysmocom - s.f.m.c. GmbH
 *
 * See also: GSMA SGP.32, section 3.2.3.2: Indirect Profile Download, steps 16 and 17
 *
 * The name of this module comes from SGP.22, section 3.1.3.2 (Sub-procedure Profile Download and Installation --
 * Download Confirmation), but that sub-procedure is not what the indirect download runs: SGP.32, section 3.2.3.2
 * spells the two steps out itself, as ES10b.PrepareDownload (step 16, which defers to section 5.7.5 of SGP.22)
 * followed by ESipa.GetBoundProfilePackage (step 17). Only the direct download refers to the SGP.22
 * sub-procedure, in section 3.2.3.1 step 11, and that flow is not implemented here.
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
#include "cert.h"
#include "es10b_prep_dwnld.h"
#include <CancelSessionReason.h>
#include <GetBoundProfilePackageResponseEsipa.h>
#include "esipa_get_bnd_prfle_pkg.h"
#include "proc_prfle_dwnld.h"

/*! Perform Sub-procedure Profile Download and Installation – Download Confirmation.
 *  \param[inout] ctx pointer to ipa_context.
 *  \param[in] pars pointer to struct that holds the procedure parameters.
 *  \returns pointer newly allocated struct with procedure result, NULL on error. */
struct ipa_esipa_get_bnd_prfle_pkg_res *ipa_proc_prfle_dwnlod(struct ipa_context *ctx,
							      const struct ipa_proc_prfle_dwnlod_pars *pars,
							      long *cancel_reason)
{
	struct ipa_es10b_prep_dwnld_req prep_dwnld_req = { 0 };
	struct ipa_es10b_prep_dwnld_res *prep_dwnld_res = NULL;
	struct ipa_esipa_get_bnd_prfle_pkg_req get_bnd_prfle_pkg_req = { 0 };
	struct ipa_esipa_get_bnd_prfle_pkg_res *get_bnd_prfle_pkg_res = NULL;

	/* Anything that goes wrong below is by default not an installation error, so it must not claim to be one. */
	*cancel_reason = CancelSessionReason_undefinedReason;

	/* The eUICC verifies CERT.DPpb.SIG in ES10b.PrepareDownload, but it has no clock, so the validity period of
	 * the certificate is checked here (same reasoning as for CERT.XXauth.SIG, see cert.c). */
	if (ipa_cert_check_validity(&pars->auth_clnt_ok_dpe->smdpCertificate, "SM-DP+ (CERT.DPpb.SIG)") < 0)
		goto error;

	prep_dwnld_req.req.smdpSigned2 = pars->auth_clnt_ok_dpe->smdpSigned2;
	prep_dwnld_req.req.smdpSignature2 = pars->auth_clnt_ok_dpe->smdpSignature2;
	prep_dwnld_req.req.smdpSignature2.size =
	    ipa_strip_tlv_envelope(prep_dwnld_req.req.smdpSignature2.buf, prep_dwnld_req.req.smdpSignature2.size,
				   0x5f37);
	/* The hash of the Confirmation Code, when the SM-DP+ asked for one. In SGP.32 it always arrives ready made
	 * from the eIM: section 5.14.3 lets the eIM provide hashCc in the ESipa.AuthenticateClient response "if a
	 * confirmation code is requested by the SM-DP+ and the confirmation code is available to the eIM", and
	 * section 3.2.3.1 step 8 notes that "How the Confirmation Code is sent to the IoT Device is out of the
	 * scope of this specification".
	 *
	 * So there is deliberately no path here for a Confirmation Code entered on the device. That belongs to the
	 * LPA of SGP.22, where section 3.1.3 step 8 has the LPAd "ask for the End User to enter the Confirmation
	 * Code" and section 3.1.3.2 step 8 leaves the retry loop to the LPAd. An IPA is not an LPA, and an IoT
	 * device generally has nobody standing at it. When the SM-DP+ demands a Confirmation Code that the eIM
	 * does not hold, the eIM answers ESipa.GetBoundProfilePackage with confirmationCodeMissing and the
	 * download fails -- correctly, and not for the IPA to work around. */
	prep_dwnld_req.req.hashCc = pars->auth_clnt_ok_dpe->hashCc;
	prep_dwnld_req.req.smdpCertificate = pars->auth_clnt_ok_dpe->smdpCertificate;

	prep_dwnld_res = ipa_es10b_prep_dwnld(ctx, &prep_dwnld_req);
	if (!prep_dwnld_res)
		goto error;

	/* The request may still have failed but we do not have to take any action on this since we forward the
	 * result as a whole to the eIM. In case of failure it is the responsibility of the eIM to look at error
	 * codes and to react accordingly. */
	get_bnd_prfle_pkg_req.prep_dwnld_res = prep_dwnld_res->res;
	get_bnd_prfle_pkg_res = ipa_esipa_get_bnd_prfle_pkg(ctx, &get_bnd_prfle_pkg_req);
	if (!get_bnd_prfle_pkg_res)
		goto error;
	else if (get_bnd_prfle_pkg_res->get_bnd_prfle_pkg_err) {
		/* "The IPAd receives metadataMismatch error in the response to ESipa.GetBoundProfilePackage [...]
		 * In this case the reason code for step (1) SHALL be metadataMismatch" (SGP.32, section 3.2.3.3).
		 * Every other error the eIM can report here -- including the confirmation code ones, which mean the
		 * eIM did not hold a confirmation code the SM-DP+ demanded -- is neither a metadata mismatch nor an
		 * error while installing a Bound Profile Package, so it falls to undefinedReason. */
		if (get_bnd_prfle_pkg_res->get_bnd_prfle_pkg_err ==
		    GetBoundProfilePackageResponseEsipa__getBoundProfilePackageErrorEsipa_metadataMismatch)
			*cancel_reason = CancelSessionReason_metadataMismatch;
		goto error;
	} else if (!get_bnd_prfle_pkg_res->get_bnd_prfle_pkg_ok)
		goto error;

	/* In case of error it is the responsibility of the caller to call the Common Cancel Session procedure.
	 * In case of success, the caller should ask the user for consent before continuing with the profile
	 * installation. */

	ipa_es10b_prep_dwnld_res_free(prep_dwnld_res);
	return get_bnd_prfle_pkg_res;
error:
	ipa_es10b_prep_dwnld_res_free(prep_dwnld_res);
	ipa_esipa_get_bnd_prfle_pkg_res_free(get_bnd_prfle_pkg_res);
	return NULL;
}
