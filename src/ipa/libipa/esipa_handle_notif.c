/*
 * Copyright (c) 2025 Onomondo ApS & sysmocom - s.f.m.c. GmbH. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Author: Philipp Maier <pmaier@sysmocom.de> / sysmocom - s.f.m.c. GmbH
 *
 * See also: GSMA SGP.32, section 5.14.7: Function (ESipa): HandleNotification
 */

#include <stdint.h>
#include <errno.h>
#include <onomondo/ipa/http.h>
#include <onomondo/ipa/log.h>
#include <onomondo/ipa/ipad.h>
#include <EsipaMessageFromIpaToEim.h>
#include <EsipaMessageFromEimToIpa.h>
#include "utils.h"
#include "length.h"
#include "context.h"
#include "esipa.h"
#include "esipa_json.h"
#include "esipa_handle_notif.h"

#ifdef IPA_HAVE_ESIPA_ASN1		/* ESipa ASN.1 binding, SGP.32 section 6.3 */
static struct ipa_buf *enc_handle_notif_req(const struct ipa_esipa_handle_notif_req *req)
{
	struct EsipaMessageFromIpaToEim msg_to_eim = { 0 };
	struct ProfileInstallationResult *prfle_inst_res;

	msg_to_eim.present = EsipaMessageFromIpaToEim_PR_handleNotificationEsipa;
	msg_to_eim.choice.handleNotificationEsipa.present = HandleNotificationEsipa_PR_pendingNotification;

	if (req->profile_installation_result) {
		msg_to_eim.choice.handleNotificationEsipa.choice.pendingNotification.present =
		    SGP32_PendingNotification_PR_profileInstallationResult;
		prfle_inst_res =
		    &msg_to_eim.choice.handleNotificationEsipa.choice.pendingNotification.choice.
		    profileInstallationResult;
		prfle_inst_res->profileInstallationResultData =
		    req->profile_installation_result->profileInstallationResultData;
		prfle_inst_res->euiccSignPIR = req->profile_installation_result->euiccSignPIR;
	} else if (req->pending_notification) {
		msg_to_eim.choice.handleNotificationEsipa.choice.pendingNotification = *req->pending_notification;
	} else {
		IPA_LOGP_ESIPA("HandleNotification", LERROR, "no notification data, nothing to deliver!\n");
		return NULL;
	}

	/* Encode */
	return ipa_esipa_msg_to_eim_enc(&msg_to_eim, "HandleNotification");
}

static int dec_handle_notif_res(const struct ipa_buf *msg_to_ipa_encoded)
{
	/* There is no response defined for this function (see also SGP.32, section 6.3.2.4), so we expect just an empty
	 * response (0 bytes of data) */
	if (msg_to_ipa_encoded->len) {
		IPA_LOGP_ESIPA("HandleNotification", LERROR,
			       "Expected a response of 0 bytes, but got a response with %zu bytes!\n",
			       msg_to_ipa_encoded->len);
		return -EINVAL;
	}

	return 0;
}

#endif /* IPA_HAVE_ESIPA_ASN1 */

/*! Function (ESipa): HandleNotification.
 *  \param[inout] ctx pointer to ipa_context.
 *  \param[in] req pointer to struct that holds the function parameters.
 *  \returns 0 on success, negative on error.
 *
 *  Note: unlike the other ipa_esipa_* functions this one is NOT built on
 *  ipa_esipa_call() — it returns an int status rather than a heap-allocated
 *  result object and has no response body to decode, so the shared helper's
 *  void*-result contract does not fit.  The enc/req/dec skeleton is kept
 *  inline here on purpose. */
int ipa_esipa_handle_notif(struct ipa_context *ctx, const struct ipa_esipa_handle_notif_req *req)
{
	struct ipa_buf *esipa_req = NULL;
	struct ipa_buf *esipa_res = NULL;
	int rc = -EINVAL;

	IPA_LOGP_ESIPA("HandleNotification", LINFO, "Sending notification to eIM\n");

	/* NEW v1.2 §6.4: JSON binding dispatcher — HandleNotification has no
	 * response body in either binding. */
	if (ctx->cfg->esipa_binding == IPA_ESIPA_BINDING_JSON) {
#ifdef IPA_HAVE_ESIPA_JSON
		esipa_req = ipa_esipa_json_enc_handle_notif_req(req);
		if (!esipa_req) goto error;
		esipa_res = ipa_esipa_req(ctx, esipa_req, "HandleNotification");
		if (!esipa_res) goto error;
		rc = 0;
#else
		IPA_LOGP_ESIPA("HandleNotification", LERROR,
			       "the JSON ESipa binding is not built into this libipa "
			       "(rebuild with -DESIPA_BINDING_JSON=ON)\n");
#endif
		goto error;
	}

#ifndef IPA_HAVE_ESIPA_ASN1
	IPA_LOGP_ESIPA("HandleNotification", LERROR,
		       "the ASN.1 ESipa binding is not built into this libipa "
		       "(rebuild with -DESIPA_BINDING_ASN1=ON)\n");
	goto error;
#else
	esipa_req = enc_handle_notif_req(req);
	if (!esipa_req)
		goto error;

	esipa_res = ipa_esipa_req(ctx, esipa_req, "HandleNotification");
	if (!esipa_res)
		goto error;

	rc = dec_handle_notif_res(esipa_res);
	if (rc < 0)
		goto error;
#endif

	rc = 0;
error:
	IPA_FREE(esipa_req);
	IPA_FREE(esipa_res);
	return rc;
}
