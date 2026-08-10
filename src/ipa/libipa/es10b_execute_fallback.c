/*
 * Copyright (c) 2026 Onomondo ApS & sysmocom - s.f.m.c. GmbH & Iapyx Informatica Ltda. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * See also: GSMA SGP.32, 5.9.20: Function (ES10b): ExecuteFallbackMechanism.
 *           NEW in v1.1.  Tag [93] (BF5D).
 *
 * Swaps the eUICC to the Fallback Profile (previously tagged via
 * Psmo.setFallbackAttribute) when the enabled profile lost connectivity.
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <onomondo/ipa/mem.h>
#include <onomondo/ipa/utils.h>
#include <onomondo/ipa/scard.h>
#include <onomondo/ipa/log.h>
#include <ExecuteFallbackMechanismRequest.h>
#include <ExecuteFallbackMechanismResponse.h>
#include "context.h"
#include "utils.h"
#include "euicc.h"
#include "es10x.h"
#include "es10b_execute_fallback.h"

static const struct num_str_map error_code_strings[] = {
	{ ExecuteFallbackMechanismResponse__executeFallbackMechanismResult_ok, "ok" },
	{ ExecuteFallbackMechanismResponse__executeFallbackMechanismResult_profileNotInDisabledState,
	  "profileNotInDisabledState" },
	{ ExecuteFallbackMechanismResponse__executeFallbackMechanismResult_catBusy, "catBusy" },
	{ ExecuteFallbackMechanismResponse__executeFallbackMechanismResult_fallbackNotAvailable,
	  "fallbackNotAvailable" },
	{ ExecuteFallbackMechanismResponse__executeFallbackMechanismResult_commandError, "commandError" },
	{ ExecuteFallbackMechanismResponse__executeFallbackMechanismResult_ecallActive, "ecallActive" },
	{ ExecuteFallbackMechanismResponse__executeFallbackMechanismResult_undefinedError, "undefinedError" },
	{ 0, NULL }
};

static int dec_execute_fallback_res(const struct ipa_buf *es10b_res)
{
	struct ExecuteFallbackMechanismResponse *asn = NULL;
	int rc;

	asn = ipa_es10x_res_dec(&asn_DEF_ExecuteFallbackMechanismResponse, es10b_res, "ExecuteFallbackMechanism");
	if (!asn)
		return -EINVAL;

	rc = asn->executeFallbackMechanismResult;
	if (rc == ExecuteFallbackMechanismResponse__executeFallbackMechanismResult_ok)
		IPA_LOGP_ES10X("ExecuteFallbackMechanism", LINFO, "function succeeded with status code %d=%s\n",
			       rc, ipa_str_from_num(error_code_strings, rc, "(unknown)"));
	else
		IPA_LOGP_ES10X("ExecuteFallbackMechanism", LERROR, "function failed with error code %d=%s\n",
			       rc, ipa_str_from_num(error_code_strings, rc, "(unknown)"));

	ASN_STRUCT_FREE(asn_DEF_ExecuteFallbackMechanismResponse, asn);
	return rc;
}

/*! Function (ES10b): ExecuteFallbackMechanism.
 *  \param[inout] ctx pointer to ipa_context.
 *  \param[in] refresh_flag request a UICC REFRESH after the swap.
 *  \returns eUICC result code (0 = ok, positive = eUICC error status), negative on transport error. */
int ipa_es10b_execute_fallback(struct ipa_context *ctx, bool refresh_flag)
{
	struct ipa_buf *es10b_req = NULL;
	struct ipa_buf *es10b_res = NULL;
	struct ExecuteFallbackMechanismRequest req = { 0 };
	int rc = -EINVAL;

	req.refreshFlag = refresh_flag ? 1 : 0;

	es10b_req = ipa_es10x_req_enc(&asn_DEF_ExecuteFallbackMechanismRequest, &req, "ExecuteFallbackMechanism");
	if (!es10b_req) {
		IPA_LOGP_ES10X("ExecuteFallbackMechanism", LERROR, "unable to encode ES10b request\n");
		goto error;
	}

	es10b_res = ipa_euicc_transceive_es10x(ctx, es10b_req);
	if (!es10b_res) {
		IPA_LOGP_ES10X("ExecuteFallbackMechanism", LERROR, "no ES10b response\n");
		goto error;
	}

	rc = dec_execute_fallback_res(es10b_res);

error:
	IPA_FREE(es10b_req);
	IPA_FREE(es10b_res);
	return rc;
}
