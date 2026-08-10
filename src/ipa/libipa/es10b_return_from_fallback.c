/*
 * Copyright (c) 2026 Onomondo ApS & sysmocom - s.f.m.c. GmbH & Iapyx Informatica Ltda. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * See also: GSMA SGP.32, 5.9.21: Function (ES10b): ReturnFromFallback.
 *           NEW in v1.1.  Tag [94] (BF5E).
 *
 * Inverse of ExecuteFallbackMechanism: returns the eUICC to the previously
 * enabled operational profile.
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <onomondo/ipa/mem.h>
#include <onomondo/ipa/utils.h>
#include <onomondo/ipa/scard.h>
#include <onomondo/ipa/log.h>
#include <ReturnFromFallbackRequest.h>
#include <ReturnFromFallbackResponse.h>
#include "context.h"
#include "utils.h"
#include "euicc.h"
#include "es10x.h"
#include "es10b_return_from_fallback.h"

static const struct num_str_map error_code_strings[] = {
	{ ReturnFromFallbackResponse__returnFromFallbackResult_ok, "ok" },
	{ ReturnFromFallbackResponse__returnFromFallbackResult_catBusy, "catBusy" },
	{ ReturnFromFallbackResponse__returnFromFallbackResult_fallbackNotAvailable, "fallbackNotAvailable" },
	{ ReturnFromFallbackResponse__returnFromFallbackResult_commandError, "commandError" },
	{ ReturnFromFallbackResponse__returnFromFallbackResult_undefinedError, "undefinedError" },
	{ 0, NULL }
};

static int dec_return_from_fallback_res(const struct ipa_buf *es10b_res)
{
	struct ReturnFromFallbackResponse *asn = NULL;
	int rc;

	asn = ipa_es10x_res_dec(&asn_DEF_ReturnFromFallbackResponse, es10b_res, "ReturnFromFallback");
	if (!asn)
		return -EINVAL;

	rc = asn->returnFromFallbackResult;
	if (rc == ReturnFromFallbackResponse__returnFromFallbackResult_ok)
		IPA_LOGP_ES10X("ReturnFromFallback", LINFO, "function succeeded with status code %d=%s\n",
			       rc, ipa_str_from_num(error_code_strings, rc, "(unknown)"));
	else
		IPA_LOGP_ES10X("ReturnFromFallback", LERROR, "function failed with error code %d=%s\n",
			       rc, ipa_str_from_num(error_code_strings, rc, "(unknown)"));

	ASN_STRUCT_FREE(asn_DEF_ReturnFromFallbackResponse, asn);
	return rc;
}

/*! Function (ES10b): ReturnFromFallback.
 *  \param[inout] ctx pointer to ipa_context.
 *  \param[in] refresh_flag request a UICC REFRESH after the swap.
 *  \returns eUICC result code (0 = ok, positive = eUICC error status), negative on transport error. */
int ipa_es10b_return_from_fallback(struct ipa_context *ctx, bool refresh_flag)
{
	struct ipa_buf *es10b_req = NULL;
	struct ipa_buf *es10b_res = NULL;
	struct ReturnFromFallbackRequest req = { 0 };
	int rc = -EINVAL;

	req.refreshFlag = refresh_flag ? 1 : 0;

	es10b_req = ipa_es10x_req_enc(&asn_DEF_ReturnFromFallbackRequest, &req, "ReturnFromFallback");
	if (!es10b_req) {
		IPA_LOGP_ES10X("ReturnFromFallback", LERROR, "unable to encode ES10b request\n");
		goto error;
	}

	es10b_res = ipa_euicc_transceive_es10x(ctx, es10b_req);
	if (!es10b_res) {
		IPA_LOGP_ES10X("ReturnFromFallback", LERROR, "no ES10b response\n");
		goto error;
	}

	rc = dec_return_from_fallback_res(es10b_res);

error:
	IPA_FREE(es10b_req);
	IPA_FREE(es10b_res);
	return rc;
}
