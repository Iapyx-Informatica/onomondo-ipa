/*
 * Copyright (c) 2026 Onomondo ApS & sysmocom - s.f.m.c. GmbH & Iapyx Informatica Ltda. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * See also: GSMA SGP.32, 5.9.24: Function (ES10b): GetConnectivityParameters.
 *           NEW in v1.1.  Tag [95] (BF5F).
 *
 * Exposes connectivity parameters (currently httpParams) that the IPA should
 * use when reaching back to the eIM / RSP server.  The response is a CHOICE:
 * either the parameters or an error INTEGER.  The optional httpParams OCTET
 * STRING is copied out into a caller-owned ipa_buf so the ASN.1 decode result
 * can be released here.
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <onomondo/ipa/mem.h>
#include <onomondo/ipa/utils.h>
#include <onomondo/ipa/scard.h>
#include <onomondo/ipa/log.h>
#include <GetConnectivityParametersRequest.h>
#include <GetConnectivityParametersResponse.h>
#include <ConnectivityParameters.h>
#include <ConnectivityParametersError.h>
#include "context.h"
#include "utils.h"
#include "euicc.h"
#include "es10x.h"
#include "es10b_get_connectivity_params.h"

static const struct num_str_map error_code_strings[] = {
	{ ConnectivityParametersError_parametersNotAvailable, "parametersNotAvailable" },
	{ ConnectivityParametersError_undefinedError, "undefinedError" },
	{ 0, NULL }
};

/*! Function (ES10b): GetConnectivityParameters.
 *  \param[inout] ctx pointer to ipa_context.
 *  \returns newly allocated connectivity parameters (free with
 *           ipa_es10b_connectivity_params_free), NULL on error. */
struct ipa_es10b_connectivity_params *ipa_es10b_get_connectivity_params(struct ipa_context *ctx)
{
	struct ipa_buf *es10b_req = NULL;
	struct ipa_buf *es10b_res = NULL;
	struct GetConnectivityParametersRequest req = { 0 };
	struct GetConnectivityParametersResponse *asn = NULL;
	struct ipa_es10b_connectivity_params *out = NULL;

	es10b_req = ipa_es10x_req_enc(&asn_DEF_GetConnectivityParametersRequest, &req, "GetConnectivityParameters");
	if (!es10b_req) {
		IPA_LOGP_ES10X("GetConnectivityParameters", LERROR, "unable to encode ES10b request\n");
		goto error;
	}

	es10b_res = ipa_euicc_transceive_es10x(ctx, es10b_req);
	if (!es10b_res) {
		IPA_LOGP_ES10X("GetConnectivityParameters", LERROR, "no ES10b response\n");
		goto error;
	}

	asn = ipa_es10x_res_dec(&asn_DEF_GetConnectivityParametersResponse, es10b_res, "GetConnectivityParameters");
	if (!asn)
		goto error;

	switch (asn->present) {
	case GetConnectivityParametersResponse_PR_connectivityParameters: {
		const OCTET_STRING_t *hp = asn->choice.connectivityParameters.httpParams;

		out = IPA_ALLOC_ZERO(struct ipa_es10b_connectivity_params);
		if (hp && hp->buf && hp->size > 0) {
			out->http_params = ipa_buf_alloc_and_cpy(hp->buf, hp->size);
			IPA_LOGP_ES10X("GetConnectivityParameters", LINFO, "received %d bytes of httpParams\n",
				       (int)hp->size);
		} else {
			IPA_LOGP_ES10X("GetConnectivityParameters", LINFO, "no httpParams present in response\n");
		}
		break;
	}
	case GetConnectivityParametersResponse_PR_connectivityParametersError:
		IPA_LOGP_ES10X("GetConnectivityParameters", LERROR, "function failed with error code %ld=%s\n",
			       (long)asn->choice.connectivityParametersError,
			       ipa_str_from_num(error_code_strings, asn->choice.connectivityParametersError,
						"(unknown)"));
		break;
	default:
		IPA_LOGP_ES10X("GetConnectivityParameters", LERROR, "unexpected response content!\n");
	}

error:
	if (asn)
		ASN_STRUCT_FREE(asn_DEF_GetConnectivityParametersResponse, asn);
	IPA_FREE(es10b_req);
	IPA_FREE(es10b_res);
	return out;
}

/*! Free connectivity parameters returned by ipa_es10b_get_connectivity_params().
 *  \param[in] p pointer to connectivity parameters (may be NULL). */
void ipa_es10b_connectivity_params_free(struct ipa_es10b_connectivity_params *p)
{
	if (!p)
		return;
	ipa_buf_free(p->http_params);
	IPA_FREE(p);
}
