/*
 * Copyright (c) 2026 Onomondo ApS & sysmocom - s.f.m.c. GmbH & Iapyx Informatica Ltda. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * See also: GSMA SGP.32, 5.9.25: Function (ES10b): SetDefaultDpAddress.
 *           NEW in v1.1.  Tag [101] (BF65).
 *
 * Setting the default SM-DP+ address locally.  A real IoT eUICC also accepts this from the eIM as
 * Psmo.setDefaultDpAddress (2.11.1.1.3) inside an eUICC Package, which it executes itself; under the
 * IoT eUICC emulation that PSMO is serviced by calling this function (see es10b_load_euicc_pkg.c).
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <onomondo/ipa/mem.h>
#include <onomondo/ipa/utils.h>
#include <onomondo/ipa/scard.h>
#include <onomondo/ipa/log.h>
#include <SGP32-SetDefaultDpAddressRequest.h>
#include <SGP32-SetDefaultDpAddressResponse.h>
#include <SetDefaultDpAddressRequest.h>
#include <SetDefaultDpAddressResponse.h>
#include "context.h"
#include "utils.h"
#include "euicc.h"
#include "es10x.h"
#include "es10b_set_default_dp_addr.h"

static const struct num_str_map error_code_strings[] = {
	{ SGP32_SetDefaultDpAddressResponse__setDefaultDpAddressResult_ok, "ok" },
	{ SGP32_SetDefaultDpAddressResponse__setDefaultDpAddressResult_undefinedError, "undefinedError" },
	{ 0, NULL }
};

static int dec_set_default_dp_addr_res(const struct ipa_buf *es10b_res)
{
	struct SGP32_SetDefaultDpAddressResponse *asn = NULL;
	int rc;

	asn = ipa_es10x_res_dec(&asn_DEF_SGP32_SetDefaultDpAddressResponse, es10b_res, "SetDefaultDpAddress");
	if (!asn)
		return -EINVAL;

	rc = asn->setDefaultDpAddressResult;
	if (rc == SGP32_SetDefaultDpAddressResponse__setDefaultDpAddressResult_ok)
		IPA_LOGP_ES10X("SetDefaultDpAddress", LINFO, "function succeeded with status code %d=%s\n",
			       rc, ipa_str_from_num(error_code_strings, rc, "(unknown)"));
	else
		IPA_LOGP_ES10X("SetDefaultDpAddress", LERROR, "function failed with error code %d=%s\n",
			       rc, ipa_str_from_num(error_code_strings, rc, "(unknown)"));

	ASN_STRUCT_FREE(asn_DEF_SGP32_SetDefaultDpAddressResponse, asn);
	return rc;
}

/* SGP.22 has the same function on ES10a as [63], tag 'BF3F' (RSPDefinitions), with an identical body
 * and an identical result set -- SGP.32 only moved it to [101] / 'BF65'.  A consumer eUICC knows the
 * SGP.22 tag and nothing about the SGP.32 one, so the emulation swaps the type and leaves everything
 * else alone. */
static int dec_set_default_dp_addr_res_emu(const struct ipa_buf *es10b_res)
{
	struct SetDefaultDpAddressResponse *asn = NULL;
	int rc;

	asn = ipa_es10x_res_dec(&asn_DEF_SetDefaultDpAddressResponse, es10b_res, "SetDefaultDpAddress");
	if (!asn)
		return -EINVAL;

	rc = asn->setDefaultDpAddressResult;
	if (rc == SetDefaultDpAddressResponse__setDefaultDpAddressResult_ok)
		IPA_LOGP_ES10X("SetDefaultDpAddress", LINFO,
			       "IoT eUICC emulation active, function succeeded with status code %d=%s\n", rc,
			       ipa_str_from_num(error_code_strings, rc, "(unknown)"));
	else
		IPA_LOGP_ES10X("SetDefaultDpAddress", LERROR,
			       "IoT eUICC emulation active, function failed with error code %d=%s\n", rc,
			       ipa_str_from_num(error_code_strings, rc, "(unknown)"));

	ASN_STRUCT_FREE(asn_DEF_SetDefaultDpAddressResponse, asn);
	return rc;
}

static int set_default_dp_addr_emu(struct ipa_context *ctx, const char *default_dp_fqdn)
{
	struct ipa_buf *es10b_req = NULL;
	struct ipa_buf *es10b_res = NULL;
	struct SetDefaultDpAddressRequest req = { 0 };
	int rc = -EINVAL;

	IPA_ASSIGN_STR_TO_ASN(req.defaultDpAddress, default_dp_fqdn);

	es10b_req = ipa_es10x_req_enc(&asn_DEF_SetDefaultDpAddressRequest, &req, "SetDefaultDpAddress");
	if (!es10b_req) {
		IPA_LOGP_ES10X("SetDefaultDpAddress", LERROR, "unable to encode ES10a request\n");
		goto error;
	}

	es10b_res = ipa_euicc_transceive_es10x(ctx, es10b_req);
	if (!es10b_res) {
		IPA_LOGP_ES10X("SetDefaultDpAddress", LERROR, "no ES10a response\n");
		goto error;
	}

	rc = dec_set_default_dp_addr_res_emu(es10b_res);

error:
	IPA_FREE(es10b_req);
	IPA_FREE(es10b_res);
	return rc;
}

static int set_default_dp_addr(struct ipa_context *ctx, const char *default_dp_fqdn)
{
	struct ipa_buf *es10b_req = NULL;
	struct ipa_buf *es10b_res = NULL;
	struct SGP32_SetDefaultDpAddressRequest req = { 0 };
	int rc = -EINVAL;

	/* Pointer-only assignment (no copy); req is only alive for the encode below. */
	IPA_ASSIGN_STR_TO_ASN(req.defaultDpAddress, default_dp_fqdn);

	es10b_req = ipa_es10x_req_enc(&asn_DEF_SGP32_SetDefaultDpAddressRequest, &req, "SetDefaultDpAddress");
	if (!es10b_req) {
		IPA_LOGP_ES10X("SetDefaultDpAddress", LERROR, "unable to encode ES10b request\n");
		goto error;
	}

	es10b_res = ipa_euicc_transceive_es10x(ctx, es10b_req);
	if (!es10b_res) {
		IPA_LOGP_ES10X("SetDefaultDpAddress", LERROR, "no ES10b response\n");
		goto error;
	}

	rc = dec_set_default_dp_addr_res(es10b_res);

error:
	IPA_FREE(es10b_req);
	IPA_FREE(es10b_res);
	return rc;
}

/*! Function (ES10b): SetDefaultDpAddress.
 *  \param[inout] ctx pointer to ipa_context.
 *  \param[in] default_dp_fqdn default SM-DP+ address as a NUL-terminated FQDN.
 *  \returns eUICC result code (0 = ok, positive = eUICC error status), negative on error. */
int ipa_es10b_set_default_dp_addr(struct ipa_context *ctx, const char *default_dp_fqdn)
{
	if (!default_dp_fqdn) {
		IPA_LOGP_ES10X("SetDefaultDpAddress", LERROR, "no default SM-DP+ address given\n");
		return -EINVAL;
	}

	if (IPA_EUICC_EMU(ctx))
		return set_default_dp_addr_emu(ctx, default_dp_fqdn);
	else
		return set_default_dp_addr(ctx, default_dp_fqdn);
}
