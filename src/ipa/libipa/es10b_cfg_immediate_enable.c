/*
 * Copyright (c) 2026 Onomondo ApS & sysmocom - s.f.m.c. GmbH & Iapyx Informatica Ltda. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * See also: GSMA SGP.32, 5.9.17: Function (ES10b): ConfigureImmediateProfileEnabling.
 *           NEW in v1.1.  Tag [89] (BF59).
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <onomondo/ipa/mem.h>
#include <onomondo/ipa/utils.h>
#include <onomondo/ipa/log.h>
#include <ConfigureImmediateProfileEnablingRequest.h>
#include <ConfigureImmediateProfileEnablingResponse.h>
#include "context.h"
#include "utils.h"
#include "euicc.h"
#include "es10x.h"
#include "es10b_cfg_immediate_enable.h"

/* Section 5.9.17 allows at most this many arcs before we stop trying to make sense of the OID. The
 * SM-DP+ OIDs in use are far shorter; the bound only keeps a hostile string from growing the array. */
#define MAX_OID_ARCS 32

static const struct num_str_map error_code_strings[] = {
	{ ConfigureImmediateProfileEnablingResponse__configImmediateEnableResult_ok, "ok" },
	{ ConfigureImmediateProfileEnablingResponse__configImmediateEnableResult_insufficientMemory,
	  "insufficientMemory" },
	{ ConfigureImmediateProfileEnablingResponse__configImmediateEnableResult_associatedEimAlreadyExists,
	  "associatedEimAlreadyExists" },
	{ ConfigureImmediateProfileEnablingResponse__configImmediateEnableResult_undefinedError, "undefinedError" },
	{ 0, NULL }
};

static int dec_cfg_immediate_enable_res(const struct ipa_buf *es10b_res)
{
	struct ConfigureImmediateProfileEnablingResponse *asn = NULL;
	int rc;

	asn = ipa_es10x_res_dec(&asn_DEF_ConfigureImmediateProfileEnablingResponse, es10b_res,
				"ConfigureImmediateProfileEnabling");
	if (!asn)
		return -EINVAL;

	rc = asn->configImmediateEnableResult;
	if (rc == ConfigureImmediateProfileEnablingResponse__configImmediateEnableResult_ok)
		IPA_LOGP_ES10X("ConfigureImmediateProfileEnabling", LINFO,
			       "function succeeded with status code %d=%s\n", rc,
			       ipa_str_from_num(error_code_strings, rc, "(unknown)"));
	else
		IPA_LOGP_ES10X("ConfigureImmediateProfileEnabling", LERROR,
			       "function failed with error code %d=%s\n", rc,
			       ipa_str_from_num(error_code_strings, rc, "(unknown)"));

	ASN_STRUCT_FREE(asn_DEF_ConfigureImmediateProfileEnablingResponse, asn);
	return rc;
}

/* Turn a dotted-decimal OID into the DER content bytes the request carries. */
static int set_smdp_oid(OBJECT_IDENTIFIER_t *oid, const char *smdp_oid)
{
	long arcs[MAX_OID_ARCS];
	int num_arcs;

	num_arcs = OBJECT_IDENTIFIER_parse_arcs(smdp_oid, -1, arcs, MAX_OID_ARCS, NULL);
	if (num_arcs < 0) {
		IPA_LOGP_ES10X("ConfigureImmediateProfileEnabling", LERROR, "\"%s\" is not a valid OID\n", smdp_oid);
		return -EINVAL;
	}
	/* The helper reports the real arc count even when it did not fit, so that a caller can size the
	 * array; treat an over-long OID as an error rather than silently sending a truncated one. */
	if (num_arcs > MAX_OID_ARCS) {
		IPA_LOGP_ES10X("ConfigureImmediateProfileEnabling", LERROR,
			       "OID \"%s\" has %d arcs, more than the %d we handle\n", smdp_oid, num_arcs,
			       MAX_OID_ARCS);
		return -EINVAL;
	}
	if (OBJECT_IDENTIFIER_set_arcs(oid, arcs, sizeof(arcs[0]), (unsigned int)num_arcs) != 0) {
		IPA_LOGP_ES10X("ConfigureImmediateProfileEnabling", LERROR, "unable to encode OID \"%s\"\n", smdp_oid);
		return -EINVAL;
	}

	return 0;
}

/* Apply the same configuration to the emulation state that a native IoT eUICC would store, so that
 * es10b_immediate_enable.c and es10b_enable_using_dd.c see it the way they see the PSMO-driven one.
 * A consumer eUICC has no eIM Configuration Data of its own, so the associatedEimAlreadyExists check
 * of section 5.9.17 is applied against what the emulation keeps for it. */
static int cfg_immediate_enable_emu(struct ipa_context *ctx, bool immediate_enable, const char *smdp_oid,
				    const char *smdp_address)
{
	if (ctx->nvstate.iot_euicc_emu.eim_cfg_ber) {
		IPA_LOGP_ES10X("ConfigureImmediateProfileEnabling", LERROR,
			       "IoT eUICC emulation active, but eIM configuration data is already present\n");
		return ConfigureImmediateProfileEnablingResponse__configImmediateEnableResult_associatedEimAlreadyExists;
	}

	IPA_LOGP_ES10X("ConfigureImmediateProfileEnabling", LINFO,
		       "IoT eUICC emulation active, storing the immediate enabling configuration locally\n");

	ctx->nvstate.iot_euicc_emu.auto_enable.flag = immediate_enable;

	if (smdp_oid) {
		OBJECT_IDENTIFIER_t oid = { 0 };

		if (set_smdp_oid(&oid, smdp_oid) < 0)
			return -EINVAL;
		ipa_buf_free(ctx->nvstate.iot_euicc_emu.auto_enable.smdp_oid);
		ctx->nvstate.iot_euicc_emu.auto_enable.smdp_oid = IPA_BUF_FROM_ASN(&oid);
		ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_OBJECT_IDENTIFIER, &oid);
	}

	if (smdp_address) {
		ipa_buf_free(ctx->nvstate.iot_euicc_emu.auto_enable.smdp_address);
		ctx->nvstate.iot_euicc_emu.auto_enable.smdp_address =
		    ipa_buf_alloc_data(strlen(smdp_address), (uint8_t *)smdp_address);
	}

	return ConfigureImmediateProfileEnablingResponse__configImmediateEnableResult_ok;
}

static int cfg_immediate_enable(struct ipa_context *ctx, bool immediate_enable, const char *smdp_oid,
				const char *smdp_address)
{
	struct ipa_buf *es10b_req = NULL;
	struct ipa_buf *es10b_res = NULL;
	struct ConfigureImmediateProfileEnablingRequest req = { 0 };
	NULL_t immediate_enable_flag = 0;
	OBJECT_IDENTIFIER_t oid = { 0 };
	UTF8String_t address = { 0 };
	int rc = -EINVAL;

	/* Section 5.9.17: it is the presence of immediateEnableFlag that activates immediate enabling
	 * and its absence that deactivates it -- there is no "false" to send. */
	if (immediate_enable)
		req.immediateEnableFlag = &immediate_enable_flag;

	if (smdp_oid) {
		if (set_smdp_oid(&oid, smdp_oid) < 0)
			goto error;
		req.defaultSmdpOid = &oid;
	}

	if (smdp_address) {
		address.buf = (uint8_t *)smdp_address;
		address.size = strlen(smdp_address);
		req.defaultSmdpAddress = &address;
	}

	es10b_req = ipa_es10x_req_enc(&asn_DEF_ConfigureImmediateProfileEnablingRequest, &req,
				      "ConfigureImmediateProfileEnabling");
	if (!es10b_req) {
		IPA_LOGP_ES10X("ConfigureImmediateProfileEnabling", LERROR, "unable to encode ES10b request\n");
		goto error;
	}

	es10b_res = ipa_euicc_transceive_es10x(ctx, es10b_req);
	if (!es10b_res) {
		IPA_LOGP_ES10X("ConfigureImmediateProfileEnabling", LERROR, "no ES10b response\n");
		goto error;
	}

	rc = dec_cfg_immediate_enable_res(es10b_res);

error:
	/* Only the OID owns memory here; the address aliases the caller's string. */
	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_OBJECT_IDENTIFIER, &oid);
	IPA_FREE(es10b_req);
	IPA_FREE(es10b_res);
	return rc;
}

/*! Function (ES10b): ConfigureImmediateProfileEnabling.
 *  See ipa_cfg_immediate_enable() in onomondo/ipa/ipad.h. */
int ipa_es10b_cfg_immediate_enable(struct ipa_context *ctx, bool immediate_enable, const char *smdp_oid,
				   const char *smdp_address)
{
	if (IPA_EUICC_EMU(ctx))
		return cfg_immediate_enable_emu(ctx, immediate_enable, smdp_oid, smdp_address);
	else
		return cfg_immediate_enable(ctx, immediate_enable, smdp_oid, smdp_address);
}
