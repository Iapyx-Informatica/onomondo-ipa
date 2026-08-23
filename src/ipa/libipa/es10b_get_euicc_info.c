/*
 * Copyright (c) 2025 Onomondo ApS & sysmocom - s.f.m.c. GmbH. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Author: Philipp Maier <pmaier@sysmocom.de> / sysmocom - s.f.m.c. GmbH
 *
 * See also: GSMA SGP.22, 5.7.8: Function (ES10b): GetEUICCInfo
 *           GSMA SGP.32, 5.9.2 (SGP.32 override of EUICCInfo2).
 *
 * =====================================================================
 * v1.1/v1.2 migration notes for this file:
 * =====================================================================
 * UPDATE for v1.1: 5.9.2 — The SGP.32 EUICCInfo2 gained three new OPTIONAL
 *   fields (replacing placeholders in v1.0):
 *     - euiccCiPKIdListForSigningV3 [17] (was rfu2)
 *     - additionalEuiccInfo         [18] (was rfu3)
 *     - highestSvn                  [19] (was rfu4)
 *   These are not functionally used by v1.2 (OPTIONAL / "not used by this
 *   version") but the field names change.  convert_euicc_info_2() below
 *   must be updated to propagate them when present.
 * UPDATE for v1.1: 5.9.2 — IoTSpecificInfo gains ecallSupported and
 *   fallbackSupported.  These flags tell the eIM whether the eUICC supports
 *   the Emergency-Profile / Fallback mechanisms.
 *
 * All of the above is done.  convert_euicc_info_2() handles the four new
 * fields explicitly: the three that v1.2 does not use are left absent when
 * emulating, and iotSpecificInfo is synthesised because SGP.32 requires it.
 * proc_euicc_data_req.c passes the whole SGP32_EUICCInfo2 through to
 * IpaEuiccData, so the new fields reach the eIM unchanged.
 * ipa_es10b_get_euicc_caps() below surfaces the two flags (and iotVersion) to
 * the API consumer through ipa_get_euicc_caps().
 * =====================================================================
 */

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <onomondo/ipa/mem.h>
#include <onomondo/ipa/utils.h>
#include <onomondo/ipa/scard.h>
#include <onomondo/ipa/log.h>
#include "context.h"
#include "utils.h"
#include "euicc.h"
#include "es10x.h"
#include "es10b_get_euicc_info.h"
#include <GetEuiccInfo1Request.h>
#include <GetEuiccInfo2Request.h>

static int dec_get_euicc_info1(struct ipa_es10b_euicc_info *euicc_info, const struct ipa_buf *es10b_res)
{
	struct EUICCInfo1 *asn = NULL;

	asn = ipa_es10x_res_dec(&asn_DEF_EUICCInfo1, es10b_res, "GetEuiccInfo1Request");
	if (!asn)
		return -EINVAL;

	euicc_info->euicc_info_1 = asn;
	return 0;
}

static struct ipa_es10b_euicc_info *get_euicc_info1(struct ipa_context *ctx)
{
	struct ipa_buf *es10b_req = NULL;
	struct ipa_buf *es10b_res = NULL;
	struct ipa_es10b_euicc_info *euicc_info = IPA_ALLOC_ZERO(struct ipa_es10b_euicc_info);
	struct GetEuiccInfo1Request get_euicc_info1_req = { 0 };
	int rc;

	/* Request minimal set of the eUICC information */
	es10b_req = ipa_es10x_req_enc(&asn_DEF_GetEuiccInfo1Request, &get_euicc_info1_req, "GetEuiccInfo1Request");
	if (!es10b_req) {
		IPA_LOGP_ES10X("GetEuiccInfo1Request", LERROR, "unable to encode ES10b request\n");
		goto error;
	}

	es10b_res = ipa_euicc_transceive_es10x(ctx, es10b_req);
	if (!es10b_res) {
		IPA_LOGP_ES10X("GetEuiccInfo1Request", LERROR, "no ES10b response\n");
		goto error;
	}

	rc = dec_get_euicc_info1(euicc_info, es10b_res);

	if (rc < 0)
		goto error;

	IPA_FREE(es10b_req);
	IPA_FREE(es10b_res);
	return euicc_info;
error:
	IPA_FREE(es10b_req);
	IPA_FREE(es10b_res);
	ipa_es10b_get_euicc_info_free(euicc_info);
	return NULL;
}

static void convert_euicc_info_2(struct SGP32_EUICCInfo2 *euicc_info_out, const struct EUICCInfo2 *euicc_info_in)
{
	memset(euicc_info_out, 0, sizeof(*euicc_info_out));

	euicc_info_out->profileVersion = euicc_info_in->profileVersion;
	euicc_info_out->svn = euicc_info_in->svn;
	euicc_info_out->euiccFirmwareVer = euicc_info_in->euiccFirmwareVer;
	euicc_info_out->extCardResource = euicc_info_in->extCardResource;
	euicc_info_out->uiccCapability = euicc_info_in->uiccCapability;
	euicc_info_out->ts102241Version = euicc_info_in->ts102241Version;
	euicc_info_out->globalplatformVersion = euicc_info_in->globalplatformVersion;
	euicc_info_out->rspCapability = euicc_info_in->rspCapability;
	euicc_info_out->euiccCiPKIdListForVerification.list.count =
	    euicc_info_in->euiccCiPKIdListForVerification.list.count;
	euicc_info_out->euiccCiPKIdListForVerification.list.array =
	    euicc_info_in->euiccCiPKIdListForVerification.list.array;
	euicc_info_out->euiccCiPKIdListForSigning.list.count = euicc_info_in->euiccCiPKIdListForSigning.list.count;
	euicc_info_out->euiccCiPKIdListForSigning.list.array = euicc_info_in->euiccCiPKIdListForSigning.list.array;
	euicc_info_out->euiccCategory = euicc_info_in->euiccCategory;
	euicc_info_out->forbiddenProfilePolicyRules = euicc_info_in->forbiddenProfilePolicyRules;
	euicc_info_out->ppVersion = euicc_info_in->ppVersion;
	euicc_info_out->sasAcreditationNumber = euicc_info_in->sasAcreditationNumber;
	euicc_info_out->certificationDataObject = euicc_info_in->certificationDataObject;
	/* UPDATE for v1.1: 5.9.2 - new SGP.32-specific EUICCInfo2 fields.  These
	 * replace v1.0's rfu2/rfu3/rfu4 placeholders.  All three are OPTIONAL and
	 * documented as "not used by this version of SGP.32", so when we are
	 * emulating (the source is a consumer SGP.22 eUICC) we leave them NULL. */
	/* euicc_info_out->euiccCiPKIdListForSigningV3 / additionalEuiccInfo /
	 * highestSvn are left NULL in emulation mode by the memset(0) above. */

	/* UPDATE for v1.1: 5.9.2 - iotSpecificInfo is MANDATORY within SGP.32
	 * (SHALL be present).  When emulating with a consumer eUICC the source
	 * EUICCInfo2 does not carry it, so we synthesise one advertising the
	 * SGP.32 version that this IPA implements (v1.2.0).  ecallSupported and
	 * fallbackSupported are left absent (OPTIONAL) because a consumer eUICC
	 * does not support Emergency Profile / Fallback mechanisms. */
	/* The synthesised value is the same on every call, so it is built once at load time rather than
	 * rebuilt here.  The previous version memset() the static and then ASN_SEQUENCE_ADD()ed to it,
	 * which dropped the list array asn_set_add() had malloc'd on the call before -- a small leak on
	 * every GetEUICCInfo2 in emulation mode, and a static that one conversion could clear while
	 * another still pointed at it.  Nothing frees these: they are static storage, and the shallow
	 * IPA_FREE() in ipa_es10b_get_euicc_info_free() does not descend into them. */
	static uint8_t iot_version_bytes[3] = { 0x01, 0x02, 0x00 }; /* SGP.32 v1.2.0 */
	static VersionType_t iot_version = { .buf = iot_version_bytes, .size = sizeof(iot_version_bytes) };
	static VersionType_t *iot_version_array[1] = { &iot_version };
	static IoTSpecificInfo_t iot_specific_info = {
		.iotVersion = { .list = { .array = iot_version_array, .count = 1, .size = 1 } }
	};

	euicc_info_out->iotSpecificInfo = &iot_specific_info;

}

static int dec_get_euicc_info2(struct ipa_es10b_euicc_info *euicc_info, const struct ipa_buf *es10b_res)
{
	struct EUICCInfo2 *asn = NULL;

	asn = ipa_es10x_res_dec(&asn_DEF_EUICCInfo2, es10b_res, "GetEuiccInfo2Request");
	if (!asn)
		return -EINVAL;

	euicc_info->euicc_info_2 = asn;

	/* Also offer EUICCInfo2 in SGP.32 format */
	euicc_info->sgp32_euicc_info_2 = IPA_ALLOC(struct SGP32_EUICCInfo2);
	convert_euicc_info_2(euicc_info->sgp32_euicc_info_2, euicc_info->euicc_info_2);

	return 0;
}

static int dec_get_euicc_info2_sgp32(struct ipa_es10b_euicc_info *euicc_info, const struct ipa_buf *es10b_res)
{
	struct SGP32_EUICCInfo2 *asn = NULL;

	asn = ipa_es10x_res_dec(&asn_DEF_SGP32_EUICCInfo2, es10b_res, "GetEuiccInfo2Request");
	if (!asn)
		return -EINVAL;

	euicc_info->sgp32_euicc_info_2 = asn;

	return 0;
}

static struct ipa_es10b_euicc_info *get_euicc_info2(struct ipa_context *ctx)
{
	struct ipa_buf *es10b_req = NULL;
	struct ipa_buf *es10b_res = NULL;
	struct ipa_es10b_euicc_info *euicc_info = IPA_ALLOC_ZERO(struct ipa_es10b_euicc_info);
	struct GetEuiccInfo1Request get_euicc_info2_req = { 0 };
	int rc;

	/* Request full set of the eUICC information */
	es10b_req = ipa_es10x_req_enc(&asn_DEF_GetEuiccInfo2Request, &get_euicc_info2_req, "GetEuiccInfo2Request");
	if (!es10b_req) {
		IPA_LOGP_ES10X("GetEuiccInfo2Request", LERROR, "unable to encode ES10b request\n");
		goto error;
	}

	es10b_res = ipa_euicc_transceive_es10x(ctx, es10b_req);
	if (!es10b_res) {
		IPA_LOGP_ES10X("GetEuiccInfo2Request", LERROR, "no ES10b response\n");
		goto error;
	}

	if (IPA_EUICC_EMU(ctx)) {
		IPA_LOGP_ES10X("GetEuiccInfo2Request", LINFO, "IoT eUICC emulation active, will derive SGP32-EUICCInfo2 from (SGP.22) EUICCInfo2.\n");
		rc = dec_get_euicc_info2(euicc_info, es10b_res);
	} else {
		rc = dec_get_euicc_info2_sgp32(euicc_info, es10b_res);
	}
	if (rc < 0)
		goto error;


	IPA_FREE(es10b_req);
	IPA_FREE(es10b_res);
	return euicc_info;
error:
	IPA_FREE(es10b_req);
	IPA_FREE(es10b_res);
	ipa_es10b_get_euicc_info_free(euicc_info);
	return NULL;
}

/*! Function (ES10b): GetEUICCInfo.
 *  \param[inout] ctx pointer to ipa_context.
 *  \param[in] full set to true to request EUICCInfo2 instead of EUICCInfo1.
 *  \returns struct with parsed eUICC info on success, NULL on failure. */
/* Copy iotSpecificInfo.iotVersion into a plain array the API consumer can read without knowing
 * anything about asn1c.  VersionType is OCTET STRING (SIZE(3)), major/minor/revision; a shorter one
 * would be non-conformant, so the missing bytes are read as zero rather than rejected. */
static int copy_iot_versions(struct ipa_context *ctx, const IoTSpecificInfo_t *iot)
{
	int count = iot->iotVersion.list.count;
	int i;

	/* SGP.32 5.9.2 requires at least one version. An eUICC that sends none is broken, but the two
	 * support flags are still worth reporting, so this is not treated as a failure. */
	if (count <= 0) {
		IPA_LOGP_ES10X("GetEuiccInfo2Request", LERROR, "iotSpecificInfo carries no iotVersion!\n");
		ctx->euicc_caps.iot_version = NULL;
		ctx->euicc_caps.iot_version_count = 0;
		return 0;
	}

	ctx->euicc_caps.iot_version = IPA_CALLOC(count, sizeof(struct ipa_version));
	if (!ctx->euicc_caps.iot_version)
		return -ENOMEM;
	ctx->euicc_caps.iot_version_count = count;

	for (i = 0; i < count; i++) {
		const VersionType_t *v = iot->iotVersion.list.array[i];

		if (!v || !v->buf)
			continue;
		if (v->size > 0)
			ctx->euicc_caps.iot_version[i].major = v->buf[0];
		if (v->size > 1)
			ctx->euicc_caps.iot_version[i].minor = v->buf[1];
		if (v->size > 2)
			ctx->euicc_caps.iot_version[i].revision = v->buf[2];
	}

	return 0;
}

/* See ipa_get_euicc_caps() in onomondo/ipa/ipad.h. */
int ipa_es10b_get_euicc_caps(struct ipa_context *ctx, struct ipa_euicc_caps *caps)
{
	struct ipa_es10b_euicc_info *euicc_info = NULL;
	const IoTSpecificInfo_t *iot;
	int rc = -EINVAL;

	if (ctx->euicc_caps.valid)
		goto done;

	euicc_info = ipa_es10b_get_euicc_info(ctx, true);
	if (!euicc_info || !euicc_info->sgp32_euicc_info_2) {
		IPA_LOGP_ES10X("GetEuiccInfo2Request", LERROR, "unable to read EUICCInfo2 from the eUICC\n");
		goto leave;
	}

	iot = euicc_info->sgp32_euicc_info_2->iotSpecificInfo;
	if (!iot) {
		/* SGP.32 5.9.2: iotSpecificInfo is mandatory within SGP.32, and the emulation path
		 * synthesises one, so only a non-conformant IoT eUICC reaches this. */
		IPA_LOGP_ES10X("GetEuiccInfo2Request", LERROR,
			       "EUICCInfo2 carries no iotSpecificInfo, cannot report eUICC capabilities!\n");
		goto leave;
	}

	/* Both flags are ASN.1 NULL, so it is their presence that carries the meaning. */
	ctx->euicc_caps.ecall_supported = iot->ecallSupported != NULL;
	ctx->euicc_caps.fallback_supported = iot->fallbackSupported != NULL;

	rc = copy_iot_versions(ctx, iot);
	if (rc < 0)
		goto leave;

	ctx->euicc_caps.valid = true;

done:
	caps->ecall_supported = ctx->euicc_caps.ecall_supported;
	caps->fallback_supported = ctx->euicc_caps.fallback_supported;
	caps->iot_version = ctx->euicc_caps.iot_version;
	caps->iot_version_count = ctx->euicc_caps.iot_version_count;
	/* Not cached alongside the rest: these come from the ISD-R SELECT, so they are already known by
	 * the time any ES10b command can be sent, and ipa_mode is a state that may still change. */
	caps->ipae_supported = ctx->isdr_fci.ipae_supported;
	caps->ipa_mode = ctx->ipa_mode;
	rc = 0;

leave:
	ipa_es10b_get_euicc_info_free(euicc_info);
	return rc;
}

struct ipa_es10b_euicc_info *ipa_es10b_get_euicc_info(struct ipa_context *ctx, bool full)
{
	if (full)
		return get_euicc_info2(ctx);
	else
		return get_euicc_info1(ctx);
}

/*! Free results of function (ES10b): GetEUICCInfo.
 *  \param[in] res pointer to function result. */
void ipa_es10b_get_euicc_info_free(struct ipa_es10b_euicc_info *res)
{
	if (!res)
		return;

	ASN_STRUCT_FREE(asn_DEF_EUICCInfo1, res->euicc_info_1);

	if (res->euicc_info_2) {
		IPA_FREE(res->sgp32_euicc_info_2);
		ASN_STRUCT_FREE(asn_DEF_EUICCInfo2, res->euicc_info_2);
	} else {
		ASN_STRUCT_FREE(asn_DEF_SGP32_EUICCInfo2, res->sgp32_euicc_info_2);
	}

	IPA_FREE(res);
}
