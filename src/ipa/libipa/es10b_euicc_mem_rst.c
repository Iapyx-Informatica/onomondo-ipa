/*
 * Copyright (c) 2025 Onomondo ApS & sysmocom - s.f.m.c. GmbH. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Author: Philipp Maier <pmaier@sysmocom.de> / sysmocom - s.f.m.c. GmbH
 *
 * See also: GSMA SGP.22, 5.7.19: Function (ES10b): eUICCMemoryReset
 *           GSMA SGP.32, 5.9.5 (SGP.32 override — tag / fields changed).
 *
 * =====================================================================
 * v1.1/v1.2 migration notes for this file (MAJOR CHANGES):
 * =====================================================================
 * UPDATE for v1.1: 5.9.5 — SGP.32 EuiccMemoryReset was restructured:
 *   - Tag changed from [52] (BF34) to [100] (BF64).
 *   - resetOptions adds deletePreLoadedTestProfiles(3), deleteProvisioningProfiles(4).
 *   - resetEimConfigData bit shifted from (3) to (5).
 *   - resetAutoEnableConfig renamed to resetImmediateEnableConfig and shifted
 *     from bit (4) to (6).
 *   - resetResult adds new error ecallActive(104).
 *   - resetAutoEnableConfigResult renamed to resetImmediateEnableConfigResult;
 *     the tagging is dropped (field is now untagged, relying on order).
 * TODO v1.1: after libasn regeneration the following will change:
 *   - SGP32_EuiccMemoryResetRequest / Response -> use the plain types
 *     generated from the updated SGP.32 schema (still tagged [100]).
 *   - All bit-position macros below must be renamed to match the new enum
 *     symbol names.  Specifically resetAutoEnableConfig -> resetImmediateEnableConfig.
 *   - The auto_enable_cfg request-struct field in struct ipa_es10b_euicc_mem_rst
 *     should be renamed to immediate_enable_cfg (plus one more field for
 *     deletePreLoadedTestProfiles / deleteProvisioningProfiles).
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
#include <EuiccMemoryResetRequest.h>
#include <EuiccMemoryResetResponse.h>
#include <SGP32-EuiccMemoryResetRequest.h>
#include <SGP32-EuiccMemoryResetResponse.h>
#include "context.h"
#include "utils.h"
#include "euicc.h"
#include "es10x.h"
#include "es10b_euicc_mem_rst.h"

static const struct num_str_map error_code_strings_resetResult[] = {
	{ EuiccMemoryResetResponse__resetResult_ok, "ok" },
	{ EuiccMemoryResetResponse__resetResult_nothingToDelete, "nothingToDelete" },
	{ EuiccMemoryResetResponse__resetResult_catBusy, "catBusy" },
	{ EuiccMemoryResetResponse__resetResult_undefinedError, "undefinedError" },
	{ 0, NULL }
};

static const struct num_str_map sgp32_error_code_strings_resetResult[] = {
	{ SGP32_EuiccMemoryResetResponse__resetResult_ok, "ok" },
	{ SGP32_EuiccMemoryResetResponse__resetResult_nothingToDelete, "nothingToDelete" },
	{ SGP32_EuiccMemoryResetResponse__resetResult_catBusy, "catBusy" },
	{ SGP32_EuiccMemoryResetResponse__resetResult_undefinedError, "undefinedError" },
	{ 0, NULL }
};

static const struct num_str_map sgp32_error_code_strings_resetEimResult[] = {
	{ SGP32_EuiccMemoryResetResponse__resetEimResult_ok, "ok" },
	{ SGP32_EuiccMemoryResetResponse__resetEimResult_nothingToDelete, "nothingToDelete" },
	{ SGP32_EuiccMemoryResetResponse__resetEimResult_eimResetNotSupported, "eimResetNotSupported" },
	{ SGP32_EuiccMemoryResetResponse__resetEimResult_undefinedError, "undefinedError" },
	{ 0, NULL }
};

static const struct num_str_map sgp32_error_code_strings_resetAutoEnableConfigResult[] = {
	{ SGP32_EuiccMemoryResetResponse__resetImmediateEnableConfigResult_ok, "ok" },
	{ SGP32_EuiccMemoryResetResponse__resetImmediateEnableConfigResult_resetIECNotSupported, "nothingToDelete" },
	{ SGP32_EuiccMemoryResetResponse__resetImmediateEnableConfigResult_undefinedError, "eimResetNotSupported" },
	{ 0, NULL }
};

static int dec_euicc_mem_rst_res_sgp32(const struct ipa_buf *es10b_res)
{
	struct SGP32_EuiccMemoryResetResponse *asn = NULL;
	int rc;

	asn = ipa_es10x_res_dec(&asn_DEF_SGP32_EuiccMemoryResetResponse, es10b_res, "eUICCMemoryReset");
	if (!asn)
		return -EINVAL;

	if (asn->resetResult != SGP32_EuiccMemoryResetResponse__resetResult_ok &&
	    asn->resetResult != SGP32_EuiccMemoryResetResponse__resetResult_nothingToDelete) {
		IPA_LOGP_ES10X("eUICCMemoryReset", LERROR, "function failed with error code %ld=%s!\n",
			       asn->resetResult, ipa_str_from_num(sgp32_error_code_strings_resetResult,
								  asn->resetResult, "(unknown)"));
		rc = -EINVAL;
	} else {
		IPA_LOGP_ES10X("eUICCMemoryReset", LERROR, "function succeeded with status code %ld=%s!\n",
			       asn->resetResult, ipa_str_from_num(sgp32_error_code_strings_resetResult,
								  asn->resetResult, "(unknown)"));
	}

	if (asn->resetResult != SGP32_EuiccMemoryResetResponse__resetEimResult_ok &&
	    asn->resetResult != SGP32_EuiccMemoryResetResponse__resetEimResult_nothingToDelete) {
		IPA_LOGP_ES10X("eUICCMemoryReset", LERROR, "function failed with error code %ld=%s!\n",
			       asn->resetResult, ipa_str_from_num(sgp32_error_code_strings_resetEimResult,
								  asn->resetResult, "(unknown)"));
		rc = -EINVAL;
	} else {
		IPA_LOGP_ES10X("eUICCMemoryReset", LERROR, "function succeeded with status code %ld=%s!\n",
			       asn->resetResult, ipa_str_from_num(sgp32_error_code_strings_resetEimResult,
								  asn->resetResult, "(unknown)"));
	}

	if (asn->resetResult != SGP32_EuiccMemoryResetResponse__resetImmediateEnableConfigResult_ok) {
		IPA_LOGP_ES10X("eUICCMemoryReset", LERROR, "function failed with error code %ld=%s!\n",
			       asn->resetResult, ipa_str_from_num(sgp32_error_code_strings_resetAutoEnableConfigResult,
								  asn->resetResult, "(unknown)"));
		rc = -EINVAL;
	} else {
		IPA_LOGP_ES10X("eUICCMemoryReset", LERROR, "function succeeded with status code %ld=%s!\n",
			       asn->resetResult, ipa_str_from_num(sgp32_error_code_strings_resetAutoEnableConfigResult,
								  asn->resetResult, "(unknown)"));
	}

	ASN_STRUCT_FREE(asn_DEF_EuiccMemoryResetResponse, asn);
	return rc;
}

static int dec_euicc_mem_rst_res(const struct ipa_buf *es10b_res)
{
	struct EuiccMemoryResetResponse *asn = NULL;
	int rc;

	asn = ipa_es10x_res_dec(&asn_DEF_EuiccMemoryResetResponse, es10b_res, "eUICCMemoryReset");
	if (!asn)
		return -EINVAL;

	if (asn->resetResult != EuiccMemoryResetResponse__resetResult_ok &&
	    asn->resetResult != EuiccMemoryResetResponse__resetResult_nothingToDelete) {
		IPA_LOGP_ES10X("eUICCMemoryReset", LERROR, "function failed with error code %ld=%s!\n",
			       asn->resetResult, ipa_str_from_num(error_code_strings_resetResult, asn->resetResult,
								  "(unknown)"));
		rc = -EINVAL;
	} else {
		IPA_LOGP_ES10X("eUICCMemoryReset", LERROR, "function succeeded with status code %ld=%s!\n",
			       asn->resetResult, ipa_str_from_num(error_code_strings_resetResult, asn->resetResult,
								  "(unknown)"));
	}

	ASN_STRUCT_FREE(asn_DEF_EuiccMemoryResetResponse, asn);
	return rc;
}

int euicc_mem_rst(struct ipa_context *ctx, const struct ipa_es10b_euicc_mem_rst *req)
{
	struct ipa_buf *es10b_req = NULL;
	struct ipa_buf *es10b_res = NULL;
	struct SGP32_EuiccMemoryResetRequest mem_rst_req = { 0 };
	int rc = -EINVAL;
	uint8_t rst_opt[1] = { 0 };

	mem_rst_req.resetOptions.buf = rst_opt;
	mem_rst_req.resetOptions.size = 1;
	/* UPDATE for v1.1: 5.9.5 — resetOptions has 7 bits in v1.2 (was 5);
	 * after regeneration, set bits_unused = 1 (one unused at LSB). */
	mem_rst_req.resetOptions.bits_unused = 3;

	if (req->operatnl_profiles)
		ipa_bit_string_set_named_bit(rst_opt, SGP32_EuiccMemoryResetRequest__resetOptions_deleteOperationalProfiles);
	if (req->test_profiles)
		ipa_bit_string_set_named_bit(rst_opt, SGP32_EuiccMemoryResetRequest__resetOptions_deleteFieldLoadedTestProfiles);
	if (req->default_smdp_addr)
		ipa_bit_string_set_named_bit(rst_opt, SGP32_EuiccMemoryResetRequest__resetOptions_resetDefaultSmdpAddress);
	/* TODO v1.1: 5.9.5 — add new options once struct ipa_es10b_euicc_mem_rst
	 * is extended:
	 *   if (req->pre_loaded_test_profiles)
	 *       ipa_bit_string_set_named_bit(rst_opt, ..._deletePreLoadedTestProfiles);
	 *   if (req->provisioning_profiles)
	 *       ipa_bit_string_set_named_bit(rst_opt, ..._deleteProvisioningProfiles);
	 */
	if (req->eim_cfg_data)
		/* UPDATE for v1.1: 5.9.5 — resetEimConfigData moved from bit (3) to bit (5). */
		ipa_bit_string_set_named_bit(rst_opt, SGP32_EuiccMemoryResetRequest__resetOptions_resetEimConfigData);
	/* UPDATE for v1.1: 5.9.5 — resetAutoEnableConfig (bit 4) renamed to
	 * resetImmediateEnableConfig (bit 6); after regeneration, rename the
	 * symbol below accordingly.  Also note bits 3 and 4 are now occupied by
	 * deletePreLoadedTestProfiles / deleteProvisioningProfiles respectively. */
	if (req->auto_enable_cfg)
		ipa_bit_string_set_named_bit(rst_opt, SGP32_EuiccMemoryResetRequest__resetOptions_resetImmediateEnableConfig);

	es10b_req = ipa_es10x_req_enc(&asn_DEF_SGP32_EuiccMemoryResetRequest, &mem_rst_req, "eUICCMemoryReset");
	if (!es10b_req) {
		IPA_LOGP_ES10X("eUICCMemoryReset", LERROR, "unable to encode ES10b request\n");
		goto error;
	}

	es10b_res = ipa_euicc_transceive_es10x(ctx, es10b_req);
	if (!es10b_res) {
		IPA_LOGP_ES10X("eUICCMemoryReset", LERROR, "no ES10b response\n");
		goto error;
	}

	rc = dec_euicc_mem_rst_res_sgp32(es10b_res);
	if (rc < 0)
		goto error;

error:
	IPA_FREE(es10b_req);
	IPA_FREE(es10b_res);
	return rc;
}

int euicc_mem_rst_emu(struct ipa_context *ctx, const struct ipa_es10b_euicc_mem_rst *req)
{
	struct ipa_buf *es10b_req = NULL;
	struct ipa_buf *es10b_res = NULL;
	struct EuiccMemoryResetRequest mem_rst_req = { 0 };
	int rc = -EINVAL;
	uint8_t rst_opt[1] = { 0 };

	mem_rst_req.resetOptions.buf = rst_opt;
	mem_rst_req.resetOptions.size = 1;
	mem_rst_req.resetOptions.bits_unused = 6;

	if (req->operatnl_profiles)
		ipa_bit_string_set_named_bit(rst_opt, EuiccMemoryResetRequest__resetOptions_deleteOperationalProfiles);
	if (req->test_profiles)
		ipa_bit_string_set_named_bit(rst_opt, EuiccMemoryResetRequest__resetOptions_deleteFieldLoadedTestProfiles);
	if (req->default_smdp_addr)
		ipa_bit_string_set_named_bit(rst_opt, EuiccMemoryResetRequest__resetOptions_resetDefaultSmdpAddress);

	if (req->eim_cfg_data) {
		IPA_LOGP_ES10X("eUICCMemoryReset", LINFO,
			       "IoT eUICC emulation active, also clearing memory with eIM configuration...\n");
		IPA_FREE(ctx->nvstate.iot_euicc_emu.eim_cfg_ber);
		ctx->nvstate.iot_euicc_emu.eim_cfg_ber = NULL;
	}
	if (req->auto_enable_cfg) {
		IPA_LOGP_ES10X("eUICCMemoryReset", LINFO,
			       "IoT eUICC emulation active, also clearing auto enable configuration...\n");
		IPA_FREE(ctx->nvstate.iot_euicc_emu.auto_enable.smdp_oid);
		ctx->nvstate.iot_euicc_emu.auto_enable.smdp_oid = NULL;
		IPA_FREE(ctx->nvstate.iot_euicc_emu.auto_enable.smdp_address);
		ctx->nvstate.iot_euicc_emu.auto_enable.smdp_address = NULL;
		ctx->nvstate.iot_euicc_emu.auto_enable.flag = false;
	}

	es10b_req = ipa_es10x_req_enc(&asn_DEF_EuiccMemoryResetRequest, &mem_rst_req, "eUICCMemoryReset");
	if (!es10b_req) {
		IPA_LOGP_ES10X("eUICCMemoryReset", LERROR, "unable to encode ES10b request\n");
		goto error;
	}

	es10b_res = ipa_euicc_transceive_es10x(ctx, es10b_req);
	if (!es10b_res) {
		IPA_LOGP_ES10X("eUICCMemoryReset", LERROR, "no ES10b response\n");
		goto error;
	}

	rc = dec_euicc_mem_rst_res(es10b_res);
	if (rc < 0)
		goto error;

error:
	IPA_FREE(es10b_req);
	IPA_FREE(es10b_res);
	return rc;
}

/*! Function (ES10b): eUICCMemoryReset.
 *  \param[inout] ctx pointer to ipa_context.
 *  \param[in] req pointer to struct that holds the function parameters.
 *  \returns 0 on success, negative on error. */
int ipa_es10b_euicc_mem_rst(struct ipa_context *ctx, const struct ipa_es10b_euicc_mem_rst *req)
{
	if (ctx->cfg->iot_euicc_emu_enabled)
		return euicc_mem_rst_emu(ctx, req);
	else
		return euicc_mem_rst(ctx, req);
}
