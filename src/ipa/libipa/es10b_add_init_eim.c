/*
 * Copyright (c) 2025 Onomondo ApS & sysmocom - s.f.m.c. GmbH. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Author: Philipp Maier <pmaier@sysmocom.de> / sysmocom - s.f.m.c. GmbH
 *
 * See also: GSMA SGP.32, 5.9.4: Function (ES10b): AddInitialEim
 *
 * =====================================================================
 * v1.1/v1.2 migration notes for this file:
 * =====================================================================
 * UPDATE for v1.1: 5.9.4 — AddInitialEimResponse error set changed:
 *   - unsignedEimConfigDisallowed(2) was REPLACED by associatedEimAlreadyExists(2)
 *   - new commandError(7) added.
 *   The error table below must be updated after libasn regeneration.
 * DONE for v1.2: CR12010R00 / §5.9.4 — clarified behaviour when optional
 *   EimConfigurationData subfields are absent.  complete_eim_cfg() now assigns
 *   the same defaults a native IoT eUICC would (eimIdTypeProprietary,
 *   eimProprietary, first euiccCiPKIdListForSigning entry) and no longer
 *   demands the optional-per-spec eimFqdn.  The mandatory subfields moved to
 *   ipa_es10b_add_init_eim_validate(), which runs for both eUICC flavours.
 * UPDATE for v1.1: 2.11.1.1.1 — EimConfigurationData gains
 *   indirectProfileDownload [9] NULL OPTIONAL.  If the eIM advertises it in
 *   the initial configuration, the IPA must record it and honour it in the
 *   Indirect Profile Download path (proc_indirect_prfle_dwnld.c).
 * =====================================================================
 */

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <asn_application.h>
#include <constraints.h>
#include <BIT_STRING.h>
#include <onomondo/ipa/mem.h>
#include <onomondo/ipa/utils.h>
#include <onomondo/ipa/scard.h>
#include <onomondo/ipa/log.h>
#include "context.h"
#include "utils.h"
#include "euicc.h"
#include "es10x.h"
#include "es10b_get_euicc_info.h"
#include "es10b_add_init_eim.h"

static const struct num_str_map error_code_strings[] = {
	{ AddInitialEimResponse__addInitialEimError_insufficientMemory, "insufficientMemory" },
	/* UPDATE for v1.1: 5.9.4 — unsignedEimConfigDisallowed(2) was replaced by
	 * associatedEimAlreadyExists(2). */
	{ AddInitialEimResponse__addInitialEimError_associatedEimAlreadyExists, "associatedEimAlreadyExists" },
	{ AddInitialEimResponse__addInitialEimError_ciPKUnknown, "ciPKUnknown" },
	{ AddInitialEimResponse__addInitialEimError_invalidAssociationToken, "invalidAssociationToken" },
	{ AddInitialEimResponse__addInitialEimError_counterValueOutOfRange, "counterValueOutOfRange" },
	/* UPDATE for v1.1: 5.9.4 — new commandError(7). */
	{ AddInitialEimResponse__addInitialEimError_commandError, "commandError" },
	{ AddInitialEimResponse__addInitialEimError_undefinedError, "undefinedError" },
	{ 0, NULL }
};

/* ---------------------------------------------------------------------------
 * Input validation, see also SGP.32, section 5.9.4
 *
 * Section 5.9.4 requires eimId, counterValue and either eimPublicKey or
 * eimCertificate to be present in every entry of the eimConfigurationDataList,
 * and it notes: "It is IPA's responsibility to correctly formulate each entry,
 * including the uniqueness of eimId, and the eUICC is not mandated to check the
 * validity." A real eUICC is therefore allowed to store a malformed entry
 * without complaining, which is why these checks run once for both eUICC
 * flavours (see ipa_es10b_add_init_eim() at the bottom of this file) rather
 * than being repeated in the emulation.
 * ------------------------------------------------------------------------- */

/*! Validate a single entry of the eimConfigurationDataList.
 *  \param[in] eim_cfg entry to check.
 *  \param[in] idx position of the entry in the list, for logging only.
 *  \returns 0 when the entry is acceptable, an AddInitialEimResponse error code otherwise. */
static long validate_eim_cfg(const struct EimConfigurationData *eim_cfg, int idx)
{
	char errbuf[128] = { 0 };
	size_t errlen = sizeof(errbuf);

	/* eimId is mandatory in the ASN.1 module itself, so the decoder guarantees that it is present, but its
	 * SIZE(1..128) constraint is not: ber_decode() does not apply constraints. Checking the whole entry
	 * rather than that one field also covers the sizes and value ranges of everything nested inside it. */
	if (asn_check_constraints(&asn_DEF_EimConfigurationData, eim_cfg, errbuf, &errlen) != 0) {
		IPA_LOGP_ES10X("AddInitialEim", LERROR,
			       "eimConfigurationData #%d violates the ASN.1 constraints of the specification: %s\n",
			       idx, errbuf);
		return AddInitialEimResponse__addInitialEimError_commandError;
	}

	/* "The following sub-fields of EimConfigurationData SHALL be present in each entry of the
	 * eimConfigurationDataList: eimId; counterValue; and either eimPublicKey or eimCertificate." */
	if (!eim_cfg->counterValue) {
		IPA_LOGP_ES10X("AddInitialEim", LERROR,
			       "counterValue is missing from eimConfigurationData #%d!\n", idx);
		return AddInitialEimResponse__addInitialEimError_commandError;
	}

	/* eimPublicKeyData holds the CHOICE of eimPublicKey and eimCertificate. Note that this is not the same
	 * field as trustedPublicKeyDataTls, which carries the (D)TLS trust anchor and is optional. */
	if (!eim_cfg->eimPublicKeyData) {
		IPA_LOGP_ES10X("AddInitialEim", LERROR,
			       "eimConfigurationData #%d has neither eimPublicKey nor eimCertificate, so eUICC "
			       "Package signatures from this eIM could never be verified!\n", idx);
		return AddInitialEimResponse__addInitialEimError_commandError;
	}

	return 0;
}

/*! Validate a complete AddInitialEimRequest against the mandatory content of SGP.32, section 5.9.4.
 *  \param[in] req request to check.
 *  \returns 0 when the request is acceptable, an AddInitialEimResponse error code otherwise. */
long ipa_es10b_add_init_eim_validate(const struct AddInitialEimRequest *req)
{
	int i, k;

	if (req->eimConfigurationDataList.list.count < 1) {
		IPA_LOGP_ES10X("AddInitialEim", LERROR, "eimConfigurationDataList is empty!\n");
		return AddInitialEimResponse__addInitialEimError_commandError;
	}

	for (i = 0; i < req->eimConfigurationDataList.list.count; i++) {
		long rc = validate_eim_cfg(req->eimConfigurationDataList.list.array[i], i);
		if (rc)
			return rc;

		/* "It is IPA's responsibility to correctly formulate each entry, including the uniqueness of
		 * eimId". Each eimId selects one Associated eIM, so a duplicate would make the configuration
		 * ambiguous for every lookup that follows. */
		for (k = 0; k < i; k++) {
			if (IPA_ASN_STR_CMP(&req->eimConfigurationDataList.list.array[i]->eimId,
					    &req->eimConfigurationDataList.list.array[k]->eimId)) {
				IPA_LOGP_ES10X("AddInitialEim", LERROR,
					       "eimConfigurationData #%d and #%d share the same eimId!\n", k, i);
				return AddInitialEimResponse__addInitialEimError_commandError;
			}
		}
	}

	return 0;
}

/*! Check that no association token is presented as an already resolved value.
 *
 *  SGP.32, section 5.9.4: "If requested for an Associated eIM, calculate an associationToken. If
 *  associationToken is not set to -1 the eUICC SHALL return an error code invalidAssociationToken."
 *  This rule only applies when the IPA formulates a genuine AddInitialEim, so it is checked at the
 *  provisioning entry point (see ipa_add_init_eim_cfg()) instead of inside ipa_es10b_add_init_eim():
 *  the IoT eUICC emulation re-uses that function to rewrite its stored configuration for the addEim,
 *  deleteEim and updateEim eCOs, where the tokens have long been resolved to real values.
 *
 *  \param[in] req request to check.
 *  \returns 0 when the request is acceptable, an AddInitialEimResponse error code otherwise. */
long ipa_es10b_add_init_eim_check_assoc_tokens(const struct AddInitialEimRequest *req)
{
	int i;

	for (i = 0; i < req->eimConfigurationDataList.list.count; i++) {
		const long *token = req->eimConfigurationDataList.list.array[i]->associationToken;

		if (token && *token != -1) {
			IPA_LOGP_ES10X("AddInitialEim", LERROR,
				       "eimConfigurationData #%d presents associationToken %ld, but an initial "
				       "configuration may only request one by setting it to -1!\n", i, *token);
			return AddInitialEimResponse__addInitialEimError_invalidAssociationToken;
		}
	}

	return 0;
}

static int dec_add_init_eim_res(struct ipa_es10b_add_init_eim_res *res, const struct ipa_buf *es10b_res)
{
	struct AddInitialEimResponse *asn = NULL;

	asn = ipa_es10x_res_dec(&asn_DEF_AddInitialEimResponse, es10b_res, "AddInitialEim");
	if (!asn)
		return -EINVAL;

	switch (asn->present) {
	case AddInitialEimResponse_PR_addInitialEimOk:
		/* When we see this list, we can be sure that the configuration was accepted. */
		break;
	case AddInitialEimResponse_PR_addInitialEimError:
		res->add_init_eim_err = asn->choice.addInitialEimError;
		IPA_LOGP_ES10X("AddInitialEim", LERROR, "function failed with error code %ld=%s!\n",
			       res->add_init_eim_err, ipa_str_from_num(error_code_strings, res->add_init_eim_err,
								       "(unknown)"));
		break;
	default:
		IPA_LOGP_ES10X("AddInitialEim", LERROR, "unexpected response content!\n");
		res->add_init_eim_err = -1;
	}

	res->res = asn;
	return 0;
}

static struct ipa_es10b_add_init_eim_res *add_init_eim(struct ipa_context *ctx,
						       const struct ipa_es10b_add_init_eim_req *req)
{
	struct ipa_buf *es10b_req = NULL;
	struct ipa_buf *es10b_res = NULL;
	struct ipa_es10b_add_init_eim_res *res = IPA_ALLOC_ZERO(struct ipa_es10b_add_init_eim_res);
	int rc;

	es10b_req = ipa_es10x_req_enc(&asn_DEF_AddInitialEimRequest, &req->req, "AddInitialEim");
	if (!es10b_req) {
		IPA_LOGP_ES10X("AddInitialEim", LERROR, "unable to encode ES10b request\n");
		goto error;
	}

	es10b_res = ipa_euicc_transceive_es10x(ctx, es10b_req);
	if (!es10b_res) {
		IPA_LOGP_ES10X("AddInitialEim", LERROR, "no ES10b response\n");
		goto error;
	}

	rc = dec_add_init_eim_res(res, es10b_res);
	if (rc < 0)
		goto error;

	IPA_FREE(es10b_req);
	IPA_FREE(es10b_res);
	return res;
error:
	IPA_FREE(es10b_req);
	IPA_FREE(es10b_res);
	ipa_es10b_add_init_eim_res_free(res);
	return NULL;
}

/*! Largest counterValue an eUICC must be able to handle, see also SGP.32, section 2.11.1.1. A real eUICC may
 *  support more, but it may not support less, so the emulation uses the mandated minimum as its ceiling. */
#define IPA_EIM_COUNTER_VALUE_MAX 8388607

/* Bit number of eimProprietary in EimSupportedProtocol, see also SGP.32, section 4.2 */
#define IPA_EIM_SUPPORTED_PROTOCOL_PROPRIETARY 4

/* Allocate an EimSupportedProtocol BIT STRING with only the eimProprietary bit set. */
static BIT_STRING_t *make_default_supported_protocol(void)
{
	BIT_STRING_t *bs = IPA_ALLOC_ZERO(BIT_STRING_t);

	assert(bs);
	bs->buf = IPA_ALLOC_N(1);
	assert(bs->buf);
	/* Named bits are counted from the most significant bit of the first octet. */
	bs->buf[0] = 0x80 >> IPA_EIM_SUPPORTED_PROTOCOL_PROPRIETARY;
	bs->size = 1;
	bs->bits_unused = 7 - IPA_EIM_SUPPORTED_PROTOCOL_PROPRIETARY;

	return bs;
}

/* This function is only relevant in case the IoT eUICC emulation is enabled. It fills in the values that a native
 * IoT eUICC would assign itself when the IPA leaves an optional sub-field out (see also SGP.32, section 5.9.4).
 * The mandatory sub-fields are not checked here; ipa_es10b_add_init_eim_validate() has already done that for both eUICC
 * flavours by the time this runs.
 *
 * ci_pk_id_default may be NULL when the underlying eUICC could not be asked for its euiccCiPKIdListForSigning; in
 * that case euiccCiPKId is left absent rather than being filled with a guess. */
int complete_eim_cfg(struct ipa_context *ctx, struct EimConfigurationData *eim_cfg,
		     const SubjectKeyIdentifier_t *ci_pk_id_default)
{
	/* "Check if counterValue exceeds the maximum value supported by the eUICC. If so, the eUICC SHALL
	 * return the error code counterValueOutOfRange." */
	if (*eim_cfg->counterValue < 0 || *eim_cfg->counterValue > IPA_EIM_COUNTER_VALUE_MAX) {
		IPA_LOGP_ES10X("AddInitialEim", LERROR,
			       "counterValue %ld is out of the range supported by this eUICC (0..%d)!\n",
			       *eim_cfg->counterValue, IPA_EIM_COUNTER_VALUE_MAX);
		return -1;
	}

	/* "If the eimIdType is not provided, the eUICC SHALL assign the value eimIdTypeProprietary before
	 * storing the eIM Configuration Data." */
	if (!eim_cfg->eimIdType) {
		eim_cfg->eimIdType = IPA_ALLOC(EimIdType_t);
		assert(eim_cfg->eimIdType);
		*eim_cfg->eimIdType = EimIdType_eimIdTypeProprietary;
		IPA_LOGP_ES10X("AddInitialEim", LDEBUG,
			       "eimIdType not provided, assigning eimIdTypeProprietary.\n");
	}

	/* "The eimSupportedProtocol is optional for the IPA to provide [...]. If not provided, the eUICC SHALL
	 * assign the value where only the eimProprietary bit is set". */
	if (!eim_cfg->eimSupportedProtocol) {
		eim_cfg->eimSupportedProtocol = make_default_supported_protocol();
		IPA_LOGP_ES10X("AddInitialEim", LDEBUG,
			       "eimSupportedProtocol not provided, assigning eimProprietary.\n");
	}

	/* "The euiccCiPKId is optional for the IPA to provide [...]. If not provided, the eUICC SHALL assign the
	 * value of first entry of euiccCiPKIdListForSigning in eUICCInfo2". */
	if (!eim_cfg->euiccCiPKId && ci_pk_id_default) {
		eim_cfg->euiccCiPKId = OCTET_STRING_new_fromBuf(&asn_DEF_SubjectKeyIdentifier,
								(const char *)ci_pk_id_default->buf,
								(int)ci_pk_id_default->size);
		assert(eim_cfg->euiccCiPKId);
		IPA_LOGP_ES10X("AddInitialEim", LDEBUG,
			       "euiccCiPKId not provided, assigning the first entry of "
			       "euiccCiPKIdListForSigning.\n");
	}

	/* Calculate a new associationToken if requested */
	if (eim_cfg->associationToken && *eim_cfg->associationToken == -1) {
		ctx->nvstate.iot_euicc_emu.association_token_counter++;
		*eim_cfg->associationToken = ctx->nvstate.iot_euicc_emu.association_token_counter;
	}

	return 0;
}

/* Ask the underlying eUICC for the first entry of euiccCiPKIdListForSigning, which is what a native IoT eUICC
 * would fall back to when the IPA leaves euiccCiPKId out. Returns NULL (and logs) when the eUICC cannot be asked;
 * the caller then leaves the field absent rather than inventing a value. The result borrows from euicc_info, which
 * the caller must keep alive for as long as it is used. */
static const SubjectKeyIdentifier_t *default_ci_pk_id(struct ipa_es10b_euicc_info *euicc_info)
{
	if (!euicc_info || !euicc_info->sgp32_euicc_info_2)
		return NULL;

	if (euicc_info->sgp32_euicc_info_2->euiccCiPKIdListForSigning.list.count < 1)
		return NULL;

	return euicc_info->sgp32_euicc_info_2->euiccCiPKIdListForSigning.list.array[0];
}

struct AddInitialEimRequest *complete_eim_cfg_list(struct ipa_context *ctx, const struct AddInitialEimRequest *req)
{
	struct AddInitialEimRequest *req_dup;
	struct ipa_es10b_euicc_info *euicc_info;
	const SubjectKeyIdentifier_t *ci_pk_id;
	int i;
	int rc;

	req_dup = ipa_asn1c_dup(&asn_DEF_AddInitialEimRequest, req);

	/* Query the eUICC once for the whole list instead of once per entry. */
	euicc_info = ipa_es10b_get_euicc_info(ctx, true);
	ci_pk_id = default_ci_pk_id(euicc_info);
	if (!ci_pk_id)
		IPA_LOGP_ES10X("AddInitialEim", LINFO,
			       "cannot read euiccCiPKIdListForSigning from the eUICC, any missing euiccCiPKId "
			       "will be left absent.\n");

	for (i = 0; i < req_dup->eimConfigurationDataList.list.count; i++) {
		rc = complete_eim_cfg(ctx, req_dup->eimConfigurationDataList.list.array[i], ci_pk_id);
		if (rc < 0)
			goto error;
	}

	ipa_es10b_get_euicc_info_free(euicc_info);
	return req_dup;
error:
	ipa_es10b_get_euicc_info_free(euicc_info);
	ASN_STRUCT_FREE(asn_DEF_AddInitialEimRequest, req_dup);
	return NULL;
}

struct AddInitialEimResponse *generate_add_init_eim_response(struct ipa_context *ctx,
							     const struct AddInitialEimRequest *req)
{
	struct AddInitialEimResponse *res = IPA_ALLOC_ZERO(struct AddInitialEimResponse);
	struct AddInitialEimResponse__addInitialEimOk__Member *add_init_eim_item;
	unsigned int i;

	assert(res);
	res->present = AddInitialEimResponse_PR_addInitialEimOk;
	for (i = 0; i < req->eimConfigurationDataList.list.count; i++) {
		add_init_eim_item = IPA_ALLOC_ZERO(struct AddInitialEimResponse__addInitialEimOk__Member);
		assert(add_init_eim_item);
		if (req->eimConfigurationDataList.list.array[i]->associationToken) {
			add_init_eim_item->present = AddInitialEimResponse__addInitialEimOk__Member_PR_associationToken;
			add_init_eim_item->choice.associationToken =
			    *req->eimConfigurationDataList.list.array[i]->associationToken;
		} else {
			add_init_eim_item->present = AddInitialEimResponse__addInitialEimOk__Member_PR_addOk;
			add_init_eim_item->choice.addOk = 0;
		}
		ASN_SEQUENCE_ADD(&res->choice.addInitialEimOk.list, add_init_eim_item);
	}

	return res;
}

struct AddInitialEimResponse *generate_add_init_eim_response_err(long error_code)
{
	struct AddInitialEimResponse *res = IPA_ALLOC_ZERO(struct AddInitialEimResponse);

	assert(res);
	res->present = AddInitialEimResponse_PR_addInitialEimError;
	res->choice.addInitialEimError = error_code;
	return res;
}

static struct ipa_es10b_add_init_eim_res *add_init_eim_iot_emu(struct ipa_context *ctx,
							       const struct ipa_es10b_add_init_eim_req *req)
{
	struct ipa_buf *eim_cfg_new = NULL;
	struct AddInitialEimRequest *req_cfg_new_decoded = NULL;
	struct ipa_es10b_add_init_eim_res *res = IPA_ALLOC_ZERO(struct ipa_es10b_add_init_eim_res);

	IPA_LOGP_ES10X("AddInitialEim", LINFO,
		       "IoT eUICC emulation active, pretending to query eUICC to set eIM configuration...\n");

	req_cfg_new_decoded = complete_eim_cfg_list(ctx, &req->req);
	if (!req_cfg_new_decoded) {
		IPA_LOGP_ES10X("AddInitialEim", LERROR, "unable to complete ES10b request\n");
		goto error;
	}
	eim_cfg_new = ipa_es10x_req_enc(&asn_DEF_AddInitialEimRequest, req_cfg_new_decoded, "AddInitialEim");
	if (!eim_cfg_new) {
		IPA_LOGP_ES10X("AddInitialEim", LERROR, "unable to encode ES10b request\n");
		goto error;
	}

	/* AddInitialEimRequest and GetEimConfigurationDataResponse are identical. This means we can cast
	 * AddInitialEimRequest encoded ASN.1 data to GetEimConfigurationDataResponse */
	eim_cfg_new->data[1] = 0x55;

	/* Replace the current eIM configuration with the new eIM configuration. If there is already an eIM
	 * configuration in place it will be deleted and replaced with the new eIM configuration. This
	 * behaviour contradicts the behaviour of a real IoT eUICC, which would reject any new eIM configuration
	 * in that case. However, since this is an emulation and there is no reasonable security around that
	 * eIM configuration anyway, we decided to allow unconditional overwriting an existing eIM configuration. */
	IPA_FREE(ctx->nvstate.iot_euicc_emu.eim_cfg_ber);
	ctx->nvstate.iot_euicc_emu.eim_cfg_ber = eim_cfg_new;
	eim_cfg_new = NULL;	/* Ownership is now at ctx->nvstate.iot_euicc_emu.eim_cfg_ber */
	IPA_LOGP_ES10X("AddInitialEim", LINFO, "done, eIM configuration stored in memory.\n");

	res->res = generate_add_init_eim_response(ctx, req_cfg_new_decoded);
	IPA_FREE(eim_cfg_new);
	ASN_STRUCT_FREE(asn_DEF_AddInitialEimRequest, req_cfg_new_decoded);
	return res;
error:
	res->res = generate_add_init_eim_response_err(AddInitialEimResponse__addInitialEimError_undefinedError);
	res->add_init_eim_err = res->res->choice.addInitialEimError;
	IPA_FREE(eim_cfg_new);
	ASN_STRUCT_FREE(asn_DEF_AddInitialEimRequest, req_cfg_new_decoded);
	return res;
}

/*! Function (ES10b): AddInitialEim.
 *  \param[inout] ctx pointer to ipa_context.
 *  \param[in] req pointer to struct that holds the function parameters.
 *  \returns pointer newly allocated struct with function result, NULL on error. */
struct ipa_es10b_add_init_eim_res *ipa_es10b_add_init_eim(struct ipa_context *ctx,
							  const struct ipa_es10b_add_init_eim_req *req)
{
	long err;

	/* The eUICC "is not mandated to check the validity" of what it is given (SGP.32, section 5.9.4), so a
	 * malformed entry would be stored silently by a real eUICC and go on to break every later lookup. The
	 * check therefore sits in front of the branch, where it covers both eUICC flavours exactly once. */
	err = ipa_es10b_add_init_eim_validate(&req->req);
	if (err) {
		struct ipa_es10b_add_init_eim_res *res = IPA_ALLOC_ZERO(struct ipa_es10b_add_init_eim_res);

		assert(res);
		res->res = generate_add_init_eim_response_err(err);
		res->add_init_eim_err = err;
		return res;
	}

	if (ctx->cfg->iot_euicc_emu_enabled)
		return add_init_eim_iot_emu(ctx, req);
	else
		return add_init_eim(ctx, req);
}

/*! Free results of function (ES10b): AddInitialEim.
 *  \param[in] res pointer to function result. */
void ipa_es10b_add_init_eim_res_free(struct ipa_es10b_add_init_eim_res *res)
{
	IPA_ES10X_RES_FREE(asn_DEF_AddInitialEimResponse, res);
}
