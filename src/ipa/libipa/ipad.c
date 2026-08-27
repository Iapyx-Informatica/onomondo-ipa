/*
 * Copyright (c) 2025 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Author: Philipp Maier <pmaier@sysmocom.de> / sysmocom - s.f.m.c. GmbH
 */

#include <stdio.h>
#include <assert.h>
#include <stddef.h>
#include <string.h>
#include <onomondo/ipa/mem.h>
#include <onomondo/ipa/http.h>
#include <onomondo/ipa/scard.h>
#include <onomondo/ipa/log.h>
#include <onomondo/ipa/ipad.h>
#include <onomondo/ipa/utils.h>
#include "utils.h"
#include "context.h"
#include "euicc.h"
#include "esipa.h"
#include "es10c_get_prfle_info.h"
#include "es10c_get_eid.h"
#include "proc_eim_pkg_retr.h"
#include "es10b_get_eim_cfg_data.h"
#include "es10b_add_init_eim.h"
#include "es10b_get_euicc_info.h"
#include "ipae_activation.h"
#include "esipa_get_eim_pkg.h"
#include "es10b_cfg_immediate_enable.h"
#include "es10b_euicc_mem_rst.h"
#include "es10b_load_euicc_pkg.h"
#include "es10b_immediate_enable.h"
#include "es10b_execute_fallback.h"
#include "es10b_return_from_fallback.h"
#include "es10b_enable_emergency_profile.h"
#include "es10b_disable_emergency_profile.h"
#include "es10b_get_connectivity_params.h"
#include "es10b_set_default_dp_addr.h"
#include "proc_euicc_pkg_dwnld_exec.h"
#include "proc_notif_delivery.h"

/* Counters to monitor heap memory usage, see also: onomondo/ipa/mem.h */
#ifdef MEM_EMIT_DEBUG
long int ___mem_counter = 0;
long int ___mem_peak = 0;
#endif

static void nvstate_free_contents(struct ipa_nvstate *nvstate)
{
	/* free dynamically allocated struct members (append code for new members here) */
	IPA_FREE(nvstate->iot_euicc_emu.eim_cfg_ber);
	IPA_FREE(nvstate->iot_euicc_emu.immediate_enable.smdp_oid);
	IPA_FREE(nvstate->iot_euicc_emu.immediate_enable.smdp_address);
}

static void nvstate_reset(struct ipa_nvstate *nvstate)
{
	nvstate_free_contents(nvstate);
	memset(nvstate, 0, sizeof(*nvstate));
	nvstate->version = IPA_NVSTATE_VERSION;
	/* Not the zero value: IPA_STATE_CHANGE_OTHER_EIM is 0, and a fresh state has nothing to report. */
	nvstate->state_change_cause = IPA_STATE_CHANGE_NONE;
}

static struct ipa_buf *nvstate_serialize_ipa_buf(struct ipa_buf *nvstate_bin, struct ipa_buf *buf)
{
	struct ipa_buf *buf_ser = buf;

	/* To maintain the structure and consistency of the generated serialization result we must serialize something.
	 * This means that in case we receive a null pointer as buf, we must serialize a dummy buffer */
	if (!buf)
		buf_ser = ipa_buf_alloc(0);
	nvstate_bin = ipa_buf_realloc(nvstate_bin, nvstate_bin->len + buf_ser->data_len + sizeof(*buf_ser));
	assert(nvstate_bin);
	memcpy(nvstate_bin->data + nvstate_bin->len, buf_ser, buf_ser->data_len + sizeof(*buf_ser));
	nvstate_bin->len += buf_ser->data_len + sizeof(*buf_ser);

	if (!buf)
		ipa_buf_free(buf_ser);
	return nvstate_bin;
}

static struct ipa_buf *nvstate_serialize(struct ipa_nvstate *nvstate)
{
	struct ipa_buf *nvstate_bin;

	/* serialize statically allocated struct members */
	nvstate_bin = ipa_buf_alloc_data(sizeof(*nvstate), (uint8_t *) nvstate);
	assert(nvstate_bin);

	/* serialize dynamically allocated struct members (append code for new members here) */
	nvstate_bin = nvstate_serialize_ipa_buf(nvstate_bin, nvstate->iot_euicc_emu.eim_cfg_ber);
	nvstate_bin = nvstate_serialize_ipa_buf(nvstate_bin, nvstate->iot_euicc_emu.immediate_enable.smdp_oid);
	nvstate_bin = nvstate_serialize_ipa_buf(nvstate_bin, nvstate->iot_euicc_emu.immediate_enable.smdp_address);
	return nvstate_bin;
}

/*! Deserialize one dynamically allocated member from the nvstate image.
 *  \param[inout] nvstate_data cursor into the image, advanced past the member that was read.
 *  \param[inout] nvstate_data_len bytes left at the cursor, reduced by the same amount.
 *  \param[out] malformed set when the image could not be read; left alone otherwise.
 *  \returns the member, or NULL when it was stored absent or when the image is malformed.
 *
 *  NULL alone does not say which of the two happened, because a member that was never set is stored
 *  as a placeholder and legitimately reads back as NULL. The caller has to consult malformed to tell
 *  an absent member from an image it should not be loading at all. */
static struct ipa_buf *nvstate_deserialize_ipa_buf(uint8_t ** nvstate_data, size_t *nvstate_data_len, bool *malformed)
{
	struct ipa_buf *buf;

	buf = ipa_buf_deserialize(*nvstate_data, *nvstate_data_len);
	if (!buf) {
		/* The image ended early or its length fields contradict each other. Report it and leave
		 * nothing behind for a further call to walk into. */
		*malformed = true;
		*nvstate_data_len = 0;
		return NULL;
	}

	/* ipa_buf_deserialize() checked this fits, so neither the advance nor the subtraction runs off
	 * the end of the image. */
	*nvstate_data += buf->data_len + sizeof(*buf);
	*nvstate_data_len -= (buf->data_len + sizeof(*buf));

	/* (see comment in nvstate_serialize_ipa_buf), check if we have de-serialized a dummy buffer (an ipa_buf with
	 * len and data_len set to 0). In case we hit a dummy buffer, free it and return NULL. */
	if (buf->len == 0 && buf->data_len == 0) {
		ipa_buf_free(buf);
		return NULL;
	}

	return buf;
}

static void nvstate_deserialize(struct ipa_nvstate *nvstate, struct ipa_buf *nvstate_bin)
{
	uint8_t *nvstate_data;
	size_t nvstate_data_len;
	uint32_t version;
	bool malformed = false;

	/* nothing to deserialize */
	if (!nvstate_bin) {
		nvstate_reset(nvstate);
		return;
	}

	/* A stored image written by an older build can be shorter than the current struct -- growing a
	 * statically allocated member is enough. Check the length before the copy, because the version
	 * field that would reject it lives inside the bytes we are about to read. */
	if (nvstate_bin->len < sizeof(*nvstate)) {
		IPA_LOGP(SIPA, LERROR,
			 "cannot deserialize non volatile state, it is %zu bytes but at least %zu are needed\n",
			 nvstate_bin->len, sizeof(*nvstate));
		nvstate_reset(nvstate);
		return;
	}

	/* Read the version on its own, before the wholesale copy below.  The struct holds pointers to
	 * dynamically allocated members, and nvstate_serialize() writes it out as it stands, so those
	 * pointer slots in the image hold the writing process's heap addresses.  Copying the struct in
	 * first and rejecting it afterwards would leave those addresses in place for the
	 * nvstate_reset() on the rejection path to free -- that is a free() of a value taken from the
	 * file.  Same reasoning as the length check above: what decides whether the image may be
	 * trusted has to be read before the image is acted on. */
	memcpy(&version, nvstate_bin->data + offsetof(struct ipa_nvstate, version), sizeof(version));
	if (version != IPA_NVSTATE_VERSION) {
		IPA_LOGP(SIPA, LERROR,
			 "cannot deserialize non volatile state with mismatching version number %u (expected version: %u)\n",
			 version, IPA_NVSTATE_VERSION);
		nvstate_reset(nvstate);
		return;
	}

	/* deserialize statically allocated struct members */
	memcpy((uint8_t *) nvstate, nvstate_bin->data, sizeof(*nvstate));
	nvstate_data = nvstate_bin->data + sizeof(*nvstate);
	nvstate_data_len = nvstate_bin->len - sizeof(*nvstate);

	/* The copy above also brought the stale pointers in.  Clear them so that the struct never holds
	 * a pointer that came from the file: the assignments below overwrite all three, but an early
	 * return added between here and there must not resurrect the bug this replaced. */
	nvstate->iot_euicc_emu.eim_cfg_ber = NULL;
	nvstate->iot_euicc_emu.immediate_enable.smdp_oid = NULL;
	nvstate->iot_euicc_emu.immediate_enable.smdp_address = NULL;

	/* deserialize dynamically allocated struct members (append code for new members here) */
	nvstate->iot_euicc_emu.eim_cfg_ber =
	    nvstate_deserialize_ipa_buf(&nvstate_data, &nvstate_data_len, &malformed);
	nvstate->iot_euicc_emu.immediate_enable.smdp_oid =
	    nvstate_deserialize_ipa_buf(&nvstate_data, &nvstate_data_len, &malformed);
	nvstate->iot_euicc_emu.immediate_enable.smdp_address =
	    nvstate_deserialize_ipa_buf(&nvstate_data, &nvstate_data_len, &malformed);

	/* A truncated or inconsistent image means the members that did come through cannot be trusted
	 * either -- there is no way to tell a member that was stored absent from one whose bytes went
	 * missing. Start over rather than run on half a state. */
	if (malformed) {
		IPA_LOGP(SIPA, LERROR,
			 "cannot deserialize non volatile state, the dynamically allocated members do not fit the stored image\n");
		nvstate_reset(nvstate);
	}
}

/*! Read eIM configuration from eUICC and pick a suitable eIM.
 *  \param[inout] ctx pointer to ipa_context.
 *  \returns 0 success, -EINVAL on failure. */
int eim_init(struct ipa_context *ctx)
{
	struct ipa_es10b_eim_cfg_data *eim_cfg_data = NULL;
	struct EimConfigurationData *eim_cfg_data_item = NULL;
	long i;

	/* Only the preferred eIM is wanted; when none is configured this asks for the whole list and the
	 * filter below picks the first entry. */
	eim_cfg_data = ipa_es10b_get_eim_cfg_data(ctx, ctx->cfg->preferred_eim_id);
	if (!eim_cfg_data) {
		IPA_LOGP(SIPA, LERROR, "cannot read EimConfigurationData from eUICC\n");
		goto error;
	}

	/* In case no preferred_eim_id is set, the first eIM configuration item will be pulled from the list */
	eim_cfg_data_item = ipa_es10b_get_eim_cfg_data_filter(eim_cfg_data, ctx->cfg->preferred_eim_id);
	if (!eim_cfg_data_item) {
		IPA_LOGP(SIPA, LERROR, "no suitable EimConfigurationData item present.\n");
		goto error;
	}

	ctx->eim_id = IPA_STR_FROM_ASN(&eim_cfg_data_item->eimId);
	if (!ctx->eim_id)
		goto error;

	/* eimIdType is OPTIONAL on the wire, so it must be checked before it is dereferenced: a spec compliant
	 * eUICC assigns eimIdTypeProprietary when the IPA leaves it out, but nothing guarantees that the value
	 * we read back actually carries it. */
	if (eim_cfg_data_item->eimFqdn)
		ctx->eim_fqdn = IPA_STR_FROM_ASN(eim_cfg_data_item->eimFqdn);
	else if (eim_cfg_data_item->eimIdType && *eim_cfg_data_item->eimIdType == EimIdType_eimIdTypeFqdn)
		ctx->eim_fqdn = IPA_STR_FROM_ASN(&eim_cfg_data_item->eimId);
	else {
		IPA_LOGP(SIPA, LERROR,
			 "no eimFqdn in the eIM configuration and the eimId is not an FQDN, cannot reach the eIM!\n");
		goto error;
	}

	/* Install the eIM's TLS CA certificate into the HTTP context so that
	 * HTTPS server certificate verification uses the certificate stored on
	 * the eUICC rather than a file-based CA bundle.
	 *
	 * eim_cfg_data->eim_cfg_data_list holds the DER-encoded certificate
	 * bytes (pre-computed by ipa_es10b_get_eim_cfg_data from the ASN.1
	 * trustedCertificateTls CHOICE branch).  We search the list for the
	 * item whose eim_id matches the one we just selected. */
	for (i = 0; i < eim_cfg_data->eim_cfg_data_list_count; i++) {
		struct ipa_eim_cfg_data *item = eim_cfg_data->eim_cfg_data_list[i];
		if (!item->eim_id || strcmp(item->eim_id, ctx->eim_id) != 0)
			continue;
		if (item->trusted_public_key_data_tls.trusted_certificate_tls) {
			struct ipa_buf *ca_der =
			    item->trusted_public_key_data_tls.trusted_certificate_tls;
			if (ipa_http_set_ca_cert_der(ctx->http_ctx,
						     ca_der->data,
						     ca_der->len) < 0)
				IPA_LOGP(SIPA, LERROR,
					 "failed to install eIM TLS CA certificate; "
					 "HTTPS will fall back to cabundle if set\n");
		} else if (item->trusted_public_key_data_tls.trusted_eim_pk_tls) {
			struct ipa_buf *spki =
			    item->trusted_public_key_data_tls.trusted_eim_pk_tls;
			if (ipa_http_set_ca_pk_spki(ctx->http_ctx,
						    spki->data,
						    spki->len) < 0)
				IPA_LOGP(SIPA, LERROR,
					 "failed to install eIM TLS public key pin; "
					 "HTTPS will fall back to cabundle if set\n");
		} else {
			IPA_LOGP(SIPA, LDEBUG,
				 "no trustedPublicKeyDataTls in EimConfigurationData; "
				 "HTTPS server verification uses cabundle\n");
		}
		break;
	}

	ipa_es10b_get_eim_cfg_data_free(eim_cfg_data);
	return 0;
error:
	IPA_LOGP(SIPA, LERROR, "unable to retrieve EimConfigurationData\n");
	ipa_es10b_get_eim_cfg_data_free(eim_cfg_data);
	return -EINVAL;
}

/*! Create a new ipa_context.
 *  \param[in] cfg IPAd configuration.
 *  \returns ipa_context on success, NULL on failure. */
struct ipa_context *ipa_new_ctx(struct ipa_config *cfg, struct ipa_buf *nvstate)
{
	struct ipa_context *ctx;

	ctx = IPA_ALLOC_ZERO(struct ipa_context);
	assert(ctx);

	ctx->cfg = cfg;
	/* Not the zero value: IPA_MODE_IPAD is 0, and nothing has been established yet. The mode only
	 * settles once TERMINAL CAPABILITY has told the eUICC which IPA the device supports. */
	ctx->ipa_mode = IPA_MODE_UNKNOWN;
	nvstate_deserialize(&ctx->nvstate, nvstate);

	return ctx;
}

/*! Initialize IPAd and prepare links towards eIM and eUICC.
 *  \param[inout] ctx pointer to ipa_context.
 *  \returns 0 success, -EINVAL on failure. */
int ipa_init(struct ipa_context *ctx)
{
	int rc;

	/* Refuse rather than quietly ignore: a caller that asks for the emulation is telling us it has a consumer
	 * eUICC in the reader, and carrying on against it as if it were an IoT eUICC would fail later in ways that
	 * are much harder to read than this. */
#ifndef IPA_HAVE_IOT_EUICC_EMULATION
	if (ctx->cfg->iot_euicc_emu_enabled) {
		IPA_LOGP(SIPA, LERROR,
			 "IoT eUICC emulation was requested, but this build does not have it "
			 "(rebuild with -DIOT_EUICC_EMULATION=ON)\n");
		return -EINVAL;
	}
#endif

	/* Likewise for the wire binding: better to say so here than to have every ESipa call fail the same way. */
#ifndef IPA_HAVE_ESIPA_ASN1
	if (ctx->cfg->esipa_binding == IPA_ESIPA_BINDING_ASN1) {
		IPA_LOGP(SIPA, LERROR,
			 "the ASN.1 ESipa binding was selected, but this build does not have it "
			 "(set ipa_config.esipa_binding to IPA_ESIPA_BINDING_JSON, or rebuild with "
			 "-DESIPA_BINDING_ASN1=ON)\n");
		return -EINVAL;
	}
#endif
#ifndef IPA_HAVE_ESIPA_JSON
	if (ctx->cfg->esipa_binding == IPA_ESIPA_BINDING_JSON) {
		IPA_LOGP(SIPA, LERROR,
			 "the JSON ESipa binding was selected, but this build does not have it "
			 "(rebuild with -DESIPA_BINDING_JSON=ON)\n");
		return -EINVAL;
	}
#endif

	ctx->http_ctx = ipa_http_init(ctx->cfg->eim_cabundle, ctx->cfg->eim_disable_ssl_verif);
	if (!ctx->http_ctx)
		return -EINVAL;

	ctx->scard_ctx = ipa_scard_init(ctx->cfg->reader_num);
	if (!ctx->scard_ctx)
		return -EINVAL;

	rc = ipa_euicc_init_es10x(ctx);
	if (rc < 0)
		return -EINVAL;

	rc = ipa_es10c_get_eid(ctx, ctx->eid);
	if (rc < 0)
		return -EINVAL;

	return 0;
}

/*! setup initial eIM configuration on the eUICC (AddInitialEim).
 *  \param[inout] ctx pointer to ipa_context.
 *  \param[inout] cfg BER encoded eIM configuration (in the form of AddInitialEimRequest or GetEimConfigurationDataResponse).
 *  \returns 0 on success, negative on error. */
int ipa_add_init_eim_cfg(struct ipa_context *ctx, struct ipa_buf *cfg)
{
	asn_dec_rval_t rc;
	struct AddInitialEimRequest *eim_cfg_decoded = NULL;
	struct ipa_es10b_add_init_eim_req add_init_eim_req = { 0 };
	struct ipa_es10b_add_init_eim_res *add_init_eim_res = NULL;

	/* Validate the caller-supplied buffer before indexing data[0..1] below. */
	if (!cfg || cfg->len < 2) {
		IPA_LOGP(SIPA, LERROR, "initial eIM configuration is missing or too short\n");
		return -EINVAL;
	}

	/* AddInitialEimRequest and GetEimConfigurationDataResponse are identical. This means we can cast
	 * GetEimConfigurationDataResponse encoded ASN.1 data to AddInitialEimRequest */
	if (cfg->data[0] == 0xBF && cfg->data[1] == 0x55) {
		cfg->data[0] = 0xBF;
		cfg->data[1] = 0x57;
	}

	/* Decode AddInitialEimRequest */
	rc = ber_decode(0, &asn_DEF_AddInitialEimRequest, (void **)&eim_cfg_decoded, cfg->data, cfg->len);
	if (rc.code != RC_OK) {
		IPA_LOGP(SIPA, LERROR, "unable decode EimConfigurationData\n");
		ASN_STRUCT_FREE(asn_DEF_AddInitialEimRequest, eim_cfg_decoded);
		return -EINVAL;
	}

	/* An initial configuration may only *request* an association token, by setting it to -1 (SGP.32,
	 * section 5.9.4). The remaining checks are done by ipa_es10b_add_init_eim() itself, for both the real
	 * eUICC and the emulation. */
	if (ipa_es10b_add_init_eim_check_assoc_tokens(eim_cfg_decoded)) {
		IPA_LOGP(SIPA, LERROR, "refusing the initial eIM configuration\n");
		ASN_STRUCT_FREE(asn_DEF_AddInitialEimRequest, eim_cfg_decoded);
		return -EINVAL;
	}

	/* Call ES10b function AddInitialEim */
	add_init_eim_req.req = *eim_cfg_decoded;
	add_init_eim_res = ipa_es10b_add_init_eim(ctx, &add_init_eim_req);

	if (!add_init_eim_res || add_init_eim_res->add_init_eim_err) {
		IPA_LOGP(SIPA, LERROR, "the initial eIM configuration was not accepted\n");
		ipa_es10b_add_init_eim_res_free(add_init_eim_res);
		ASN_STRUCT_FREE(asn_DEF_AddInitialEimRequest, eim_cfg_decoded);
		return -EINVAL;
	}

	ipa_es10b_add_init_eim_res_free(add_init_eim_res);
	ASN_STRUCT_FREE(asn_DEF_AddInitialEimRequest, eim_cfg_decoded);
	return 0;
}

/*! reset memory of the eUICC (eUICCMemoryReset). See ipa_euicc_mem_rst() in ipad.h. */
int ipa_euicc_mem_rst(struct ipa_context *ctx, uint32_t options)
{
	struct ipa_es10b_euicc_mem_rst euicc_mem_rst = {
		.operatnl_profiles = !!(options & IPA_EUICC_MEM_RST_OPERATIONAL_PROFILES),
		.test_profiles = !!(options & IPA_EUICC_MEM_RST_FIELD_LOADED_TEST_PROFILES),
		.default_smdp_addr = !!(options & IPA_EUICC_MEM_RST_DEFAULT_SMDP_ADDR),
		.pre_loaded_test_profiles = !!(options & IPA_EUICC_MEM_RST_PRE_LOADED_TEST_PROFILES),
		.provisioning_profiles = !!(options & IPA_EUICC_MEM_RST_PROVISIONING_PROFILES),
		.eim_cfg_data = !!(options & IPA_EUICC_MEM_RST_EIM_CFG_DATA),
		.immediate_enable_cfg = !!(options & IPA_EUICC_MEM_RST_IMMEDIATE_ENABLE_CFG),
	};
	return ipa_es10b_euicc_mem_rst(ctx, &euicc_mem_rst);
}

/* ---------------------------------------------------------------------------
 * Direct ES10b triggers (see onomondo/ipad.h for the daemon-integration
 * contract).  These are thin, synchronous pass-throughs to the ES10b layer;
 * the host decides when to invoke them.
 * --------------------------------------------------------------------------- */

/*! Report what the eUICC supports.  See ipa_get_euicc_caps() in ipad.h. */
int ipa_get_euicc_caps(struct ipa_context *ctx, struct ipa_euicc_caps *caps)
{
	return ipa_es10b_get_euicc_caps(ctx, caps);
}

/*! Activate the eUICC's own IPAe.  See ipa_activate_ipae() in ipad.h. */
int ipa_activate_ipae(struct ipa_context *ctx)
{
	return ipa_ipae_activation(ctx);
}

/*! Record the last registered PLMN.  See ipa_set_rplmn() in ipad.h. */
int ipa_set_rplmn(struct ipa_context *ctx, const char *mcc, const char *mnc)
{
	return ipa_esipa_set_rplmn(ctx, mcc, mnc);
}

/*! ES10b ConfigureImmediateProfileEnabling.  See ipa_cfg_immediate_enable() in ipad.h. */
int ipa_cfg_immediate_enable(struct ipa_context *ctx, bool immediate_enable, const char *smdp_oid,
			     const char *smdp_address)
{
	return ipa_es10b_cfg_immediate_enable(ctx, immediate_enable, smdp_oid, smdp_address);
}

/*! ES10b ImmediateEnable.  See ipa_immediate_enable() in ipad.h. */
int ipa_immediate_enable(struct ipa_context *ctx, bool refresh_flag)
{
	return ipa_es10b_immediate_enable(ctx, refresh_flag);
}

/*! ES10b ExecuteFallbackMechanism.  See ipa_execute_fallback() in ipad.h. */
int ipa_execute_fallback(struct ipa_context *ctx, bool refresh_flag)
{
	return ipa_es10b_execute_fallback(ctx, refresh_flag);
}

/*! Which Profile is the Fallback Profile?  See ipa_get_fallback_profile() in ipad.h. */
int ipa_get_fallback_profile(struct ipa_context *ctx, uint8_t *iccid)
{
	struct ipa_es10c_get_prfle_info_res *res;
	const struct SGP32_ProfileInfo *prfle;
	int rc = -ENOENT;

	if (!ctx || !iccid)
		return -EINVAL;

	res = ipa_es10c_get_prfle_info(ctx, NULL);
	if (!res || res->prfle_info_list_err) {
		ipa_es10c_get_prfle_info_res_free(res);
		return -EIO;
	}

	/* The Profile Metadata is the eUICC's own answer, so it wins wherever it exists.  Only when the
	 * eUICC cannot hold the flag does the emulation's record stand in -- and then it is the only
	 * record there is, which is why the two can never disagree. */
	prfle = ipa_es10c_fallback_prfle(res);
	if (prfle && prfle->iccid && prfle->iccid->size == IPA_LEN_ICCID) {
		memcpy(iccid, prfle->iccid->buf, IPA_LEN_ICCID);
		rc = 0;
	} else if (IPA_EMU_FALLBACK_SET(ctx)) {
		memcpy(iccid, ctx->nvstate.iot_euicc_emu.fallback_iccid, IPA_LEN_ICCID);
		rc = 0;
	}

	ipa_es10c_get_prfle_info_res_free(res);
	return rc;
}

/*! ES10b ReturnFromFallback.  See ipa_return_from_fallback() in ipad.h. */
int ipa_return_from_fallback(struct ipa_context *ctx, bool refresh_flag)
{
	return ipa_es10b_return_from_fallback(ctx, refresh_flag);
}

/*! ES10b EnableEmergencyProfile.  See ipa_enable_emergency_profile() in ipad.h. */
int ipa_enable_emergency_profile(struct ipa_context *ctx, bool refresh_flag)
{
	return ipa_es10b_enable_emergency_profile(ctx, refresh_flag);
}

/*! ES10b DisableEmergencyProfile.  See ipa_disable_emergency_profile() in ipad.h. */
int ipa_disable_emergency_profile(struct ipa_context *ctx, bool refresh_flag)
{
	return ipa_es10b_disable_emergency_profile(ctx, refresh_flag);
}

/*! ES10b SetDefaultDpAddress.  See ipa_set_default_dp_addr() in ipad.h. */
int ipa_set_default_dp_addr(struct ipa_context *ctx, const char *default_dp_fqdn)
{
	return ipa_es10b_set_default_dp_addr(ctx, default_dp_fqdn);
}

/*! ES10b GetConnectivityParameters.  See ipa_get_connectivity_params() in ipad.h.
 *  Copies the (optional) httpParams out of the internal ipa_buf into a plain
 *  caller-owned buffer so the public struct stays free of internal types. */
struct ipa_connectivity_params *ipa_get_connectivity_params(struct ipa_context *ctx)
{
	struct ipa_es10b_connectivity_params *internal;
	struct ipa_connectivity_params *out;

	internal = ipa_es10b_get_connectivity_params(ctx);
	if (!internal)
		return NULL;

	out = IPA_ALLOC_ZERO(struct ipa_connectivity_params);
	if (internal->http_params && internal->http_params->len > 0) {
		out->http_params_len = internal->http_params->len;
		out->http_params = IPA_ALLOC_N(out->http_params_len);
		assert(out->http_params);
		memcpy(out->http_params, internal->http_params->data, out->http_params_len);
	}

	ipa_es10b_connectivity_params_free(internal);
	return out;
}

/*! Free the result of ipa_get_connectivity_params() (NULL-safe). */
void ipa_connectivity_params_free(struct ipa_connectivity_params *p)
{
	if (!p)
		return;
	IPA_FREE(p->http_params);
	IPA_FREE(p);
}

static int check_canaries(struct ipa_context *ctx)
{
	if (ctx->check_http)
		return IPA_POLL_CHECK_HTTP;
	if (ctx->check_scard)
		return IPA_POLL_CHECK_SCARD;
	return -EINVAL;
}

/*! poll the IPAd (may be called in regular intervals or on purpose).
 *  \param[inout] ctx pointer to ipa_context.
 *  \returns positive on success, negative on error (see also enum ipa_poll_rc). */
int ipa_poll(struct ipa_context *ctx)
{
	int rc;

	/* Reset canaries */
	ctx->check_scard = false;
	ctx->check_http = false;

	if (ctx->proc_eucc_pkg_dwnld_exec_res) {
		/* There is an eUICC package execution ongoing, which we have to finish first.
		 *
		 * Reaching this point means that the previous ipa_poll returned
		 * IPA_POLL_AGAIN_WHEN_ONLINE, which is only the case when the eUICC package (or a
		 * subsequent profile rollback) has changed the active profile. An eUICC in that
		 * state may refuse every further ES10b command with SW=6985 until it is reset, so
		 * the remaining steps of the procedure (ES10b.RetrieveNotificationsList and the
		 * removal of the delivered notifications) would fail and the EuiccPackageResult
		 * would never reach the eIM.
		 *
		 * The reset is done here, and not on the proactive REFRESH path in euicc.c, because
		 * not every eUICC asks for it: some raise a REFRESH with the "UICC Reset" qualifier,
		 * others require the reset without signalling anything at all. The condition used
		 * here comes from the package contents instead of from card behaviour, so it holds
		 * for both. Resetting an eUICC that has already reset itself is harmless. */
		rc = ipa_euicc_reset_es10x(ctx);
		if (rc < 0) {
			/* Without a usable ES10x link the procedure cannot be completed. The
			 * EuiccPackageResult stays pending as a notification on the eUICC and will be
			 * delivered by ipa_notif_delivery() once the link is working again. */
			IPA_LOGP(SIPA, LERROR,
				 "unable to reset the eUICC after a profile change, eUICC package execution aborted!\n");
			ipa_proc_eucc_pkg_dwnld_exec_res_free(ctx->proc_eucc_pkg_dwnld_exec_res);
			ctx->proc_eucc_pkg_dwnld_exec_res = NULL;
			return check_canaries(ctx);
		}

		rc = ipa_proc_eucc_pkg_dwnld_exec_onset(ctx, ctx->proc_eucc_pkg_dwnld_exec_res);
		if (rc < 0) {
			/* ipa_proc_eucc_pkg_dwnld_exec_onset indicates an error that can not be recovered from. */
			ipa_proc_eucc_pkg_dwnld_exec_res_free(ctx->proc_eucc_pkg_dwnld_exec_res);
			ctx->proc_eucc_pkg_dwnld_exec_res = NULL;
			return check_canaries(ctx);
		} else if (ctx->proc_eucc_pkg_dwnld_exec_res->call_onset == false) {
			/* ipa_proc_eucc_pkg_dwnld_exec_onset indicates that the procedure is done. */
			ipa_proc_eucc_pkg_dwnld_exec_res_free(ctx->proc_eucc_pkg_dwnld_exec_res);
			ctx->proc_eucc_pkg_dwnld_exec_res = NULL;
			return IPA_POLL_AGAIN;
		} else {
			/* There is an eUICC package execution ongoing which has done changes to the currently
			 * selected profile. the caller of ipa_poll must ensure that ipa_poll is called again
			 * once the IP connection has resettled */
			return IPA_POLL_AGAIN_WHEN_ONLINE;
		}
	} else {
		/* See if there are pending notification on the eUICC and deliver them first */
		ipa_notif_delivery(ctx);

		/* Normal operation, we poll the eIM for the next eIM package. */
		rc = ipa_proc_eim_pkg_retr(ctx);
		if (rc == -GetEimPackageResponse__eimPackageError_noEimPackageAvailable)
			/* When no more eIM packages are available it makes sense to relax the poll interval. */
			return IPA_POLL_AGAIN_LATER;
		else if (rc < 0)
			/* ipa_proc_eim_pkg_retr indicates an error that can not be recovered from. */
			return check_canaries(ctx);
		else {
			if (ctx->proc_eucc_pkg_dwnld_exec_res)
				/* There is an eUICC package execution ongoing which has done changes to the currently
				 * selected profile. the caller of ipa_poll must ensure that ipa_poll is called again
				 * once the IP connection has resettled */
				return IPA_POLL_AGAIN_WHEN_ONLINE;
			else
				/* Tell the caller to continue polling normally */
				return IPA_POLL_AGAIN;
		}
	}
}

/*! close connection towards the eIM.
 *  \param[inout] ctx pointer to ipa_context. */
void ipa_close(struct ipa_context *ctx)
{
	ipa_esipa_close(ctx);
}

/*! close links towards eIM and eUICC and free an ipa_context.
 *  \param[inout] ctx pointer to ipa_context. */
struct ipa_buf *ipa_free_ctx(struct ipa_context *ctx)
{
	struct ipa_buf *nvstate;

	if (!ctx)
		return NULL;

	nvstate = nvstate_serialize(&ctx->nvstate);

	IPA_FREE(ctx->iot_euicc_emu.rollback_iccid);
	ipa_buf_free(ctx->iot_euicc_emu.immediate_enable.smdp_oid);
	ipa_buf_free(ctx->iot_euicc_emu.immediate_enable.smdp_address);
	ipa_buf_free(ctx->iot_euicc_emu.immediate_enable.profile_aid);
	IPA_FREE(ctx->eim_id);
	IPA_FREE(ctx->eim_fqdn);
	ipa_proc_eucc_pkg_dwnld_exec_res_free(ctx->proc_eucc_pkg_dwnld_exec_res);
	IPA_FREE(ctx->euicc_caps.iot_version);

	if (ctx->scard_ctx)
		ipa_euicc_close_es10x(ctx);
	ipa_http_free(ctx->http_ctx);
	ipa_scard_free(ctx->scard_ctx);
	nvstate_free_contents(&ctx->nvstate);
	IPA_FREE(ctx);

	return nvstate;
}
