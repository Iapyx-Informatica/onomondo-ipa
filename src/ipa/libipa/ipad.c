/*
 * Copyright (c) 2025 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Author: Philipp Maier <pmaier@sysmocom.de> / sysmocom - s.f.m.c. GmbH
 */

#include <stdio.h>
#include <assert.h>
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
#include "es10c_get_eid.h"
#include "proc_eim_pkg_retr.h"
#include "es10b_get_eim_cfg_data.h"
#include "es10b_add_init_eim.h"
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
	IPA_FREE(nvstate->iot_euicc_emu.auto_enable.smdp_oid);
	IPA_FREE(nvstate->iot_euicc_emu.auto_enable.smdp_address);
}

static void nvstate_reset(struct ipa_nvstate *nvstate)
{
	nvstate_free_contents(nvstate);
	memset(nvstate, 0, sizeof(*nvstate));
	nvstate->version = IPA_NVSTATE_VERSION;
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
	nvstate_bin = nvstate_serialize_ipa_buf(nvstate_bin, nvstate->iot_euicc_emu.auto_enable.smdp_oid);
	nvstate_bin = nvstate_serialize_ipa_buf(nvstate_bin, nvstate->iot_euicc_emu.auto_enable.smdp_address);
	return nvstate_bin;
}

struct ipa_buf *nvstate_deserialize_ipa_buf(uint8_t ** nvstate_data, size_t *nvstate_data_len)
{
	struct ipa_buf *buf;

	buf = ipa_buf_deserialize(*nvstate_data, *nvstate_data_len);

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

	/* nothing to deserialize */
	if (!nvstate_bin) {
		nvstate_reset(nvstate);
		return;
	}

	/* deserialize statically allocated struct members and check version */
	memcpy((uint8_t *) nvstate, nvstate_bin->data, sizeof(*nvstate));
	nvstate_data = nvstate_bin->data + sizeof(*nvstate);
	nvstate_data_len = nvstate_bin->len - sizeof(*nvstate);
	if (nvstate->version != IPA_NVSTATE_VERSION) {
		IPA_LOGP(SIPA, LERROR,
			 "cannot deserialize non volatile state with mismatching version number %u (expected version: %u)\n",
			 nvstate->version, IPA_NVSTATE_VERSION);
		nvstate_reset(nvstate);
		return;
	}

	/* deserialize dynamically allocated struct members (append code for new members here) */
	nvstate->iot_euicc_emu.eim_cfg_ber = nvstate_deserialize_ipa_buf(&nvstate_data, &nvstate_data_len);
	nvstate->iot_euicc_emu.auto_enable.smdp_oid = nvstate_deserialize_ipa_buf(&nvstate_data, &nvstate_data_len);
	nvstate->iot_euicc_emu.auto_enable.smdp_address = nvstate_deserialize_ipa_buf(&nvstate_data, &nvstate_data_len);
}

/*! Read eIM configuration from eUICC and pick a suitable eIM.
 *  \param[inout] ctx pointer to ipa_context.
 *  \returns 0 success, -EINVAL on failure. */
int eim_init(struct ipa_context *ctx)
{
	struct ipa_es10b_eim_cfg_data *eim_cfg_data = NULL;
	struct EimConfigurationData *eim_cfg_data_item = NULL;
	long i;

	eim_cfg_data = ipa_es10b_get_eim_cfg_data(ctx);
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

	if (eim_cfg_data_item->eimFqdn)
		ctx->eim_fqdn = IPA_STR_FROM_ASN(eim_cfg_data_item->eimFqdn);
	else if (*eim_cfg_data_item->eimIdType == 2)
		ctx->eim_fqdn = IPA_STR_FROM_ASN(&eim_cfg_data_item->eimId);
	else
		goto error;

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
		/* TODO: install eUICC client certificate for mutual TLS once
		 * an ES10b-backed or PC/SC-APDU signing function is available:
		 *
		 *   ipa_http_set_client_cert_der(ctx->http_ctx,
		 *       euicc_cert_der, euicc_cert_len,
		 *       euicc_tls_sign, ctx);
		 *
		 * euicc_tls_sign() would obtain the eUICC certificate from
		 * ipa_es10b_get_certs() and delegate ECDSA signing to the chip
		 * via a COMPUTE DIGITAL SIGNATURE APDU or equivalent. */
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
	nvstate_deserialize(&ctx->nvstate, nvstate);

	return ctx;
}

/*! Initialize IPAd and prepare links towards eIM and eUICC.
 *  \param[inout] ctx pointer to ipa_context.
 *  \returns 0 success, -EINVAL on failure. */
int ipa_init(struct ipa_context *ctx)
{
	int rc;

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

	/* Call ES10b function AddInitialEim */
	add_init_eim_req.req = *eim_cfg_decoded;
	add_init_eim_res = ipa_es10b_add_init_eim(ctx, &add_init_eim_req);

	ipa_es10b_add_init_eim_res_free(add_init_eim_res);
	ASN_STRUCT_FREE(asn_DEF_AddInitialEimRequest, eim_cfg_decoded);
	return 0;
}

/*! reset memory of the eUICC (eUICCMemoryReset).
 *  \param[inout] ctx pointer to ipa_context.
 *  \param[inout] operatnl_profiles apply reset option "deleteOperationalProfiles".
 *  \param[inout] test_profiles apply reset option "deleteFieldLoadedTestProfiles".
 *  \param[inout] default_smdp_addr apply reset option "resetDefaultSmdpAddress".
 *  \returns 0 on success, negative on error. */
int ipa_euicc_mem_rst(struct ipa_context *ctx, bool operatnl_profiles, bool test_profiles, bool default_smdp_addr,
		      bool eim_cfg_data, bool auto_enable_cfg)
{
	struct ipa_es10b_euicc_mem_rst euicc_mem_rst = { 0 };
	euicc_mem_rst.operatnl_profiles = operatnl_profiles;
	euicc_mem_rst.test_profiles = test_profiles;
	euicc_mem_rst.default_smdp_addr = default_smdp_addr;
	euicc_mem_rst.eim_cfg_data = eim_cfg_data;
	euicc_mem_rst.auto_enable_cfg = auto_enable_cfg;
	return ipa_es10b_euicc_mem_rst(ctx, &euicc_mem_rst);
}

/* ---------------------------------------------------------------------------
 * Direct ES10b triggers (see onomondo/ipad.h for the daemon-integration
 * contract).  These are thin, synchronous pass-throughs to the ES10b layer;
 * the host decides when to invoke them.
 * --------------------------------------------------------------------------- */

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
	ipa_buf_free(ctx->iot_euicc_emu.auto_enable.smdp_oid);
	ipa_buf_free(ctx->iot_euicc_emu.auto_enable.smdp_address);
	ipa_buf_free(ctx->iot_euicc_emu.auto_enable.profile_aid);
	IPA_FREE(ctx->eim_id);
	IPA_FREE(ctx->eim_fqdn);
	ipa_proc_eucc_pkg_dwnld_exec_res_free(ctx->proc_eucc_pkg_dwnld_exec_res);

	if (ctx->scard_ctx)
		ipa_euicc_close_es10x(ctx);
	ipa_http_free(ctx->http_ctx);
	ipa_scard_free(ctx->scard_ctx);
	nvstate_free_contents(&ctx->nvstate);
	IPA_FREE(ctx);

	return nvstate;
}
