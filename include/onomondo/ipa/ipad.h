/*
 * Copyright (c) 2025 Onomondo ApS & sysmocom - s.f.m.c. GmbH. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#define IPA_LEN_FQDN 255
#define IPA_LEN_TAC 4
#define IPA_LEN_ALLOWED_CA 20
#define IPE_LEN_EIM_ID 256

struct ipa_context;
struct ipa_buf;

/* NEW in v1.1: SGP.32 §6.3.2.6 — StateChangeCause.  The IPA sets this on
 * ESipa.GetEimPackage after a local state change so the eIM can correlate.
 * Values mirror the SGP.32 v1.2 StateChangeCause enumeration; keep them in
 * sync with the ASN.1 definition in asn1/SGP32Definitions.asn. */
enum ipa_state_change_cause {
	IPA_STATE_CHANGE_NONE = -1, /* IPA-internal sentinel; do not send */
	IPA_STATE_CHANGE_OTHER_EIM = 0,
	IPA_STATE_CHANGE_FALLBACK = 1,
	IPA_STATE_CHANGE_EMERGENCY_PROFILE = 2,
	IPA_STATE_CHANGE_LOCAL = 3,
	IPA_STATE_CHANGE_RESET = 4,
	IPA_STATE_CHANGE_IMMEDIATE_ENABLE_PROFILE = 5,
	IPA_STATE_CHANGE_DEVICE_CHANGE = 6, /* IPAe-only */
	IPA_STATE_CHANGE_UNDEFINED = 127,
};

/* (deprecated, see github issue #5) */
typedef bool (*ipa_prfle_inst_consent_cb)(char *sm_dp_plus_address, char *ac_token);

/* NEW in v1.1: §6.1 / §6.4 — ESipa transport binding.  SGP.32 v1.2 defines
 * two wire encodings for messages between IPA and eIM: ASN.1 (BER/DER)
 * and JSON.  The eIM MUST support both; the IPA may pick either.  Default
 * to ASN.1 for compactness (important over NB-IoT/cat-M uplinks). */
enum ipa_esipa_binding {
	IPA_ESIPA_BINDING_ASN1 = 0, /* default — application/x-gsma-rsp-asn1 */
	IPA_ESIPA_BINDING_JSON = 1, /* application/json;charset=UTF-8 */
};

enum ipa_poll_rc {
	/*! The API user shall call ipa_poll() again immediately.
	 *  (there may be still eIM packages waiting to be executed). */
	IPA_POLL_AGAIN = 0,

	/*! The APU user may call ipa_poll() less frequently.
	 *  (there are no further eIM packages waiting) */
	IPA_POLL_AGAIN_LATER = 1,

	/*! An eIM package contained an operation (e.g. switch to another eUICC profile) that may cause a temporary loss
	 *  of the IP connectivity. The API user shall call ipa_poll() again as soon as the IP connectivity has
	 *  been resettled. */
	IPA_POLL_AGAIN_WHEN_ONLINE = 2,

	/*! Communication with the eUICC was not possible. The caller shall call ipa_popp() again when connectivity to
	 *  the eUICC has been recovered. */
	IPA_POLL_CHECK_SCARD = -1000,

	/*! Communication with the eIM was not possible. The caller shall call ipa_popp() again when connectivity to
	 *  the eIM has been recovered. */
	IPA_POLL_CHECK_HTTP = -2000,
};

/*! IPAd Configuration */
struct ipa_config {
	/*! preferred eimId (optional. When set to NULL, the first eIM config item in the EimConfigurationData list is
	 *  used.) */
	char *preferred_eim_id;

	/*! current TAC (This struct member may be updated at any time after context creation.) */
	uint8_t tac[IPA_LEN_TAC];

	/*! The caller may specify a path to a CA bundle file. The string is passed to ipa_http_init() on
	 *  initialization (see also http.h and http.c) */
	const char *eim_cabundle;

	/*! The caller may choose to disable SSL in a test environment to simplify debugging. */
	bool eim_disable_ssl;

	/*! The caller may choose to disable SSL certificate verification in a test environment to simplify debugging. */
	bool eim_disable_ssl_verif;

	/*! Configure the number of retries to apply in case a request (HTTP) to the eIM fails */
	unsigned int esipa_req_retries;

	/*! ESipa wire binding — ASN.1 (default) or JSON per SGP.32 v1.2 §6.4.
	 *  Set IPA_ESIPA_BINDING_JSON to talk to an eIM that prefers / requires
	 *  the JSON binding.  Both bindings are spec-compliant; ASN.1 is more
	 *  compact and recommended for constrained IoT uplinks. */
	enum ipa_esipa_binding esipa_binding;

	/*! When a profile rollback is performed an optional refresh flag can be set. (See also SGP.32, section 5.9.16)
	 *  In case the IoT eUICC emulation is enabled (iot_euicc_emu_enabled), then this flag also plays a role when
	 *  profiles are disabled or enabled. (See also SGP.22, section 5.7.16 and section 5.7.17)
	 *
	 *  UPDATE for v1.1: 5.9.15 — This flag now ALSO governs ES10b.ImmediateEnable
	 *  (formerly EnableUsingDD) and the new Emergency-Profile / Fallback
	 *  functions (§5.9.22, §5.9.23, §5.9.20).
	 *  UPDATE for v1.2: CR111007R00 — when refresh_flag == true the eUICC will
	 *  reset rollback authorization during ImmediateEnable / EnableEmergencyProfile
	 *  / DisableEmergencyProfile.  Choose with that side-effect in mind. */
	bool refresh_flag;

	/*! ID number of the cardreader that interfaces the eUICC */
	unsigned int reader_num;

	/*! Number of the logical channel that is used to communicate with the ISD-R */
	uint8_t euicc_channel;

	/*! Enable IoT eUICC emulation.
	 *  This IPAd also supports the use of consumer eUICCs, which have a slightly different interface. When the
	 *  IoT eUICC emulation is enabled, the IPAd will adapt the interface on ES10x function level so that the
	 *  consumer eUICC appears as an IoT eUICC on procedure level. */
	bool iot_euicc_emu_enabled;

	/*! (deprecated, see github issue #5) Consent to profile installation.
	 *  SGP.32 requires to prompt the user to consent to a profile installation. The API user may pass a callback
	 *  function here to handle the consent request. In case no callback function is provided onomondo-eim will
	 *  automatically consent to any profile installation. */
	ipa_prfle_inst_consent_cb prfle_inst_consent_cb;
};

struct ipa_context *ipa_new_ctx(struct ipa_config *cfg, struct ipa_buf *nvstate);
int ipa_init(struct ipa_context *ctx);
int eim_init(struct ipa_context *ctx);
int ipa_add_init_eim_cfg(struct ipa_context *ctx, struct ipa_buf *cfg);
int ipa_euicc_mem_rst(struct ipa_context *ctx, bool operatnl_profiles, bool test_profiles, bool default_smdp_addr,
		      bool eim_cfg_data, bool auto_enable_cfg);
int ipa_poll(struct ipa_context *ctx);
void ipa_close(struct ipa_context *ctx);
struct ipa_buf *ipa_free_ctx(struct ipa_context *ctx);

/* ===========================================================================
 * NEW in v1.1/v1.2 — direct ES10b triggers for host / daemon integration
 * ===========================================================================
 *
 * SGP.32 v1.1 adds several ES10b functions whose *invocation* is a device
 * policy decision the IPAd library cannot make on its own: it depends on
 * signals the host owns (radio-registration state, an eCall trigger, an
 * operator request, ...).  This library therefore provides only the ES10b
 * transport for each; the device daemon decides WHEN to call them.
 *
 * How a real IoT-device daemon is expected to wire these up:
 *
 *   - Fallback (§5.9.20 / §5.9.21): when the modem repeatedly fails to register
 *     on the network of the currently enabled profile, call
 *     ipa_execute_fallback(); once connectivity is restored (or the fallback
 *     window ends), call ipa_return_from_fallback().  The Fallback Profile must
 *     already have been tagged by the eIM via Psmo.setFallbackAttribute.
 *
 *   - Emergency Profile (§5.9.22 / §5.9.23): call
 *     ipa_enable_emergency_profile() when the device enters an eCall / emergency
 *     state (only on devices whose eUICC reports
 *     iotSpecificInfo.ecallSupported), and ipa_disable_emergency_profile() when
 *     leaving it.
 *
 *   - Connectivity parameters (§5.9.24): after (re)selecting a profile, call
 *     ipa_get_connectivity_params() to learn how the eUICC wants the IPA to
 *     reach the RSP server, and feed the returned httpParams into your HTTP /
 *     transport configuration.
 *
 *   - Default SM-DP+ (§5.9.25): call ipa_set_default_dp_addr() if the host wants
 *     to set the default SM-DP+ FQDN locally.  If instead the eIM sets it via
 *     the Psmo path, no direct call is needed (it is handled inside ipa_poll()).
 *
 * Threading / sequencing: each call is a synchronous ES10b (APDU) round-trip to
 * the eUICC.  Call these BETWEEN ipa_poll() cycles, never concurrently with an
 * in-flight poll, and only after a successful ipa_init().
 *
 * refresh_flag: pass true to request a UICC REFRESH after the profile-state
 * change (and, per CR111007R00, a reset of rollback authorization on
 * ImmediateEnable / EnableEmergencyProfile / DisableEmergencyProfile).  A daemon
 * typically sources this from ipa_config.refresh_flag.
 *
 * Return value (unless noted otherwise): 0 when the eUICC reports "ok", a
 * positive SGP.32 result/error code returned by the eUICC (see the per-function
 * enumerations in the spec / the corresponding es10b_*.h), or a negative value
 * on a transport / encode / decode failure.
 */

/*! ES10b ImmediateEnable — enable the (immediate-enable-configured) profile now. */
int ipa_immediate_enable(struct ipa_context *ctx, bool refresh_flag);

/*! ES10b ExecuteFallbackMechanism — swap to the tagged Fallback Profile. */
int ipa_execute_fallback(struct ipa_context *ctx, bool refresh_flag);

/*! ES10b ReturnFromFallback — return from the Fallback Profile to the operational one. */
int ipa_return_from_fallback(struct ipa_context *ctx, bool refresh_flag);

/*! ES10b EnableEmergencyProfile — enable the Emergency (eCall) Profile. */
int ipa_enable_emergency_profile(struct ipa_context *ctx, bool refresh_flag);

/*! ES10b DisableEmergencyProfile — disable the Emergency (eCall) Profile. */
int ipa_disable_emergency_profile(struct ipa_context *ctx, bool refresh_flag);

/*! ES10b SetDefaultDpAddress — set the default SM-DP+ address on the eUICC.
 *  \param[in] default_dp_fqdn NUL-terminated FQDN (e.g. "smdp.example.com"). */
int ipa_set_default_dp_addr(struct ipa_context *ctx, const char *default_dp_fqdn);

/*! Connectivity parameters returned by ipa_get_connectivity_params(). */
struct ipa_connectivity_params {
	/*! httpParams OCTET STRING as provided by the eUICC (SGP.32 §5.9.24), or
	 *  NULL if the eUICC did not include it.  Contents are deployment-specific;
	 *  treat as opaque and hand to your transport layer.  Owned by this struct
	 *  and released by ipa_connectivity_params_free(). */
	uint8_t *http_params;
	/*! length of http_params in bytes (0 when http_params is NULL). */
	size_t http_params_len;
};

/*! ES10b GetConnectivityParameters — query the eUICC's connectivity parameters.
 *  \returns newly-allocated parameters (free with ipa_connectivity_params_free()),
 *           or NULL on transport error or when the eUICC returns an error CHOICE. */
struct ipa_connectivity_params *ipa_get_connectivity_params(struct ipa_context *ctx);

/*! Free a result returned by ipa_get_connectivity_params() (NULL-safe). */
void ipa_connectivity_params_free(struct ipa_connectivity_params *p);
