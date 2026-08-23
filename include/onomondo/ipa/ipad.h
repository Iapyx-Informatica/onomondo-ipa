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
/*! Length of an IMEI as carried in DeviceInfo (SGP.22 Octet8: 8 BCD digits plus check digit and a filler). */
#define IPA_LEN_IMEI 8
/*! Length of a VersionType: major, minor and revision, one binary byte each (e.g. { 0x0f, 0x00, 0x00 } for
 *  3GPP release 15). */
#define IPA_LEN_VERSION 3
#define IPA_LEN_ALLOWED_CA 20
#define IPE_LEN_EIM_ID 256

struct ipa_context;
struct ipa_buf;

/*! Radio access technologies the device supports, for the deviceCapabilities of DeviceInfo.
 *
 *  SGP.22, section 4.2: "Device Information is mainly in destination of the SM-DP+ for the purpose of Device
 *  eligibility check. The SM-DP+/Operator is free to use or ignore this information at their discretion", and
 *  "Device capabilities: The Device SHALL set all the capabilities it supports". Every entry is OPTIONAL on the
 *  wire, so an entry left NULL says the device does not support that technology -- which is why they should be
 *  filled in for a device that does, even though nothing breaks if they are not.
 *
 *  Each entry points at IPA_LEN_VERSION bytes holding the highest fully supported release. The IPA cannot
 *  discover any of this by itself; it belongs to the device the IPA is integrated into, like the TAC. */
struct ipa_device_capabilities {
	const uint8_t *gsm;
	const uint8_t *utran;
	const uint8_t *cdma2000_onex;
	const uint8_t *cdma2000_hrpd;
	const uint8_t *cdma2000_ehrpd;
	const uint8_t *eutran_epc;
	const uint8_t *nr_epc;
	const uint8_t *nr_5gc;
	const uint8_t *eutran_5gc;
};

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

/* Simple Confirmation on a profile download, see ipa_config.prfle_inst_consent_cb. */
typedef bool (*ipa_prfle_inst_consent_cb)(char *sm_dp_plus_address, char *ac_token);

/*! Profile Policy Rules of a profile that the Rules Authorisation Table of the eUICC allows only with the consent of
 *  the end user. A rule that the RAT allows outright, or that the profile does not set at all, is false here -- the
 *  struct describes what the end user is being asked about, not everything the profile carries.
 *  See also GSMA SGP.22, section 2.9.1 (the rules) and section 3.1.3, step 8 (the consent). */
struct ipa_ppr_consent {
	/*! PPR1, 'Disabling of this Profile is not allowed'. */
	bool ppr1;

	/*! PPR2, 'Deletion of this Profile is not allowed'. */
	bool ppr2;

	/*! Profile name of the profile about to be installed ('Short Description' in SGP.21), from the profile
	 *  metadata. Valid for the duration of the call only. */
	const char *profile_name;

	/*! Service provider name of the profile about to be installed, from the profile metadata. Valid for the
	 *  duration of the call only. */
	const char *service_provider_name;
};

/*! Ask the end user to consent to the Profile Policy Rules of a profile that is about to be installed.
 *  A device with a user interface is expected to present the rules and their consequences and to let the end user
 *  decide (SGP.22, section 3.1.3, step 8 calls this a Strong Confirmation).
 *  \param[in] consent the rules the consent is being asked for, and the profile they belong to.
 *  \return true when the end user consents and the profile may be installed. */
typedef bool (*ipa_ppr_consent_cb)(const struct ipa_ppr_consent *consent);

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

	/*! IMEI of the device, IPA_LEN_IMEI bytes, or NULL to leave it out. It is OPTIONAL in DeviceInfo
	 *  (SGP.22, section 4.2), but an SM-DP+ may use it for its eligibility check. */
	const uint8_t *imei;

	/*! Radio access technologies of the device, all entries NULL by default. See the struct comment: leaving
	 *  these unset tells the SM-DP+ that the device supports none of them. */
	struct ipa_device_capabilities device_capabilities;

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
	 *  compact and recommended for constrained IoT uplinks.
	 *
	 *  Both are built by default, and a deployment that knows which one its eIM speaks can drop the other with
	 *  -DESIPA_BINDING_ASN1=OFF or -DESIPA_BINDING_JSON=OFF. libipa defines IPA_HAVE_ESIPA_ASN1 and
	 *  IPA_HAVE_ESIPA_JSON for the ones it has; selecting a binding the build does not have makes ipa_init()
	 *  fail with -EINVAL. Note that ASN.1 is the zero value of this enum, so a JSON-only build has to set this
	 *  explicitly. */
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
	 *  consumer eUICC appears as an IoT eUICC on procedure level.
	 *
	 *  The emulation is a build option and is OFF by default, because a product ships with the eUICC it ships
	 *  with and one that will never see a consumer card should not carry the adaptation layer. libipa defines
	 *  IPA_HAVE_IOT_EUICC_EMULATION when it was built with -DIOT_EUICC_EMULATION=ON; setting this flag in a
	 *  build without it makes ipa_init() fail with -EINVAL rather than silently ignore the request. */
	bool iot_euicc_emu_enabled;

	/*! Consent to the Profile Policy Rules of a profile about to be installed.
	 *  This is asked only for the rules the RAT of the eUICC marks as requiring end user consent, and it is a
	 *  separate question from prfle_inst_consent_cb below, which is about the download as such.
	 *
	 *  A device with a user interface SHOULD provide this callback. A device without one cannot ask, and what
	 *  happens then is decided when the library is built: by default such a profile is refused, and
	 *  -DPPR_ALLOW_WITHOUT_CONSENT=ON installs it instead (see README). SGP.32, section 3.2.3.1 notes that IoT
	 *  devices without a user interface are not expected to be given a RAT that demands consent at all. */
	ipa_ppr_consent_cb ppr_consent_cb;

	/*! Consent to the profile download as such (Simple Confirmation).
	 *  SGP.32, section 3.2.3.2 step 15 (and section 3.2.3.1 step 10 for the direct download) has the IPA verify
	 *  the Profile Metadata "according to steps 7a, b, c and 8 of section 3.1.3" of SGP.22, and step 8 requires
	 *  Simple Confirmation on the profile download when the metadata carries neither Profile Policy Rules nor
	 *  Enterprise Rules. When those rules are present and the RAT marks them as needing end user consent, the
	 *  question to ask is the Strong Confirmation of ppr_consent_cb above instead.
	 *  The API user may pass a callback function here to handle the consent request. In case no callback
	 *  function is provided onomondo-ipa will automatically consent to any profile download. */
	ipa_prfle_inst_consent_cb prfle_inst_consent_cb;
};

struct ipa_context *ipa_new_ctx(struct ipa_config *cfg, struct ipa_buf *nvstate);
int ipa_init(struct ipa_context *ctx);
int eim_init(struct ipa_context *ctx);
int ipa_add_init_eim_cfg(struct ipa_context *ctx, struct ipa_buf *cfg);
/*! Subsets an eUICC Memory Reset may delete or reset, see GSMA SGP.32, section 5.9.5.
 *  Any combination MAY be given. The bit positions are the resetOptions named-bit numbers of the SGP.32
 *  EuiccMemoryResetRequest, so this enum stays readable next to the specification. */
enum ipa_euicc_mem_rst_opt {
	/*! Delete all Operational Profiles. */
	IPA_EUICC_MEM_RST_OPERATIONAL_PROFILES = (1 << 0),
	/*! Delete Test Profiles that were field loaded. */
	IPA_EUICC_MEM_RST_FIELD_LOADED_TEST_PROFILES = (1 << 1),
	/*! Reset the default SM-DP+ address to its initial value. */
	IPA_EUICC_MEM_RST_DEFAULT_SMDP_ADDR = (1 << 2),
	/*! Delete Test Profiles that were pre-installed in the factory. Not reloadable in the field. */
	IPA_EUICC_MEM_RST_PRE_LOADED_TEST_PROFILES = (1 << 3),
	/*! Delete all Provisioning Profiles. These carry the bootstrap connectivity a device uses to reach
	 *  its eIM, so on a deployed device this may remove the only way back in. */
	IPA_EUICC_MEM_RST_PROVISIONING_PROFILES = (1 << 4),
	/*! Remove the eIM Configuration Data of all Associated eIMs. */
	IPA_EUICC_MEM_RST_EIM_CFG_DATA = (1 << 5),
	/*! Deactivate immediate Profile enabling and drop its configuration. */
	IPA_EUICC_MEM_RST_IMMEDIATE_ENABLE_CFG = (1 << 6),
};

/*! Perform an eUICC Memory Reset (ES10b), see GSMA SGP.32, section 5.9.5.
 *  \param[inout] ctx pointer to ipa_context.
 *  \param[in] options bitmask of enum ipa_euicc_mem_rst_opt; nothing is deleted when it is 0.
 *  \returns 0 on success, negative on error. */
int ipa_euicc_mem_rst(struct ipa_context *ctx, uint32_t options);
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

/*! A version as EUICCInfo2 carries it (VersionType: major/minor/revision, one byte each). */
struct ipa_version {
	uint8_t major;
	uint8_t minor;
	uint8_t revision;
};

/*! Which IPA is currently active, see GSMA SGP.32, section 3.8.4. IPAe and IPAd are mutually
 *  exclusive, and which one is in charge is not something the eUICC is asked -- it follows from what
 *  the device has told the eUICC, so the library tracks it as the link is brought up. */
enum ipa_mode {
	/*! Not settled yet: the eUICC has not been told which IPA the device supports. */
	IPA_MODE_UNKNOWN = -1,
	/*! IPAd is active -- this library is the IPA. Reached once TERMINAL CAPABILITY has declared
	 *  IPAd support, which is what makes the eUICC leave its own IPAe deactivated. */
	IPA_MODE_IPAD = 0,
	/*! IPAe is active -- the IPA runs inside the eUICC and this library is not in charge. */
	IPA_MODE_IPAE = 1,
};

/*! What the eUICC reports about itself in EUICCInfo2, see GSMA SGP.32, section 5.9.2.
 *  Fill it with ipa_get_euicc_caps() and use it to decide whether the ES10b triggers below apply to
 *  this eUICC at all. */
struct ipa_euicc_caps {
	/*! The eUICC supports the Emergency Profile mechanism, so ipa_enable_emergency_profile() and
	 *  ipa_disable_emergency_profile() are meaningful on it (iotSpecificInfo.ecallSupported). */
	bool ecall_supported;

	/*! The eUICC supports the Fallback mechanism, so ipa_execute_fallback() and
	 *  ipa_return_from_fallback() are meaningful on it (iotSpecificInfo.fallbackSupported). */
	bool fallback_supported;

	/*! The SGP.32 version(s) the eUICC supports (iotSpecificInfo.iotVersion); at least one is always
	 *  present. The array belongs to the library and stays valid until ipa_free_ctx(); do not free it. */
	const struct ipa_version *iot_version;

	/*! Number of entries in iot_version. */
	size_t iot_version_count;

	/*! The eUICC has an IPAe of its own (ISDRProprietaryApplicationTemplateIoT.ipaeSupported from the
	 *  ISD-R SELECT FCI, section 3.8.4). This says an IPAe exists, not that it is running -- see
	 *  ipa_mode for that. False also when the eUICC returned no such template at all, which is what
	 *  an SGP.22 eUICC does. */
	bool ipae_supported;

	/*! Which IPA is active. Once the link is up this is IPA_MODE_IPAD: bringing it up declares IPAd
	 *  support in TERMINAL CAPABILITY, and section 3.8.4 has the eUICC deactivate its IPAe in
	 *  response. Unlike the other fields here this one is a state, not a property of the eUICC, and
	 *  it changes if the IPAe is ever activated. */
	enum ipa_mode ipa_mode;
};

/*! Read the eUICC's IoT capabilities, see GSMA SGP.32, section 5.9.2.
 *  The first call fetches EUICCInfo2 from the eUICC; iotSpecificInfo does not change for the life of
 *  the eUICC, so the result is cached in the context and later calls cost nothing. Call it any time
 *  after a successful ipa_init().
 *  In IoT eUICC emulation mode the underlying consumer eUICC supports neither mechanism, so both flags
 *  come back false, iot_version reports the SGP.32 version this IPA implements, and ipae_supported is
 *  false -- a consumer eUICC has no IPAe.
 *  \param[inout] ctx pointer to ipa_context.
 *  \param[out] caps filled in on success, untouched otherwise.
 *  \returns 0 on success, negative on error. */
int ipa_get_euicc_caps(struct ipa_context *ctx, struct ipa_euicc_caps *caps);

/*! Activate the eUICC's own IPAe, see GSMA SGP.32, section 3.8.4.
 *
 *  This hands the eUICC over. IPAe and IPAd are mutually exclusive: on success the IPA runs inside the
 *  eUICC and this library is no longer the active IPA, so stop calling it. Section 3.8.4 notes that
 *  getting back means resetting the eUICC and sending a TERMINAL CAPABILITY that declares IPAd support
 *  again -- ipa_init() on a fresh context does that.
 *
 *  Section 3.8.4 makes this a MAY, conditioned on two things the caller must satisfy: the eUICC has to
 *  have advertised IPAe (ipa_get_euicc_caps().ipae_supported), which this function checks and refuses
 *  with -ENOTSUP when the eUICC positively said otherwise; and the IoT Device has to meet the IPAe
 *  requirements of Annex A.2, which the library cannot know and does not check. Deciding that is the
 *  host's job, exactly like the ES10b triggers below.
 *
 *  \param[inout] ctx pointer to ipa_context.
 *  \returns 0 when the eUICC reports ok, positive on an eUICC error status (notSupported = 1),
 *           negative on a transport failure or when the eUICC has no IPAe to activate. */
int ipa_activate_ipae(struct ipa_context *ctx);

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
