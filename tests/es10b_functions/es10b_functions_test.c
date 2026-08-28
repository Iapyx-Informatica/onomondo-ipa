/*
 * Copyright (c) 2026 Onomondo ApS & sysmocom - s.f.m.c. GmbH & Iapyx Informatica Ltda. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * The ES10b functions GSMA SGP.32 added in v1.1, over the real ES10x path: EnableEmergencyProfile
 * (section 5.9.22), DisableEmergencyProfile (5.9.23), GetConnectivityParameters (5.9.24),
 * ImmediateEnable (5.9.15) and ConfigureImmediateProfileEnabling (5.9.17).
 *
 * Each of them encodes a request, hands it to the ES10x framing and decodes a response carrying its own
 * error enum.  What that leaves exposed is a schema change or a renamed field: the code still compiles,
 * still runs, and is wrong only against a real eUICC.  So these check the bytes that reach the card --
 * the request tag, and the members the spec makes mandatory -- and that every value of each error enum
 * arrives at the caller as itself.
 *
 * The two functions with an emulation branch take their real branch here: IPA_EUICC_EMU() is a constant
 * 0 in a build without the emulation, and the runtime flag is left off in the one with it.  Their
 * emulation branches are covered in tests/euicc_emu/.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <stdbool.h>
#include <onomondo/ipa/utils.h>
#include <onomondo/ipa/ipad.h>
#include <onomondo/ipa/scard.h>
#include <EnableEmergencyProfileResponse.h>
#include <DisableEmergencyProfileResponse.h>
#include <GetConnectivityParametersResponse.h>
#include <ImmediateEnableResponse.h>
#include <ConfigureImmediateProfileEnablingResponse.h>
#include "src/ipa/libipa/context.h"
#include "src/ipa/libipa/es10b_enable_emergency_profile.h"
#include "src/ipa/libipa/es10b_disable_emergency_profile.h"
#include "src/ipa/libipa/es10b_get_connectivity_params.h"
#include "src/ipa/libipa/es10b_immediate_enable.h"
#include "src/ipa/libipa/es10b_cfg_immediate_enable.h"
#include "tests/stubs/euicc_stub.h"

/* ES10x request tags, from the ASN.1 in asn1/SGP32Definitions.asn. */
#define TAG_ENABLE_EMERGENCY  0xBF5B	/* [91], section 5.9.22 */
#define TAG_DISABLE_EMERGENCY 0xBF5C	/* [92], section 5.9.23 */
#define TAG_GET_CONNECTIVITY  0xBF5F	/* [95], section 5.9.24 */
#define TAG_IMMEDIATE_ENABLE  0xBF5A	/* [90], section 5.9.15 */
#define TAG_CFG_IMMEDIATE_EN  0xBF59	/* [89], section 5.9.17 */

static struct ipa_config cfg;

static struct ipa_context *test_ctx(void)
{
	struct ipa_context *ctx;

	memset(&cfg, 0, sizeof(cfg));
	/* Left off deliberately: these cases are about the real ES10b path.  In a build without the
	 * emulation the flag has no effect anyway. */
	cfg.iot_euicc_emu_enabled = false;
	ctx = ipa_new_ctx(&cfg, NULL);
	assert(ctx);
	ctx->scard_ctx = ipa_scard_init(0);
	euicc_stub_reset();
	return ctx;
}

static void free_ctx(struct ipa_context *ctx)
{
	ipa_buf_free(ipa_free_ctx(ctx));
}

/* The one request the card saw, checked for its tag. */
static void assert_single_request(uint16_t tag)
{
	assert(euicc_stub_requests() == 1);
	assert(euicc_stub_request_has_tag(0, tag));
}

/* Does the request the card saw contain this byte sequence?  Used for the members the spec makes
 * mandatory, which are small enough to match literally. */
static bool request_contains(const uint8_t *needle, size_t len)
{
	const uint8_t *req;
	size_t req_len, i;

	req = euicc_stub_request(0, &req_len);
	if (!req || req_len < len)
		return false;
	for (i = 0; i + len <= req_len; i++) {
		if (!memcmp(req + i, needle, len))
			return true;
	}
	return false;
}

/* SGP.32 section 5.9.22.  Both emergency functions carry a refreshFlag and report through an enum whose
 * ok(0) also makes the IPA record a state change for the eIM's next poll. */
static void enable_emergency_profile_test(void)
{
	static const struct {
		long result;
		const char *name;
	} cases[] = {
		{ EnableEmergencyProfileResponse__enableEmergencyProfileResult_ok, "ok" },
		{ EnableEmergencyProfileResponse__enableEmergencyProfileResult_profileNotInDisabledState,
		  "profileNotInDisabledState" },
		{ EnableEmergencyProfileResponse__enableEmergencyProfileResult_catBusy, "catBusy" },
		{ EnableEmergencyProfileResponse__enableEmergencyProfileResult_ecallNotAvailable,
		  "ecallNotAvailable" },
		{ EnableEmergencyProfileResponse__enableEmergencyProfileResult_undefinedError, "undefinedError" },
	};
	unsigned int i;

	printf("== enable_emergency_profile_test ==\n");

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		struct ipa_context *ctx = test_ctx();
		EnableEmergencyProfileResponse_t res = { 0 };
		int rc;

		res.enableEmergencyProfileResult = cases[i].result;
		euicc_stub_queue_asn1(&asn_DEF_EnableEmergencyProfileResponse, &res);

		rc = ipa_es10b_enable_emergency_profile(ctx, true);
		assert_single_request(TAG_ENABLE_EMERGENCY);
		assert(rc == cases[i].result);

		/* Only a success is a state change worth telling the eIM about. */
		if (cases[i].result == EnableEmergencyProfileResponse__enableEmergencyProfileResult_ok)
			assert(ctx->nvstate.state_change_cause == IPA_STATE_CHANGE_EMERGENCY_PROFILE);
		else
			assert(ctx->nvstate.state_change_cause != IPA_STATE_CHANGE_EMERGENCY_PROFILE);

		printf("   %-26s -> reported as itself\n", cases[i].name);
		free_ctx(ctx);
	}
}

/* SGP.32 section 5.9.23, the mirror of the above. */
static void disable_emergency_profile_test(void)
{
	static const struct {
		long result;
		const char *name;
	} cases[] = {
		{ DisableEmergencyProfileResponse__disableEmergencyProfileResult_ok, "ok" },
		{ DisableEmergencyProfileResponse__disableEmergencyProfileResult_profileNotInEnabledState,
		  "profileNotInEnabledState" },
		{ DisableEmergencyProfileResponse__disableEmergencyProfileResult_catBusy, "catBusy" },
		{ DisableEmergencyProfileResponse__disableEmergencyProfileResult_undefinedError, "undefinedError" },
	};
	unsigned int i;

	printf("== disable_emergency_profile_test ==\n");

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		struct ipa_context *ctx = test_ctx();
		DisableEmergencyProfileResponse_t res = { 0 };
		int rc;

		res.disableEmergencyProfileResult = cases[i].result;
		euicc_stub_queue_asn1(&asn_DEF_DisableEmergencyProfileResponse, &res);

		rc = ipa_es10b_disable_emergency_profile(ctx, false);
		assert_single_request(TAG_DISABLE_EMERGENCY);
		assert(rc == cases[i].result);
		printf("   %-26s -> reported as itself\n", cases[i].name);
		free_ctx(ctx);
	}
}

/* SGP.32 section 5.9.24.  A CHOICE rather than a result enum: httpParams come back on one arm and an
 * error code on the other, and httpParams is itself OPTIONAL within its arm. */
static void get_connectivity_params_test(void)
{
	static const uint8_t http_params[] = { 0x01, 0x02, 0x03, 0x04 };
	struct ipa_context *ctx;
	GetConnectivityParametersResponse_t res;
	struct ipa_es10b_connectivity_params *p;
	OCTET_STRING_t hp = { 0 };

	printf("== get_connectivity_params_test ==\n");

	/* Present. */
	ctx = test_ctx();
	memset(&res, 0, sizeof(res));
	res.present = GetConnectivityParametersResponse_PR_connectivityParameters;
	assert(OCTET_STRING_fromBuf(&hp, (const char *)http_params, sizeof(http_params)) == 0);
	res.choice.connectivityParameters.httpParams = &hp;
	euicc_stub_queue_asn1(&asn_DEF_GetConnectivityParametersResponse, &res);

	p = ipa_es10b_get_connectivity_params(ctx);
	assert_single_request(TAG_GET_CONNECTIVITY);
	assert(p && p->http_params);
	assert(p->http_params->len == sizeof(http_params));
	assert(!memcmp(p->http_params->data, http_params, sizeof(http_params)));
	printf("   httpParams present         -> %zu bytes handed back\n", p->http_params->len);
	ipa_es10b_connectivity_params_free(p);
	free_ctx(ctx);

	/* Absent, which the schema allows: a result, just an empty one. */
	ctx = test_ctx();
	res.choice.connectivityParameters.httpParams = NULL;
	euicc_stub_queue_asn1(&asn_DEF_GetConnectivityParametersResponse, &res);

	p = ipa_es10b_get_connectivity_params(ctx);
	assert_single_request(TAG_GET_CONNECTIVITY);
	assert(p && p->http_params == NULL);
	printf("   httpParams absent          -> result with nothing in it\n");
	ipa_es10b_connectivity_params_free(p);
	free_ctx(ctx);

	/* The error arm.  Nothing is handed back at all, which is what separates it from the case above. */
	ctx = test_ctx();
	memset(&res, 0, sizeof(res));
	res.present = GetConnectivityParametersResponse_PR_connectivityParametersError;
	res.choice.connectivityParametersError = ConnectivityParametersError_parametersNotAvailable;
	euicc_stub_queue_asn1(&asn_DEF_GetConnectivityParametersResponse, &res);

	p = ipa_es10b_get_connectivity_params(ctx);
	assert_single_request(TAG_GET_CONNECTIVITY);
	assert(p == NULL);
	printf("   parametersNotAvailable     -> no result\n");
	free_ctx(ctx);

	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_OCTET_STRING, &hp);
}

/* SGP.32 section 5.9.15.  Renamed from EnableUsingDD in v1.1, and the request gained a mandatory
 * refreshFlag -- mandatory, so it is on the wire for both values, not omitted when false. */
static void immediate_enable_test(void)
{
	static const struct {
		long result;
		const char *name;
	} cases[] = {
		{ ImmediateEnableResponse__immediateEnableResult_ok, "ok" },
		{ ImmediateEnableResponse__immediateEnableResult_immediateEnableNotAvailable,
		  "immediateEnableNotAvailable" },
		{ ImmediateEnableResponse__immediateEnableResult_noSessionContext, "noSessionContext" },
		{ ImmediateEnableResponse__immediateEnableResult_catBusy, "catBusy" },
		{ ImmediateEnableResponse__immediateEnableResult_undefinedError, "undefinedError" },
	};
	/* BOOLEAN TRUE and FALSE as DER, under the implicit context tag [0] the schema gives refreshFlag. */
	static const uint8_t refresh_true[] = { 0x80, 0x01, 0xff };
	static const uint8_t refresh_false[] = { 0x80, 0x01, 0x00 };
	unsigned int i;
	struct ipa_context *ctx;
	ImmediateEnableResponse_t res = { 0 };
	int rc;

	printf("== immediate_enable_test ==\n");

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		ctx = test_ctx();
		memset(&res, 0, sizeof(res));
		res.immediateEnableResult = cases[i].result;
		euicc_stub_queue_asn1(&asn_DEF_ImmediateEnableResponse, &res);

		rc = ipa_es10b_immediate_enable(ctx, true);
		assert_single_request(TAG_IMMEDIATE_ENABLE);
		assert(rc == cases[i].result);
		if (cases[i].result == ImmediateEnableResponse__immediateEnableResult_ok)
			assert(ctx->nvstate.state_change_cause == IPA_STATE_CHANGE_IMMEDIATE_ENABLE_PROFILE);
		printf("   %-28s -> reported as itself\n", cases[i].name);
		free_ctx(ctx);
	}

	/* The v1.1 addition: refreshFlag is mandatory, so both values reach the card. */
	ctx = test_ctx();
	memset(&res, 0, sizeof(res));
	euicc_stub_queue_asn1(&asn_DEF_ImmediateEnableResponse, &res);
	ipa_es10b_immediate_enable(ctx, true);
	assert(request_contains(refresh_true, sizeof(refresh_true)));
	printf("   refreshFlag true             -> on the wire\n");
	free_ctx(ctx);

	ctx = test_ctx();
	euicc_stub_queue_asn1(&asn_DEF_ImmediateEnableResponse, &res);
	ipa_es10b_immediate_enable(ctx, false);
	assert(request_contains(refresh_false, sizeof(refresh_false)));
	printf("   refreshFlag false            -> on the wire, not omitted\n");
	free_ctx(ctx);
}

/* SGP.32 section 5.9.17.  The request carries the immediate-enable flag and, when configuring it on, the
 * default SM-DP+ OID and address the eUICC is to use. */
static void cfg_immediate_enable_test(void)
{
	static const struct {
		long result;
		const char *name;
	} cases[] = {
		{ ConfigureImmediateProfileEnablingResponse__configImmediateEnableResult_ok, "ok" },
		{ ConfigureImmediateProfileEnablingResponse__configImmediateEnableResult_insufficientMemory,
		  "insufficientMemory" },
		{ ConfigureImmediateProfileEnablingResponse__configImmediateEnableResult_associatedEimAlreadyExists,
		  "associatedEimAlreadyExists" },
		{ ConfigureImmediateProfileEnablingResponse__configImmediateEnableResult_undefinedError,
		  "undefinedError" },
	};
	static const char smdp_address[] = "smdp.example.com";
	unsigned int i;
	struct ipa_context *ctx;
	ConfigureImmediateProfileEnablingResponse_t res = { 0 };
	int rc;

	printf("== cfg_immediate_enable_test ==\n");

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		ctx = test_ctx();
		memset(&res, 0, sizeof(res));
		res.configImmediateEnableResult = cases[i].result;
		euicc_stub_queue_asn1(&asn_DEF_ConfigureImmediateProfileEnablingResponse, &res);

		rc = ipa_es10b_cfg_immediate_enable(ctx, true, "1.3.6.1.4.1.1", smdp_address);
		assert_single_request(TAG_CFG_IMMEDIATE_EN);
		assert(rc == cases[i].result);
		printf("   %-28s -> reported as itself\n", cases[i].name);
		free_ctx(ctx);
	}

	/* The address travels verbatim; it is the eUICC that has to reach it later. */
	ctx = test_ctx();
	memset(&res, 0, sizeof(res));
	euicc_stub_queue_asn1(&asn_DEF_ConfigureImmediateProfileEnablingResponse, &res);
	ipa_es10b_cfg_immediate_enable(ctx, true, "1.3.6.1.4.1.1", smdp_address);
	assert(request_contains((const uint8_t *)smdp_address, strlen(smdp_address)));
	printf("   smdp_address                 -> on the wire verbatim\n");
	free_ctx(ctx);
}

/* A card that stops answering has to fail every one of them, rather than be read as a result.  This is
 * the path a queued response cannot reach. */
static void transport_failure_test(void)
{
	struct ipa_context *ctx = test_ctx();

	printf("== transport_failure_test ==\n");
	euicc_stub_set_offline(true);

	assert(ipa_es10b_enable_emergency_profile(ctx, true) < 0);
	assert(ipa_es10b_disable_emergency_profile(ctx, true) < 0);
	assert(ipa_es10b_get_connectivity_params(ctx) == NULL);
	assert(ipa_es10b_immediate_enable(ctx, true) < 0);
	assert(ipa_es10b_cfg_immediate_enable(ctx, true, "1.3.6.1.4.1.1", "smdp.example.com") < 0);
	printf("   card offline               -> all five fail rather than report a result\n");

	euicc_stub_set_offline(false);
	free_ctx(ctx);
}

int main(int argc, char **argv)
{
	(void)argc;
	(void)argv;

	enable_emergency_profile_test();
	disable_emergency_profile_test();
	get_connectivity_params_test();
	immediate_enable_test();
	cfg_immediate_enable_test();
	transport_failure_test();

	printf("es10b_functions_test: all checks passed\n");
	return 0;
}

/* Stubs: this test never reaches the eIM. */
void *ipa_http_init(const char *cabundle, bool no_verif) { (void)cabundle; (void)no_verif; return NULL; }
struct ipa_buf *ipa_http_req(void *c, const struct ipa_buf *r, const char *u)
{ (void)c; (void)r; (void)u; return NULL; }
struct ipa_buf *ipa_http_req_with_ct(void *c, const struct ipa_buf *r, const char *u, const char *ct)
{ (void)c; (void)r; (void)u; (void)ct; return NULL; }
long ipa_http_last_status(void *c) { (void)c; return 0; }
void ipa_http_close(void *c) { (void)c; }
void ipa_http_free(void *c) { (void)c; }
