/*
 * Copyright (c) 2026 Onomondo ApS & sysmocom - s.f.m.c. GmbH & Iapyx Informatica Ltda. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * The IoT eUICC emulation paths, driven through the real stack against the fake eUICC in
 * tests/stubs.  These paths exist so a consumer (SGP.22) eUICC can stand in for an IoT (SGP.32) one,
 * which means most of what they do is libipa translating between the two -- exactly the part that a
 * stub placed any higher would have replaced instead of exercised.
 *
 * Covered here: ES10b SetDefaultDpAddress and the setDefaultDpAddress PSMO (SGP.32 sections 5.9.25
 * and 2.11.1.1.3), and the Fallback Mechanism (sections 5.9.20, 5.9.21, 3.4.6, 3.4.7).
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <stdbool.h>
#include <onomondo/ipa/utils.h>
#include <onomondo/ipa/ipad.h>
#include <onomondo/ipa/scard.h>
#include <SetDefaultDpAddressResponse.h>
#include <SGP32-SetDefaultDpAddressRequest.h>
#include <SGP32-SetDefaultDpAddressResponse.h>
#include <ProfileInfoListResponse.h>
#include <EnableProfileResponse.h>
#include <ExecuteFallbackMechanismResponse.h>
#include <ReturnFromFallbackResponse.h>
#include <EuiccResultData.h>
#include <Psmo.h>
#include "src/ipa/libipa/context.h"
#include "src/ipa/libipa/length.h"
#include "src/ipa/libipa/es10b_set_default_dp_addr.h"
#include "src/ipa/libipa/es10b_execute_fallback.h"
#include "src/ipa/libipa/es10b_return_from_fallback.h"
#include "tests/stubs/euicc_stub.h"

/* Not declared in a header: the PSMO handlers are reached from the dispatch in the same file. */
struct EuiccResultData *iot_emo_do_setDefaultDpAddress_psmo(struct ipa_context *ctx,
							    const struct SGP32_SetDefaultDpAddressRequest *psmo);

/* ES10x request tags we expect to see on the wire. */
#define TAG_SET_DEFAULT_DP_SGP22 0xBF3F	/* SGP.22 [63], what a consumer eUICC understands */
#define TAG_SET_DEFAULT_DP_SGP32 0xBF65	/* SGP.32 [101], what a real IoT eUICC understands */
#define TAG_GET_PROFILES_INFO 0xBF2D
#define TAG_ENABLE_PROFILE 0xBF31

static const uint8_t ICCID_OP[IPA_LEN_ICCID] = { 0x98, 0x10, 0, 0, 0, 0, 0, 0, 0, 0x1a };
static const uint8_t ICCID_FB[IPA_LEN_ICCID] = { 0x98, 0x10, 0, 0, 0, 0, 0, 0, 0, 0x2b };

static struct ipa_config cfg;

static struct ipa_context *emu_ctx(void)
{
	struct ipa_context *ctx;

	memset(&cfg, 0, sizeof(cfg));
	cfg.iot_euicc_emu_enabled = true;
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

/* Queue an SGP.22 SetDefaultDpAddressResponse, which is what the emulation branch decodes. */
static void queue_set_default_dp_res(long result)
{
	SetDefaultDpAddressResponse_t res = { 0 };

	res.setDefaultDpAddressResult = result;
	euicc_stub_queue_asn1(&asn_DEF_SetDefaultDpAddressResponse, &res);
}

/* Queue a GetProfilesInfo answer holding two profiles with the given states. */
static void queue_profiles(long state_op, long state_fb)
{
	ProfileInfoListResponse_t res = { 0 };
	struct ProfileInfo *p;
	const uint8_t *iccids[2] = { ICCID_OP, ICCID_FB };
	long states[2] = { state_op, state_fb };
	int i;

	res.present = ProfileInfoListResponse_PR_profileInfoListOk;
	for (i = 0; i < 2; i++) {
		p = calloc(1, sizeof(*p));
		assert(p);
		p->iccid = calloc(1, sizeof(*p->iccid));
		assert(p->iccid);
		assert(OCTET_STRING_fromBuf(p->iccid, (const char *)iccids[i], IPA_LEN_ICCID) == 0);
		p->profileState = calloc(1, sizeof(*p->profileState));
		assert(p->profileState);
		*p->profileState = states[i];
		ASN_SEQUENCE_ADD(&res.choice.profileInfoListOk.list, p);
	}
	euicc_stub_queue_asn1(&asn_DEF_ProfileInfoListResponse, &res);
	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_ProfileInfoListResponse, &res);
}

static void queue_enable_profile_res(long result)
{
	EnableProfileResponse_t res = { 0 };

	res.enableResult = result;
	euicc_stub_queue_asn1(&asn_DEF_EnableProfileResponse, &res);
}

/* SGP.32 5.9.25: a consumer eUICC only knows the SGP.22 form of this function, so the emulation
 * must send BF3F and not the SGP.32 BF65 the real path uses. */
static void set_default_dp_addr_emu_test(void)
{
	struct ipa_context *ctx = emu_ctx();

	printf("== set_default_dp_addr_emu_test ==\n");

	queue_set_default_dp_res(SetDefaultDpAddressResponse__setDefaultDpAddressResult_ok);
	assert(ipa_es10b_set_default_dp_addr(ctx, "smdp.example.com") == 0);
	assert(euicc_stub_requests() == 1);
	assert(euicc_stub_request_has_tag(0, TAG_SET_DEFAULT_DP_SGP22));
	assert(!euicc_stub_request_has_tag(0, TAG_SET_DEFAULT_DP_SGP32));
	printf("   ok:            %s\n", ipa_hexdump(euicc_stub_request(0, NULL), 8));

	/* The FQDN has to survive into the request; a length or pointer slip here would be invisible
	 * to the eUICC-status check above. */
	{
		size_t len;
		const uint8_t *req = euicc_stub_request(0, &len);

		assert(memmem(req, len, "smdp.example.com", 16));
	}

	/* An eUICC error status is passed through, not swallowed. */
	euicc_stub_reset();
	queue_set_default_dp_res(SetDefaultDpAddressResponse__setDefaultDpAddressResult_undefinedError);
	assert(ipa_es10b_set_default_dp_addr(ctx, "smdp.example.com") ==
	       SetDefaultDpAddressResponse__setDefaultDpAddressResult_undefinedError);

	/* A dead card is a negative return, distinct from any eUICC status. */
	euicc_stub_reset();
	euicc_stub_set_offline(true);
	assert(ipa_es10b_set_default_dp_addr(ctx, "smdp.example.com") < 0);
	euicc_stub_set_offline(false);

	/* No address at all is refused before anything reaches the card. */
	euicc_stub_reset();
	assert(ipa_es10b_set_default_dp_addr(ctx, NULL) < 0);
	assert(euicc_stub_requests() == 0);

	free_ctx(ctx);
}

/* SGP.32 2.11.1.1.3: the same function reached as a PSMO inside an eUICC Package. */
static void set_default_dp_addr_psmo_test(void)
{
	static const char *fqdn = "smdp.example.com";
	struct ipa_context *ctx = emu_ctx();
	struct SGP32_SetDefaultDpAddressRequest psmo = { 0 };
	struct EuiccResultData *r;

	printf("== set_default_dp_addr_psmo_test ==\n");

	/* The PSMO carries a UTF8String that is not NUL-terminated. */
	psmo.defaultDpAddress.buf = (uint8_t *)fqdn;
	psmo.defaultDpAddress.size = strlen(fqdn);

	queue_set_default_dp_res(SetDefaultDpAddressResponse__setDefaultDpAddressResult_ok);
	r = iot_emo_do_setDefaultDpAddress_psmo(ctx, &psmo);
	assert(r->present == EuiccResultData_PR_setDefaultDpAddressResult);
	assert(r->choice.setDefaultDpAddressResult.setDefaultDpAddressResult ==
	       SGP32_SetDefaultDpAddressResponse__setDefaultDpAddressResult_ok);
	assert(euicc_stub_request_has_tag(0, TAG_SET_DEFAULT_DP_SGP22));
	{
		size_t len;
		const uint8_t *req = euicc_stub_request(0, &len);

		assert(memmem(req, len, fqdn, strlen(fqdn)));
	}
	ASN_STRUCT_FREE(asn_DEF_EuiccResultData, r);
	printf("   ok -> setDefaultDpAddressResult ok\n");

	/* Both result sets are ok(0) / undefinedError(127), so a status passes straight through. */
	euicc_stub_reset();
	queue_set_default_dp_res(SetDefaultDpAddressResponse__setDefaultDpAddressResult_undefinedError);
	r = iot_emo_do_setDefaultDpAddress_psmo(ctx, &psmo);
	assert(r->choice.setDefaultDpAddressResult.setDefaultDpAddressResult ==
	       SGP32_SetDefaultDpAddressResponse__setDefaultDpAddressResult_undefinedError);
	ASN_STRUCT_FREE(asn_DEF_EuiccResultData, r);

	/* A transport failure has no eUICC status to report, so it becomes undefinedError. */
	euicc_stub_reset();
	euicc_stub_set_offline(true);
	r = iot_emo_do_setDefaultDpAddress_psmo(ctx, &psmo);
	assert(r->choice.setDefaultDpAddressResult.setDefaultDpAddressResult ==
	       SGP32_SetDefaultDpAddressResponse__setDefaultDpAddressResult_undefinedError);
	ASN_STRUCT_FREE(asn_DEF_EuiccResultData, r);
	euicc_stub_set_offline(false);
	printf("   undefinedError and transport failure both -> undefinedError\n");

	free_ctx(ctx);
}

/* SGP.32 5.9.20 / 5.9.21 against a consumer eUICC: the Fallback Profile is whichever ICCID the
 * setFallbackAttribute PSMO recorded, and the swap is one ES10c EnableProfile. */
static void fallback_emu_test(void)
{
	struct ipa_context *ctx = emu_ctx();

	printf("== fallback_emu_test ==\n");

	/* Nothing carries the Fallback Attribute yet: refused without touching the card. */
	assert(ipa_es10b_execute_fallback(ctx, false) ==
	       ExecuteFallbackMechanismResponse__executeFallbackMechanismResult_fallbackNotAvailable);
	assert(euicc_stub_requests() == 0);
	printf("   no fallback profile     -> fallbackNotAvailable, no APDU\n");

	/* Pretend the PSMO ran. */
	memcpy(ctx->nvstate.iot_euicc_emu.fallback_iccid, ICCID_FB, IPA_LEN_ICCID);

	/* Nothing enabled: there is nothing to fall back from. */
	euicc_stub_reset();
	queue_profiles(ProfileState_disabled, ProfileState_disabled);
	assert(ipa_es10b_execute_fallback(ctx, false) ==
	       ExecuteFallbackMechanismResponse__executeFallbackMechanismResult_commandError);
	assert(euicc_stub_request_has_tag(0, TAG_GET_PROFILES_INFO));
	assert(euicc_stub_requests() == 1);	/* looked, did not enable */
	printf("   nothing enabled         -> commandError, no enable\n");

	/* The Fallback Profile is already the enabled one. */
	euicc_stub_reset();
	queue_profiles(ProfileState_disabled, ProfileState_enabled);
	assert(ipa_es10b_execute_fallback(ctx, false) ==
	       ExecuteFallbackMechanismResponse__executeFallbackMechanismResult_profileNotInDisabledState);
	assert(euicc_stub_requests() == 1);
	printf("   fallback already on     -> profileNotInDisabledState\n");

	/* The happy path: look, then enable the Fallback Profile by ICCID. */
	euicc_stub_reset();
	queue_profiles(ProfileState_enabled, ProfileState_disabled);
	queue_enable_profile_res(EnableProfileResponse__enableResult_ok);
	assert(ipa_es10b_execute_fallback(ctx, false) ==
	       ExecuteFallbackMechanismResponse__executeFallbackMechanismResult_ok);
	assert(euicc_stub_requests() == 2);
	assert(euicc_stub_request_has_tag(0, TAG_GET_PROFILES_INFO));
	assert(euicc_stub_request_has_tag(1, TAG_ENABLE_PROFILE));
	{	/* the ICCID enabled must be the Fallback Profile's, not the operational one's */
		size_t len;
		const uint8_t *req = euicc_stub_request(1, &len);

		assert(memmem(req, len, ICCID_FB, IPA_LEN_ICCID));
		assert(!memmem(req, len, ICCID_OP, IPA_LEN_ICCID));
	}
	/* And the profile that was displaced is remembered, so ReturnFromFallback can undo it. */
	assert(memcmp(ctx->nvstate.iot_euicc_emu.pre_fallback_iccid, ICCID_OP, IPA_LEN_ICCID) == 0);
	printf("   happy path              -> ok, enabled the fallback ICCID\n");

	/* Coming back re-enables what was displaced. */
	euicc_stub_reset();
	queue_profiles(ProfileState_disabled, ProfileState_enabled);
	queue_enable_profile_res(EnableProfileResponse__enableResult_ok);
	assert(ipa_es10b_return_from_fallback(ctx, false) ==
	       ReturnFromFallbackResponse__returnFromFallbackResult_ok);
	{
		size_t len;
		const uint8_t *req = euicc_stub_request(1, &len);

		assert(memmem(req, len, ICCID_OP, IPA_LEN_ICCID));
	}
	printf("   return from fallback    -> ok, re-enabled the displaced ICCID\n");

	/* Returning again: the Fallback Profile is no longer the enabled one. */
	euicc_stub_reset();
	queue_profiles(ProfileState_enabled, ProfileState_disabled);
	assert(ipa_es10b_return_from_fallback(ctx, false) ==
	       ReturnFromFallbackResponse__returnFromFallbackResult_fallbackNotAvailable);
	printf("   return again            -> fallbackNotAvailable\n");

	free_ctx(ctx);
}

int main(int argc, char **argv)
{
	(void)argc;
	(void)argv;

	set_default_dp_addr_emu_test();
	set_default_dp_addr_psmo_test();
	fallback_emu_test();

	printf("euicc_emu_test: all checks passed\n");
	return 0;
}

/* Stubs: this test never reaches the eIM. */
void *ipa_http_init(const char *cabundle, bool no_verif) { (void)cabundle; (void)no_verif; return NULL; }
struct ipa_buf *ipa_http_req(void *c, const struct ipa_buf *r, const char *u)
{ (void)c; (void)r; (void)u; return NULL; }
struct ipa_buf *ipa_http_req_with_ct(void *c, const struct ipa_buf *r, const char *u, const char *ct)
{ (void)c; (void)r; (void)u; (void)ct; return NULL; }
void ipa_http_close(void *c) { (void)c; }
void ipa_http_free(void *c) { (void)c; }
