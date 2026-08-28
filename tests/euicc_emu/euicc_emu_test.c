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
 * and 2.11.1.1.3), the Fallback Mechanism (sections 5.9.20, 5.9.21, 3.4.6, 3.4.7), and the error
 * codes AddInitialEim reports for a rejected eIM Configuration Data entry (section 5.9.4).
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <onomondo/ipa/utils.h>
#include <onomondo/ipa/ipad.h>
#include <onomondo/ipa/scard.h>
#include <SetDefaultDpAddressResponse.h>
#include <SGP32-SetDefaultDpAddressRequest.h>
#include <SGP32-SetDefaultDpAddressResponse.h>
#include <ProfileInfoListResponse.h>
#include <EsipaMessageFromEimToIpa.h>
#include <EnableProfileResponse.h>
#include <ImmediateEnableResponse.h>
#include <ConfigureImmediateProfileEnablingResponse.h>
#include <ExecuteFallbackMechanismResponse.h>
#include <ReturnFromFallbackResponse.h>
#include <EuiccResultData.h>
#include <EUICCInfo2.h>
#include <Psmo.h>
#include "src/ipa/libipa/context.h"
#include "src/ipa/libipa/length.h"
#include "src/ipa/libipa/es10b_set_default_dp_addr.h"
#include "src/ipa/libipa/es10b_execute_fallback.h"
#include "src/ipa/libipa/es10b_return_from_fallback.h"
#include "src/ipa/libipa/es10b_add_init_eim.h"
#include "src/ipa/libipa/es10b_load_euicc_pkg.h"
#include "src/ipa/libipa/proc_euicc_pkg_dwnld_exec.h"
#include "src/ipa/libipa/es10b_prfle_rollback.h"
#include "src/ipa/libipa/es10b_immediate_enable.h"
#include "src/ipa/libipa/es10b_cfg_immediate_enable.h"
#include "tests/stubs/euicc_stub.h"

/* Not declared in a header: the PSMO handlers are reached from the dispatch in the same file. */
struct EuiccResultData *iot_emo_do_setDefaultDpAddress_psmo(struct ipa_context *ctx,
							    const struct SGP32_SetDefaultDpAddressRequest *psmo);
struct ipa_es10b_load_euicc_pkg_res *load_euicc_pkg_iot_emu(struct ipa_context *ctx,
							    const struct ipa_es10b_load_euicc_pkg_req *req);

/* ES10x request tags we expect to see on the wire. */
#define TAG_SET_DEFAULT_DP_SGP22 0xBF3F	/* SGP.22 [63], what a consumer eUICC understands */
#define TAG_SET_DEFAULT_DP_SGP32 0xBF65	/* SGP.32 [101], what a real IoT eUICC understands */
#define TAG_GET_PROFILES_INFO 0xBF2D
#define TAG_ENABLE_PROFILE 0xBF31
#define TAG_GET_EUICC_INFO2 0xBF22

static const uint8_t ICCID_OP[IPA_LEN_ICCID] = { 0x98, 0x10, 0, 0, 0, 0, 0, 0, 0, 0x1a };
static const uint8_t ICCID_FB[IPA_LEN_ICCID] = { 0x98, 0x10, 0, 0, 0, 0, 0, 0, 0, 0x2b };

static struct ipa_config cfg;

static uint8_t eim_enc_buf[2048];
static size_t eim_enc_len;

/* ipa_free_ctx() releases these strings with IPA_FREE, and the library fills them in with
 * IPA_STR_FROM_ASN (IPA_ALLOC_N underneath).  strdup() would allocate outside that accounting and be
 * freed inside it, which drives the -DMEM_EMIT_DEBUG=ON counter negative. */
static char *test_strdup(const char *s)
{
	char *copy = IPA_ALLOC_N(strlen(s) + 1);

	assert(copy);
	strcpy(copy, s);
	return copy;
}

static int eim_enc_sink(const void *b, size_t sz, void *k)
{
	(void)k;
	assert(eim_enc_len + sz <= sizeof(eim_enc_buf));
	memcpy(eim_enc_buf + eim_enc_len, b, sz);
	eim_enc_len += sz;
	return 0;
}

/* One canned eIM response, handed to the next ESipa request and then forgotten. */
static struct ipa_buf *eim_response;

static void queue_eim_response(const struct EsipaMessageFromEimToIpa *msg)
{
	asn_enc_rval_t er;

	eim_enc_len = 0;
	er = der_encode(&asn_DEF_EsipaMessageFromEimToIpa, (void *)msg, eim_enc_sink, NULL);
	assert(er.encoded > 0);
	ipa_buf_free(eim_response);
	eim_response = ipa_buf_alloc_data(eim_enc_len, eim_enc_buf);
}

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
		/* IPA_* allocators throughout: every fixture here is released through the asn1c free
		 * functions, whose FREEMEM is IPA_FREE (asn_internal.h).  Allocating outside that
		 * accounting and freeing inside it drives the -DMEM_EMIT_DEBUG=ON counter negative. */
		p = IPA_CALLOC(1, sizeof(*p));
		assert(p);
		p->iccid = IPA_CALLOC(1, sizeof(*p->iccid));
		assert(p->iccid);
		assert(OCTET_STRING_fromBuf(p->iccid, (const char *)iccids[i], IPA_LEN_ICCID) == 0);
		p->profileState = IPA_CALLOC(1, sizeof(*p->profileState));
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

/* Queue an SGP.22 EUICCInfo2 carrying the given euiccCiPKIdListForSigning.  Under emulation
 * ipa_es10b_get_euicc_info() reads this form and derives the SGP.32 one from it, so this is where
 * the CI Public Key Identifiers that section 5.9.4 checks against come from. */
static void queue_euicc_info2(const uint8_t *const *ci_pk_ids, const size_t *ci_pk_id_lens, int count)
{
	EUICCInfo2_t res = { 0 };
	SubjectKeyIdentifier_t *id;
	static const uint8_t version[3] = { 0x02, 0x02, 0x00 };
	static const uint8_t empty[1] = { 0 };
	int i;

	/* The mandatory members have to be set for der_encode() to succeed; only the signing list matters
	 * to the code under test, the rest just has to be structurally sound. */
	assert(OCTET_STRING_fromBuf(&res.profileVersion, (const char *)version, sizeof(version)) == 0);
	assert(OCTET_STRING_fromBuf(&res.svn, (const char *)version, sizeof(version)) == 0);
	assert(OCTET_STRING_fromBuf(&res.euiccFirmwareVer, (const char *)version, sizeof(version)) == 0);
	assert(OCTET_STRING_fromBuf(&res.extCardResource, (const char *)empty, sizeof(empty)) == 0);
	assert(OCTET_STRING_fromBuf(&res.ppVersion, (const char *)version, sizeof(version)) == 0);
	assert(OCTET_STRING_fromBuf(&res.sasAcreditationNumber, "TEST", 4) == 0);
	res.uiccCapability.buf = IPA_CALLOC(1, 1);
	assert(res.uiccCapability.buf);
	res.uiccCapability.size = 1;
	res.uiccCapability.bits_unused = 7;
	res.rspCapability.buf = IPA_CALLOC(1, 1);
	assert(res.rspCapability.buf);
	res.rspCapability.size = 1;
	res.rspCapability.bits_unused = 7;

	for (i = 0; i < count; i++) {
		id = IPA_CALLOC(1, sizeof(*id));
		assert(id);
		assert(OCTET_STRING_fromBuf(id, (const char *)ci_pk_ids[i], (int)ci_pk_id_lens[i]) == 0);
		ASN_SEQUENCE_ADD(&res.euiccCiPKIdListForSigning.list, id);
	}

	euicc_stub_queue_asn1(&asn_DEF_EUICCInfo2, &res);
	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_EUICCInfo2, &res);
}

/* Build a one-entry AddInitialEimRequest holding everything section 5.9.4 makes mandatory. */
static struct AddInitialEimRequest *add_init_eim_req(long counter_value, const uint8_t *ci_pk_id,
						     size_t ci_pk_id_len)
{
	static const uint8_t oid_ec_public_key[] = { 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 };
	struct AddInitialEimRequest *req = IPA_CALLOC(1, sizeof(*req));
	struct EimConfigurationData *cfg_eim = IPA_CALLOC(1, sizeof(*cfg_eim));
	struct EimConfigurationData__eimPublicKeyData *pk = IPA_CALLOC(1, sizeof(*pk));

	assert(req && cfg_eim && pk);
	assert(OCTET_STRING_fromBuf(&cfg_eim->eimId, "eim.example.com", 15) == 0);
	cfg_eim->counterValue = IPA_CALLOC(1, sizeof(*cfg_eim->counterValue));
	assert(cfg_eim->counterValue);
	*cfg_eim->counterValue = counter_value;

	/* The OID is an OBJECT IDENTIFIER, not an OCTET STRING, so it is filled in by hand.  It has to be
	 * set at all because validate_eim_cfg() runs asn_check_constraints() over the whole entry. */
	pk->present = EimConfigurationData__eimPublicKeyData_PR_eimPublicKey;
	pk->choice.eimPublicKey.algorithm.algorithm.buf = IPA_ALLOC_N(sizeof(oid_ec_public_key));
	assert(pk->choice.eimPublicKey.algorithm.algorithm.buf);
	memcpy(pk->choice.eimPublicKey.algorithm.algorithm.buf, oid_ec_public_key, sizeof(oid_ec_public_key));
	pk->choice.eimPublicKey.algorithm.algorithm.size = sizeof(oid_ec_public_key);
	pk->choice.eimPublicKey.subjectPublicKey.buf = IPA_CALLOC(1, 1);
	assert(pk->choice.eimPublicKey.subjectPublicKey.buf);
	pk->choice.eimPublicKey.subjectPublicKey.size = 1;
	cfg_eim->eimPublicKeyData = pk;

	if (ci_pk_id) {
		cfg_eim->euiccCiPKId = OCTET_STRING_new_fromBuf(&asn_DEF_SubjectKeyIdentifier,
								(const char *)ci_pk_id, (int)ci_pk_id_len);
		assert(cfg_eim->euiccCiPKId);
	}

	ASN_SEQUENCE_ADD(&req->eimConfigurationDataList.list, cfg_eim);
	return req;
}

/* Run AddInitialEim against the emulation and report the error code it put in the response. */
static long add_init_eim_err(struct ipa_context *ctx, struct AddInitialEimRequest *req)
{
	struct ipa_es10b_add_init_eim_req wrapped = { 0 };
	struct ipa_es10b_add_init_eim_res *res;
	long err;

	wrapped.req = *req;
	res = ipa_es10b_add_init_eim(ctx, &wrapped);
	assert(res && res->res);
	err = res->res->present == AddInitialEimResponse_PR_addInitialEimError ?
	      res->res->choice.addInitialEimError : 0;
	ipa_es10b_add_init_eim_res_free(res);
	return err;
}

/* SGP.32 5.9.4 names a distinct error code per rejected sub-field.  Reporting undefinedError instead
 * tells the eIM only that something went wrong, not what to correct, so the codes are worth pinning
 * all the way out to the response the eIM would see. */
static void add_init_eim_errors_test(void)
{
	struct ipa_context *ctx;
	struct AddInitialEimRequest *req;
	static const uint8_t known[] = { 0xde, 0xad, 0xbe, 0xef };
	static const uint8_t unknown[] = { 0xba, 0xdc, 0x0f, 0xfe };
	const uint8_t *ids[] = { known };
	const size_t id_lens[] = { sizeof(known) };

	printf("== add_init_eim_errors_test ==\n");

	/* A euiccCiPKId the eUICC can actually sign for is stored, and the eIM configuration lands. */
	ctx = emu_ctx();
	queue_euicc_info2(ids, id_lens, 1);
	req = add_init_eim_req(1, known, sizeof(known));
	assert(add_init_eim_err(ctx, req) == 0);
	assert(euicc_stub_request_has_tag(0, TAG_GET_EUICC_INFO2));
	assert(ctx->nvstate.iot_euicc_emu.eim_cfg_ber != NULL);
	ASN_STRUCT_FREE(asn_DEF_AddInitialEimRequest, req);
	printf("   known euiccCiPKId       -> accepted\n");
	free_ctx(ctx);

	/* One that is not in euiccCiPKIdListForSigning is refused with ciPKUnknown, and nothing is stored:
	 * "in case of any error [...] the command SHALL [...] leave the eIM Configuration Data in their
	 * original state prior to function execution." */
	ctx = emu_ctx();
	queue_euicc_info2(ids, id_lens, 1);
	req = add_init_eim_req(1, unknown, sizeof(unknown));
	assert(add_init_eim_err(ctx, req) == AddInitialEimResponse__addInitialEimError_ciPKUnknown);
	assert(ctx->nvstate.iot_euicc_emu.eim_cfg_ber == NULL);
	ASN_STRUCT_FREE(asn_DEF_AddInitialEimRequest, req);
	printf("   unknown euiccCiPKId     -> ciPKUnknown, nothing stored\n");
	free_ctx(ctx);

	/* A counterValue above the mandated minimum ceiling gets its own code, not undefinedError. */
	ctx = emu_ctx();
	queue_euicc_info2(ids, id_lens, 1);
	req = add_init_eim_req(8388608, known, sizeof(known));
	assert(add_init_eim_err(ctx, req) ==
	       AddInitialEimResponse__addInitialEimError_counterValueOutOfRange);
	assert(ctx->nvstate.iot_euicc_emu.eim_cfg_ber == NULL);
	ASN_STRUCT_FREE(asn_DEF_AddInitialEimRequest, req);
	printf("   counterValue too large  -> counterValueOutOfRange, nothing stored\n");
	free_ctx(ctx);

	/* When the eUICC cannot be asked for its list there is nothing to check against, so a supplied
	 * identifier is stored rather than rejected on a guess. */
	ctx = emu_ctx();
	euicc_stub_set_offline(true);
	req = add_init_eim_req(1, unknown, sizeof(unknown));
	assert(add_init_eim_err(ctx, req) == 0);
	assert(ctx->nvstate.iot_euicc_emu.eim_cfg_ber != NULL);
	ASN_STRUCT_FREE(asn_DEF_AddInitialEimRequest, req);
	euicc_stub_set_offline(false);
	printf("   list unreadable         -> accepted unchecked\n");
	free_ctx(ctx);
}


/* SGP.32 section 2.11.2: "If it was included in the signed eUICC Package, the eUICC SHALL include the
 * same eimTransactionId in the signed eUICC Package Result and also euiccPackageErrorUnsigned and
 * euiccPackageErrorSigned in case of errors."  Under the emulation this code is the eUICC, so the
 * obligation lands here.  The success branch always honoured it; the error branch did not, which left
 * a failed eUICC Package as the one outcome the eIM could not match to the package it sent.
 *
 * Both branches are checked, because the point is that they agree. */
static void euicc_pkg_result_transaction_id_test(void)
{
	static const uint8_t tid_bytes[] = { 0xa1, 0xb2, 0xc3, 0xd4 };
	struct ipa_context *ctx = emu_ctx();
	struct ipa_es10b_load_euicc_pkg_req req;
	struct ipa_es10b_load_euicc_pkg_res *res;
	TransactionId_t tid = { 0 };
	const TransactionId_t *echoed;

	printf("== euicc_pkg_result_transaction_id_test ==\n");

	/* Both result branches stamp the eIM's own id into what they build, which ipa_init() would have
	 * taken from the eIM Configuration Data on the eUICC.  Nothing here reads it back; it just has to
	 * be there. */
	ctx->eim_id = test_strdup("eim.example.com");
	assert(ctx->eim_id);

	assert(OCTET_STRING_fromBuf(&tid, (const char *)tid_bytes, sizeof(tid_bytes)) == 0);

	/* The error branch: an eUICC Package that is neither a psmoList nor an ecoList cannot be
	 * executed, which is the failure that produces euiccPackageErrorUnsigned. */
	memset(&req, 0, sizeof(req));
	req.req.euiccPackageSigned.eimTransactionId = &tid;
	req.req.euiccPackageSigned.euiccPackage.present = EuiccPackage_PR_NOTHING;
	res = load_euicc_pkg_iot_emu(ctx, &req);
	assert(res && res->res);
	assert(res->res->present == EuiccPackageResult_PR_euiccPackageErrorUnsigned);
	echoed = res->res->choice.euiccPackageErrorUnsigned.eimTransactionId;
	assert(echoed && echoed->size == sizeof(tid_bytes));
	assert(memcmp(echoed->buf, tid_bytes, sizeof(tid_bytes)) == 0);
	printf("   euiccPackageErrorUnsigned    -> eimTransactionId echoed\n");
	ipa_es10b_load_euicc_pkg_res_free(res);

	/* An eIM that sent none must not have one invented for it: the field is OPTIONAL and the rule is
	 * conditional on the package having carried one. */
	memset(&req, 0, sizeof(req));
	req.req.euiccPackageSigned.euiccPackage.present = EuiccPackage_PR_NOTHING;
	res = load_euicc_pkg_iot_emu(ctx, &req);
	assert(res && res->res);
	assert(res->res->present == EuiccPackageResult_PR_euiccPackageErrorUnsigned);
	assert(res->res->choice.euiccPackageErrorUnsigned.eimTransactionId == NULL);
	printf("   package without one          -> none invented\n");
	ipa_es10b_load_euicc_pkg_res_free(res);

	/* The success branch, for comparison: an empty ecoList executes trivially. */
	memset(&req, 0, sizeof(req));
	req.req.euiccPackageSigned.eimTransactionId = &tid;
	req.req.euiccPackageSigned.euiccPackage.present = EuiccPackage_PR_ecoList;
	res = load_euicc_pkg_iot_emu(ctx, &req);
	assert(res && res->res);
	assert(res->res->present == EuiccPackageResult_PR_euiccPackageResultSigned);
	echoed = res->res->choice.euiccPackageResultSigned.euiccPackageResultDataSigned.eimTransactionId;
	assert(echoed && echoed->size == sizeof(tid_bytes));
	assert(memcmp(echoed->buf, tid_bytes, sizeof(tid_bytes)) == 0);
	printf("   euiccPackageResultSigned     -> eimTransactionId echoed\n");
	ipa_es10b_load_euicc_pkg_res_free(res);

	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_TransactionId, &tid);
	free_ctx(ctx);
}


/* ipa_get_fallback_profile() answers "which Profile would ipa_execute_fallback() swap to".  A real IoT
 * eUICC says so in the Profile Metadata (fallbackAttribute, section 4.4); a consumer eUICC has nowhere
 * to keep that, so under the emulation the answer comes from nvstate instead.  This exercises the
 * second path -- the first is covered by profile_info_test, which can build a Profile list carrying the
 * attribute that this stub eUICC will never produce. */
static void fallback_profile_query_emu_test(void)
{
	struct ipa_context *ctx = emu_ctx();
	uint8_t iccid[IPA_LEN_ICCID];

	printf("== fallback_profile_query_emu_test ==\n");

	queue_profiles(ProfileState_enabled, ProfileState_disabled);
	assert(ipa_get_fallback_profile(ctx, iccid) == -ENOENT);
	printf("   no fallback profile set  -> -ENOENT\n");

	memcpy(ctx->nvstate.iot_euicc_emu.fallback_iccid, ICCID_FB, IPA_LEN_ICCID);
	queue_profiles(ProfileState_enabled, ProfileState_disabled);
	assert(ipa_get_fallback_profile(ctx, iccid) == 0);
	assert(memcmp(iccid, ICCID_FB, IPA_LEN_ICCID) == 0);
	printf("   emulation nvstate record -> that ICCID\n");

	assert(ipa_get_fallback_profile(ctx, NULL) == -EINVAL);
	assert(ipa_get_fallback_profile(NULL, iccid) == -EINVAL);
	printf("   NULL arguments           -> -EINVAL\n");

	free_ctx(ctx);
}


/* SGP.32 section 5.14.6 has the eIM discard an eUICC Package Result whose sequence number is not
 * greater than the one it expects, and then raise its expectation to what it received.  The emulation
 * used to send a constant 0, so every result after the first was discarded on that check alone --
 * separately from, and in addition to, the unsignable euiccSignEPR placeholder.
 *
 * The number is this library's own, though, and section 5.9.12's RemoveNotificationFromList would read
 * it as naming a Notification the consumer eUICC actually holds.  Both halves are checked here. */
static void euicc_pkg_seq_number_test(void)
{
	struct ipa_context *ctx = emu_ctx();
	struct ipa_es10b_load_euicc_pkg_req req;
	struct ipa_es10b_load_euicc_pkg_res *res;
	long first, second;

	printf("== euicc_pkg_seq_number_test ==\n");
	ctx->eim_id = test_strdup("eim.example.com");
	assert(ctx->eim_id);

	memset(&req, 0, sizeof(req));
	req.req.euiccPackageSigned.euiccPackage.present = EuiccPackage_PR_ecoList;

	res = load_euicc_pkg_iot_emu(ctx, &req);
	assert(res && res->res && res->res->present == EuiccPackageResult_PR_euiccPackageResultSigned);
	first = res->res->choice.euiccPackageResultSigned.euiccPackageResultDataSigned.seqNumber;
	ipa_es10b_load_euicc_pkg_res_free(res);

	res = load_euicc_pkg_iot_emu(ctx, &req);
	assert(res && res->res);
	second = res->res->choice.euiccPackageResultSigned.euiccPackageResultDataSigned.seqNumber;
	ipa_es10b_load_euicc_pkg_res_free(res);

	/* Greater than the previous one is the whole requirement; that it also starts above zero keeps the
	 * first result from being discarded by an eIM whose expectation starts there. */
	assert(first > 0);
	assert(second > first);
	printf("   two packages in a row    -> sequence numbers %ld then %ld\n", first, second);

	/* Persisted, because a restart that walked it backwards would have the eIM discard again. */
	assert(ctx->nvstate.iot_euicc_emu.epr_seq_number == (uint32_t)second);
	printf("   counter kept in nvstate  -> survives a restart\n");

	free_ctx(ctx);
}

/* The other half: that synthesised number must never reach the card.  ES10b.RemoveNotificationFromList
 * (tag 'BF30') addresses the consumer eUICC's own Notification list, where the number would name an
 * unrelated real Notification -- possibly one still waiting to be delivered. */
static void euicc_pkg_no_spurious_removal_test(void)
{
	struct ipa_context *ctx = emu_ctx();
	struct ipa_proc_eucc_pkg_dwnld_exec_res exec_res = { 0 };
	struct EsipaMessageFromEimToIpa msg = { 0 };
	struct ipa_es10b_load_euicc_pkg_req req;
	long *ack;
	long seq;
	unsigned int i;

	printf("== euicc_pkg_no_spurious_removal_test ==\n");
	ctx->eim_id = test_strdup("eim.example.com");
	assert(ctx->eim_id);

	memset(&req, 0, sizeof(req));
	req.req.euiccPackageSigned.euiccPackage.present = EuiccPackage_PR_ecoList;
	exec_res.load_euicc_pkg_res = load_euicc_pkg_iot_emu(ctx, &req);
	assert(exec_res.load_euicc_pkg_res && exec_res.load_euicc_pkg_res->res);
	seq = exec_res.load_euicc_pkg_res->res->choice.euiccPackageResultSigned.
	    euiccPackageResultDataSigned.seqNumber;

	/* The eIM acknowledges the result by its sequence number, as section 3.1.1.1 step 8 has it do. */
	msg.present = EsipaMessageFromEimToIpa_PR_provideEimPackageResultResponse;
	msg.choice.provideEimPackageResultResponse.present =
	    ProvideEimPackageResultResponse_PR_eimAcknowledgements;
	ack = IPA_CALLOC(1, sizeof(*ack));
	assert(ack);
	*ack = seq;
	ASN_SEQUENCE_ADD(&msg.choice.provideEimPackageResultResponse.choice.eimAcknowledgements.list, ack);
	queue_eim_response(&msg);

	euicc_stub_reset();
	ipa_proc_eucc_pkg_dwnld_exec_onset(ctx, &exec_res);

	for (i = 0; i < euicc_stub_requests(); i++)
		assert(!euicc_stub_request_has_tag(i, 0xBF30));
	printf("   eIM acknowledged seq %-3ld -> no RemoveNotificationFromList reached the card\n", seq);

	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_EsipaMessageFromEimToIpa, &msg);
	/* exec_res itself is on the stack here, so only its members are freed -- not
	 * ipa_proc_eucc_pkg_dwnld_exec_res_free(), which would free the struct too. */
	ipa_es10b_prfle_rollback_res_free(exec_res.prfle_rollback_res);
	ipa_es10b_load_euicc_pkg_res_free(exec_res.load_euicc_pkg_res);
	free_ctx(ctx);
}


/* SGP.32 section 5.9.17, emulation branch.  A consumer eUICC has nowhere to keep an immediate-enable
 * configuration, so the emulation keeps it in nvstate and answers without touching the card at all --
 * which is the first thing worth asserting, since a version that did talk to the card would be sending
 * an ES10b function the card does not implement. */
static void cfg_immediate_enable_emu_test(void)
{
	static const char smdp_address[] = "smdp.example.com";
	struct ipa_context *ctx = emu_ctx();
	int rc;

	printf("== cfg_immediate_enable_emu_test ==\n");

	rc = ipa_es10b_cfg_immediate_enable(ctx, true, "1.3.6.1.4.1.1", smdp_address);
	assert(rc == ConfigureImmediateProfileEnablingResponse__configImmediateEnableResult_ok);
	assert(euicc_stub_requests() == 0);
	assert(ctx->nvstate.iot_euicc_emu.immediate_enable.flag == true);
	assert(ctx->nvstate.iot_euicc_emu.immediate_enable.smdp_oid);
	assert(ctx->nvstate.iot_euicc_emu.immediate_enable.smdp_address);
	assert(ctx->nvstate.iot_euicc_emu.immediate_enable.smdp_address->len == strlen(smdp_address));
	assert(!memcmp(ctx->nvstate.iot_euicc_emu.immediate_enable.smdp_address->data, smdp_address,
		       strlen(smdp_address)));
	printf("   configured               -> kept in nvstate, no ES10x traffic\n");

	/* Turning it off keeps the addresses but clears the flag, which is what immediate_enable_emu()
	 * checks first. */
	rc = ipa_es10b_cfg_immediate_enable(ctx, false, NULL, NULL);
	assert(rc == ConfigureImmediateProfileEnablingResponse__configImmediateEnableResult_ok);
	assert(ctx->nvstate.iot_euicc_emu.immediate_enable.flag == false);
	printf("   turned off               -> flag cleared\n");

	/* An eUICC that already has eIM configuration data refuses: section 5.9.17 gives that its own
	 * code, added in v1.1. */
	ctx->nvstate.iot_euicc_emu.eim_cfg_ber = ipa_buf_alloc_data(2, (uint8_t *)"\x01\x02");
	assert(ctx->nvstate.iot_euicc_emu.eim_cfg_ber);
	rc = ipa_es10b_cfg_immediate_enable(ctx, true, "1.3.6.1.4.1.1", smdp_address);
	assert(rc ==
	       ConfigureImmediateProfileEnablingResponse__configImmediateEnableResult_associatedEimAlreadyExists);
	printf("   eIM config already there -> associatedEimAlreadyExists\n");

	free_ctx(ctx);
}

/* SGP.32 section 5.9.15, emulation branch.  Here the emulation is doing the eUICC's job: it checks the
 * configuration against the session the download left behind, and only then enables the profile through
 * the consumer ES10c function.  None of that runs against a real IoT eUICC. */
static void immediate_enable_emu_test(void)
{
	static const uint8_t aid[] = { 0xa0, 0x00, 0x00, 0x05, 0x59, 0x10, 0x10 };
	static const char smdp_address[] = "smdp.example.com";
	struct ipa_context *ctx;
	int rc;

	printf("== immediate_enable_emu_test ==\n");

	/* Never configured: nothing to enable against. */
	ctx = emu_ctx();
	rc = ipa_es10b_immediate_enable(ctx, true);
	assert(rc == ImmediateEnableResponse__immediateEnableResult_immediateEnableNotAvailable);
	assert(euicc_stub_requests() == 0);
	printf("   not configured           -> immediateEnableNotAvailable, card untouched\n");
	free_ctx(ctx);

	/* Configured, but no download session left anything behind to enable. */
	ctx = emu_ctx();
	assert(ipa_es10b_cfg_immediate_enable(ctx, true, "1.3.6.1.4.1.1", smdp_address) == 0);
	rc = ipa_es10b_immediate_enable(ctx, true);
	assert(rc == ImmediateEnableResponse__immediateEnableResult_noSessionContext);
	printf("   no session context       -> noSessionContext\n");
	free_ctx(ctx);

	/* Configured, session present, everything agrees: the profile is enabled through ES10c. */
	ctx = emu_ctx();
	assert(ipa_es10b_cfg_immediate_enable(ctx, true, "1.3.6.1.4.1.1", smdp_address) == 0);
	ctx->iot_euicc_emu.immediate_enable.smdp_oid =
	    ipa_buf_alloc_and_cpy(ctx->nvstate.iot_euicc_emu.immediate_enable.smdp_oid->data,
				  ctx->nvstate.iot_euicc_emu.immediate_enable.smdp_oid->len);
	ctx->iot_euicc_emu.immediate_enable.smdp_address =
	    ipa_buf_alloc_data(strlen(smdp_address), (uint8_t *)smdp_address);
	ctx->iot_euicc_emu.immediate_enable.profile_aid = ipa_buf_alloc_data(sizeof(aid), (uint8_t *)aid);
	euicc_stub_reset();
	queue_enable_profile_res(EnableProfileResponse__enableResult_ok);

	rc = ipa_es10b_immediate_enable(ctx, true);
	assert(rc == ImmediateEnableResponse__immediateEnableResult_ok);
	assert(euicc_stub_request_has_tag(0, TAG_ENABLE_PROFILE));
	assert(ctx->nvstate.state_change_cause == IPA_STATE_CHANGE_IMMEDIATE_ENABLE_PROFILE);
	/* The session is one-shot: whatever the outcome, it must not be reusable. */
	assert(ctx->iot_euicc_emu.immediate_enable.smdp_oid == NULL);
	assert(ctx->iot_euicc_emu.immediate_enable.smdp_address == NULL);
	assert(ctx->iot_euicc_emu.immediate_enable.profile_aid == NULL);
	printf("   session matches          -> ES10c EnableProfile sent, session consumed\n");
	free_ctx(ctx);

	/* The check that makes the rest of it worth doing: a session naming a different SM-DP+ than the one
	 * configured must not enable anything.  Same length as the configured address on purpose, so it is
	 * the comparison of the bytes that has to catch this and not the length check in front of it. */
	ctx = emu_ctx();
	assert(ipa_es10b_cfg_immediate_enable(ctx, true, "1.3.6.1.4.1.1", smdp_address) == 0);
	ctx->iot_euicc_emu.immediate_enable.smdp_oid =
	    ipa_buf_alloc_and_cpy(ctx->nvstate.iot_euicc_emu.immediate_enable.smdp_oid->data,
				  ctx->nvstate.iot_euicc_emu.immediate_enable.smdp_oid->len);
	ctx->iot_euicc_emu.immediate_enable.smdp_address =
	    ipa_buf_alloc_data(strlen("smdq.example.com"), (uint8_t *)"smdq.example.com");
	ctx->iot_euicc_emu.immediate_enable.profile_aid = ipa_buf_alloc_data(sizeof(aid), (uint8_t *)aid);
	euicc_stub_reset();

	rc = ipa_es10b_immediate_enable(ctx, true);
	assert(rc == ImmediateEnableResponse__immediateEnableResult_immediateEnableNotAvailable);
	assert(euicc_stub_requests() == 0);
	printf("   session names another SM-DP+ -> refused, nothing enabled\n");
	free_ctx(ctx);
}

int main(int argc, char **argv)
{
	(void)argc;
	(void)argv;

	set_default_dp_addr_emu_test();
	set_default_dp_addr_psmo_test();
	fallback_emu_test();
	add_init_eim_errors_test();
	euicc_pkg_result_transaction_id_test();
	fallback_profile_query_emu_test();
	euicc_pkg_seq_number_test();
	euicc_pkg_no_spurious_removal_test();
	cfg_immediate_enable_emu_test();
	immediate_enable_emu_test();

	printf("euicc_emu_test: all checks passed\n");
	return 0;
}

/* Stubs: the eIM answers only what a case queued with queue_eim_response(), and fails otherwise. */
void *ipa_http_init(const char *cabundle, bool no_verif) { (void)cabundle; (void)no_verif; return (void *)1; }
struct ipa_buf *ipa_http_req(void *c, const struct ipa_buf *r, const char *u)
{ (void)c; (void)r; (void)u; return NULL; }
struct ipa_buf *ipa_http_req_with_ct(void *c, const struct ipa_buf *r, const char *u, const char *ct)
{
	struct ipa_buf *res = eim_response;

	(void)c; (void)r; (void)u; (void)ct;
	eim_response = NULL;
	return res;
}
long ipa_http_last_status(void *c) { (void)c; return 200; }
void ipa_http_close(void *c) { (void)c; }
void ipa_http_free(void *c) { (void)c; }
