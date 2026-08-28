/*
 * Copyright (c) 2026 Onomondo ApS & sysmocom - s.f.m.c. GmbH & Iapyx Informatica Ltda. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * The lookup helpers over a decoded ES10c.GetProfilesInfo result: the Emergency Profile predicate
 * that GSMA SGP.32 section 2.11.2.2 gates an eUICC data request on, and the Fallback Profile lookup
 * over the fallbackAttribute of section 4.4.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <stdbool.h>
#include <onomondo/ipa/mem.h>
#include <onomondo/ipa/utils.h>
#include "src/ipa/libipa/length.h"
#include "src/ipa/libipa/es10c_get_prfle_info.h"

static const uint8_t ICCID_A[IPA_LEN_ICCID] = { 0x98, 0x10, 0, 0, 0, 0, 0, 0, 0, 0x1a };
static const uint8_t ICCID_B[IPA_LEN_ICCID] = { 0x98, 0x10, 0, 0, 0, 0, 0, 0, 0, 0x2b };

/* One Profile. ecall == -1 leaves ecallIndication absent, the way a consumer eUICC sends it. */
/* IPA_CALLOC rather than calloc: what these fixtures build is handed to ASN_STRUCT_FREE, whose FREEMEM
 * is IPA_FREE.  Under -DMEM_EMIT_DEBUG that pair keeps a byte counter with an assert on it, so an
 * allocation the counter never saw becomes an abort at free time rather than a leak. */
static struct SGP32_ProfileInfo *profile(const uint8_t *iccid, long state, int ecall)
{
	struct SGP32_ProfileInfo *p = IPA_CALLOC(1, sizeof(*p));

	assert(p);
	p->iccid = IPA_CALLOC(1, sizeof(*p->iccid));
	assert(p->iccid);
	assert(OCTET_STRING_fromBuf(p->iccid, (const char *)iccid, IPA_LEN_ICCID) == 0);
	p->profileState = IPA_CALLOC(1, sizeof(*p->profileState));
	assert(p->profileState);
	*p->profileState = state;
	if (ecall >= 0) {
		p->ecallIndication = IPA_CALLOC(1, sizeof(*p->ecallIndication));
		assert(p->ecallIndication);
		*p->ecallIndication = ecall;
	}
	return p;
}

/* Tag a Profile as the Fallback Profile, or (fallback == 0) carry the flag set to FALSE, which SGP.32
 * section 4.4 makes the same thing as not carrying it: the field is DEFAULT FALSE. */
static struct SGP32_ProfileInfo *with_fallback(struct SGP32_ProfileInfo *p, int fallback)
{
	p->fallbackAttribute = IPA_CALLOC(1, sizeof(*p->fallbackAttribute));
	assert(p->fallbackAttribute);
	*p->fallbackAttribute = fallback;
	return p;
}

static struct ipa_es10c_get_prfle_info_res *result_of(struct SGP32_ProfileInfo **profiles, int count)
{
	struct ipa_es10c_get_prfle_info_res *res = IPA_CALLOC(1, sizeof(*res));
	int i;

	assert(res);
	res->sgp32_res = IPA_CALLOC(1, sizeof(*res->sgp32_res));
	assert(res->sgp32_res);
	res->sgp32_res->present = SGP32_ProfileInfoListResponse_PR_profileInfoListOk;
	for (i = 0; i < count; i++)
		ASN_SEQUENCE_ADD(&res->sgp32_res->choice.profileInfoListOk.list, profiles[i]);
	return res;
}

/* SGP.32 section 4.4 marks the Emergency Profile with ecallIndication; section 2.11.2.2 refuses an
 * IpaEuiccDataRequest with ecallActive only while that Profile is *enabled*. */
static void ecall_profile_enabled_test(void)
{
	struct SGP32_ProfileInfo *p[2];
	struct ipa_es10c_get_prfle_info_res *res;

	printf("== ecall_profile_enabled_test ==\n");

	/* Nothing carries the indication: a consumer eUICC never sends it at all. */
	p[0] = profile(ICCID_A, ProfileState_enabled, -1);
	p[1] = profile(ICCID_B, ProfileState_disabled, -1);
	res = result_of(p, 2);
	assert(ipa_es10c_ecall_prfle_enabled(res) == false);
	printf("   no ecallIndication anywhere      -> false\n");
	ipa_es10c_get_prfle_info_res_free(res);

	/* Present but disabled: the Profile exists, the mechanism is not active, so requests proceed. */
	p[0] = profile(ICCID_A, ProfileState_enabled, -1);
	p[1] = profile(ICCID_B, ProfileState_disabled, 1);
	res = result_of(p, 2);
	assert(ipa_es10c_ecall_prfle_enabled(res) == false);
	printf("   Emergency Profile disabled       -> false\n");
	ipa_es10c_get_prfle_info_res_free(res);

	/* Present and enabled: this is the state that gates the refusal. */
	p[0] = profile(ICCID_A, ProfileState_disabled, -1);
	p[1] = profile(ICCID_B, ProfileState_enabled, 1);
	res = result_of(p, 2);
	assert(ipa_es10c_ecall_prfle_enabled(res) == true);
	printf("   Emergency Profile enabled        -> true\n");
	ipa_es10c_get_prfle_info_res_free(res);

	/* Present-and-false is not the same as present: BOOLEAN, not NULL. */
	p[0] = profile(ICCID_A, ProfileState_enabled, 0);
	res = result_of(p, 1);
	assert(ipa_es10c_ecall_prfle_enabled(res) == false);
	printf("   ecallIndication present but FALSE -> false\n");
	ipa_es10c_get_prfle_info_res_free(res);

	/* An enabled ordinary Profile alongside a disabled Emergency one must not be mistaken for it. */
	p[0] = profile(ICCID_A, ProfileState_enabled, 0);
	p[1] = profile(ICCID_B, ProfileState_disabled, 1);
	res = result_of(p, 2);
	assert(ipa_es10c_ecall_prfle_enabled(res) == false);
	printf("   enabled ordinary + disabled eCall -> false\n");
	ipa_es10c_get_prfle_info_res_free(res);
}

/* The helper is reached on paths where the eUICC may not have answered at all. */

/* SGP.32 section 4.4 marks the Fallback Profile with fallbackAttribute (tag '9F26') and forbids more
 * than one Profile carrying it.  The flag was decoded but never read by anything, so nothing could
 * answer "which Profile would ipa_execute_fallback() swap to". */
static void fallback_profile_test(void)
{
	struct SGP32_ProfileInfo *p[2];
	struct ipa_es10c_get_prfle_info_res *res;
	const struct SGP32_ProfileInfo *found;

	printf("== fallback_profile_test ==\n");

	/* Absent on both, which is what a consumer eUICC always sends. */
	p[0] = profile(ICCID_A, ProfileState_enabled, -1);
	p[1] = profile(ICCID_B, ProfileState_disabled, -1);
	res = result_of(p, 2);
	assert(ipa_es10c_fallback_prfle(res) == NULL);
	printf("   attribute absent everywhere      -> none\n");
	ipa_es10c_get_prfle_info_res_free(res);

	/* Present but FALSE is the same answer as absent. */
	p[0] = with_fallback(profile(ICCID_A, ProfileState_enabled, -1), 0);
	p[1] = with_fallback(profile(ICCID_B, ProfileState_disabled, -1), 0);
	res = result_of(p, 2);
	assert(ipa_es10c_fallback_prfle(res) == NULL);
	printf("   attribute present but false      -> none\n");
	ipa_es10c_get_prfle_info_res_free(res);

	/* The one that matters: the tagged Profile is found, and it is not simply the first in the list. */
	p[0] = with_fallback(profile(ICCID_A, ProfileState_enabled, -1), 0);
	p[1] = with_fallback(profile(ICCID_B, ProfileState_disabled, -1), 1);
	res = result_of(p, 2);
	found = ipa_es10c_fallback_prfle(res);
	assert(found && found->iccid && found->iccid->size == IPA_LEN_ICCID);
	assert(memcmp(found->iccid->buf, ICCID_B, IPA_LEN_ICCID) == 0);
	printf("   second profile tagged            -> that one, not the first\n");
	ipa_es10c_get_prfle_info_res_free(res);

	/* A disabled Fallback Profile is the normal case -- it is what fallback swaps *to* -- so the
	 * profile state must not filter the answer the way it does for the Emergency Profile. */
	p[0] = with_fallback(profile(ICCID_A, ProfileState_disabled, -1), 1);
	res = result_of(p, 1);
	found = ipa_es10c_fallback_prfle(res);
	assert(found && memcmp(found->iccid->buf, ICCID_A, IPA_LEN_ICCID) == 0);
	printf("   tagged profile disabled          -> still found\n");
	ipa_es10c_get_prfle_info_res_free(res);
}

static void degenerate_input_test(void)
{
	struct ipa_es10c_get_prfle_info_res res = { 0 };
	struct ipa_es10c_get_prfle_info_res *empty;
	struct SGP32_ProfileInfo *p[1];

	printf("== degenerate_input_test ==\n");

	assert(ipa_es10c_ecall_prfle_enabled(NULL) == false);
	assert(ipa_es10c_fallback_prfle(NULL) == NULL);
	printf("   NULL result                      -> false\n");

	/* Decoded, but the eUICC returned the error arm rather than a list. */
	assert(ipa_es10c_ecall_prfle_enabled(&res) == false);
	assert(ipa_es10c_fallback_prfle(&res) == NULL);
	printf("   no sgp32_res                     -> false\n");

	res.sgp32_res = IPA_CALLOC(1, sizeof(*res.sgp32_res));
	assert(res.sgp32_res);
	res.sgp32_res->present = SGP32_ProfileInfoListResponse_PR_profileInfoListError;
	assert(ipa_es10c_ecall_prfle_enabled(&res) == false);
	assert(ipa_es10c_fallback_prfle(&res) == NULL);
	printf("   profileInfoListError arm         -> false\n");

	/* An empty list is a valid answer from an eUICC with no Profiles installed. */
	p[0] = NULL;
	empty = result_of(p, 0);
	assert(ipa_es10c_ecall_prfle_enabled(empty) == false);
	assert(ipa_es10c_fallback_prfle(empty) == NULL);
	printf("   empty profile list               -> false\n");
	ipa_es10c_get_prfle_info_res_free(empty);

	/* res is on the stack, so only the arm built above is released here.  The library helper cannot
	 * be used for that: it frees the containing struct too. */
	ASN_STRUCT_FREE(asn_DEF_SGP32_ProfileInfoListResponse, res.sgp32_res);
}

int main(int argc, char **argv)
{
	(void)argc;
	(void)argv;

	ecall_profile_enabled_test();
	fallback_profile_test();
	degenerate_input_test();
	printf("profile_info_test: all checks passed\n");
	return 0;
}

/* Stubs: this test never reaches the eUICC or the eIM. */
void *ipa_http_init(const char *cabundle, bool no_verif) { (void)cabundle; (void)no_verif; return NULL; }
struct ipa_buf *ipa_http_req(void *c, const struct ipa_buf *r, const char *u) { (void)c; (void)r; (void)u; return NULL; }
void ipa_http_close(void *c) { (void)c; }
void ipa_http_free(void *c) { (void)c; }
void *ipa_scard_init(unsigned int n) { (void)n; return NULL; }
int ipa_scard_reset(void *c) { (void)c; return 0; }
int ipa_scard_atr(void *c, struct ipa_buf *a) { (void)c; (void)a; return 0; }
int ipa_scard_transceive(void *c, struct ipa_buf *res, const struct ipa_buf *req) { (void)c; (void)res; (void)req; return 0; }
int ipa_scard_free(void *c) { (void)c; return 0; }
