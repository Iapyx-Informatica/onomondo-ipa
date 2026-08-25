/*
 * Copyright (c) 2026 Onomondo ApS & sysmocom - s.f.m.c. GmbH & Iapyx Informatica Ltda. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * The lookup helpers over a decoded ES10c.GetProfilesInfo result, in particular the Emergency Profile
 * predicate that GSMA SGP.32 section 2.11.2.2 gates an eUICC data request on.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <stdbool.h>
#include <onomondo/ipa/utils.h>
#include "src/ipa/libipa/length.h"
#include "src/ipa/libipa/es10c_get_prfle_info.h"

static const uint8_t ICCID_A[IPA_LEN_ICCID] = { 0x98, 0x10, 0, 0, 0, 0, 0, 0, 0, 0x1a };
static const uint8_t ICCID_B[IPA_LEN_ICCID] = { 0x98, 0x10, 0, 0, 0, 0, 0, 0, 0, 0x2b };

/* One Profile. ecall == -1 leaves ecallIndication absent, the way a consumer eUICC sends it. */
static struct SGP32_ProfileInfo *profile(const uint8_t *iccid, long state, int ecall)
{
	struct SGP32_ProfileInfo *p = calloc(1, sizeof(*p));

	assert(p);
	p->iccid = calloc(1, sizeof(*p->iccid));
	assert(p->iccid);
	assert(OCTET_STRING_fromBuf(p->iccid, (const char *)iccid, IPA_LEN_ICCID) == 0);
	p->profileState = calloc(1, sizeof(*p->profileState));
	assert(p->profileState);
	*p->profileState = state;
	if (ecall >= 0) {
		p->ecallIndication = calloc(1, sizeof(*p->ecallIndication));
		assert(p->ecallIndication);
		*p->ecallIndication = ecall;
	}
	return p;
}

static struct ipa_es10c_get_prfle_info_res *result_of(struct SGP32_ProfileInfo **profiles, int count)
{
	struct ipa_es10c_get_prfle_info_res *res = calloc(1, sizeof(*res));
	int i;

	assert(res);
	res->sgp32_res = calloc(1, sizeof(*res->sgp32_res));
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

	/* Present but disabled: the Profile exists, the mechanism is not active, so requests proceed. */
	p[0] = profile(ICCID_A, ProfileState_enabled, -1);
	p[1] = profile(ICCID_B, ProfileState_disabled, 1);
	res = result_of(p, 2);
	assert(ipa_es10c_ecall_prfle_enabled(res) == false);
	printf("   Emergency Profile disabled       -> false\n");

	/* Present and enabled: this is the state that gates the refusal. */
	p[0] = profile(ICCID_A, ProfileState_disabled, -1);
	p[1] = profile(ICCID_B, ProfileState_enabled, 1);
	res = result_of(p, 2);
	assert(ipa_es10c_ecall_prfle_enabled(res) == true);
	printf("   Emergency Profile enabled        -> true\n");

	/* Present-and-false is not the same as present: BOOLEAN, not NULL. */
	p[0] = profile(ICCID_A, ProfileState_enabled, 0);
	res = result_of(p, 1);
	assert(ipa_es10c_ecall_prfle_enabled(res) == false);
	printf("   ecallIndication present but FALSE -> false\n");

	/* An enabled ordinary Profile alongside a disabled Emergency one must not be mistaken for it. */
	p[0] = profile(ICCID_A, ProfileState_enabled, 0);
	p[1] = profile(ICCID_B, ProfileState_disabled, 1);
	res = result_of(p, 2);
	assert(ipa_es10c_ecall_prfle_enabled(res) == false);
	printf("   enabled ordinary + disabled eCall -> false\n");
}

/* The helper is reached on paths where the eUICC may not have answered at all. */
static void degenerate_input_test(void)
{
	struct ipa_es10c_get_prfle_info_res res = { 0 };
	struct ipa_es10c_get_prfle_info_res *empty;
	struct SGP32_ProfileInfo *p[1];

	printf("== degenerate_input_test ==\n");

	assert(ipa_es10c_ecall_prfle_enabled(NULL) == false);
	printf("   NULL result                      -> false\n");

	/* Decoded, but the eUICC returned the error arm rather than a list. */
	assert(ipa_es10c_ecall_prfle_enabled(&res) == false);
	printf("   no sgp32_res                     -> false\n");

	res.sgp32_res = calloc(1, sizeof(*res.sgp32_res));
	assert(res.sgp32_res);
	res.sgp32_res->present = SGP32_ProfileInfoListResponse_PR_profileInfoListError;
	assert(ipa_es10c_ecall_prfle_enabled(&res) == false);
	printf("   profileInfoListError arm         -> false\n");

	/* An empty list is a valid answer from an eUICC with no Profiles installed. */
	p[0] = NULL;
	empty = result_of(p, 0);
	assert(ipa_es10c_ecall_prfle_enabled(empty) == false);
	printf("   empty profile list               -> false\n");
}

int main(int argc, char **argv)
{
	(void)argc;
	(void)argv;

	ecall_profile_enabled_test();
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
