/*
 * Copyright (c) 2026 Onomondo ApS & sysmocom - s.f.m.c. GmbH & Iapyx Informatica Ltda. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * The cases below follow the worked example of GSMA SGP.22, section 2.9.2.1 and the two decision trees of
 * section 2.9.2.4 (figures 5 and 6).
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <stdbool.h>
#include <onomondo/ipa/utils.h>
#include "src/ipa/libipa/ppr.h"

/* mccMnc for MCC 246 / MNC 81, coded as in 3GPP TS 24.008 (SGP.22, section 2.4a.1.2). */
static uint8_t mcc_mnc_a[3] = { 0x42, 0xf6, 0x18 };
/* A different operator: MCC 262 / MNC 01. */
static uint8_t mcc_mnc_b[3] = { 0x62, 0xf2, 0x10 };
/* The "any operator" wildcard. */
static uint8_t mcc_mnc_any[3] = { 0xee, 0xee, 0xee };
/* Only the last MNC digit wildcarded, so it covers mcc_mnc_a but not mcc_mnc_b. */
static uint8_t mcc_mnc_a_partial[3] = { 0x42, 0xf6, 0x1e };

static uint8_t gid_1[2] = { 0x01, 0x02 };
static uint8_t gid_2[2] = { 0x03, 0x04 };

/*
 * Fixture bookkeeping.
 *
 * The cases below build their fixtures inline inside the assertions, which is what makes a table of
 * matching rules readable -- and which leaves no name to free them by, so this file used to leak every
 * one of them.  Rather than lift a hundred allocations out into locals, each builder records the root
 * it produced and gives up the ones it absorbs, and every test releases what is left on the way out.
 *
 * Two rules make that work.  Ownership is tracked here, in the builders, because a fixture handed to
 * another builder becomes part of that tree and must not be freed twice -- the same OperatorId_t is
 * given to more than one rule below.  And every fixture owns its bytes: the builders copy their
 * inputs, since the arrays they are called with are static and asn1c's free functions would otherwise
 * be handed a pointer to file-scope storage.
 */
static struct {
	asn_TYPE_descriptor_t *def;
	void *obj;
} fixtures[256];
static unsigned int fixture_count;

static void *track(asn_TYPE_descriptor_t *def, void *obj)
{
	assert(fixture_count < sizeof(fixtures) / sizeof(fixtures[0]));
	fixtures[fixture_count].def = def;
	fixtures[fixture_count].obj = obj;
	fixture_count++;
	return obj;
}

/* obj now belongs to another fixture, which will free it. */
static void untrack(const void *obj)
{
	unsigned int i;

	if (!obj)
		return;
	for (i = 0; i < fixture_count; i++) {
		if (fixtures[i].obj == obj) {
			fixtures[i] = fixtures[--fixture_count];
			return;
		}
	}
	assert(!"untracking a fixture that was never tracked");
}

static void free_fixtures(void)
{
	while (fixture_count--)
		ASN_STRUCT_FREE(*fixtures[fixture_count].def, fixtures[fixture_count].obj);
	fixture_count = 0;
}

static OCTET_STRING_t *octet_string(uint8_t *buf, int size)
{
	OCTET_STRING_t *str = IPA_CALLOC(1, sizeof(*str));

	assert(str);
	if (size > 0) {
		str->buf = IPA_ALLOC_N(size);
		assert(str->buf);
		memcpy(str->buf, buf, size);
	}
	str->size = size;
	return track(&asn_DEF_OCTET_STRING, str);
}

static OperatorId_t *operator_id(uint8_t *mcc_mnc, OCTET_STRING_t *gid1, OCTET_STRING_t *gid2)
{
	OperatorId_t *op = IPA_CALLOC(1, sizeof(*op));

	assert(op);
	op->mccMnc.buf = IPA_ALLOC_N(3);
	assert(op->mccMnc.buf);
	memcpy(op->mccMnc.buf, mcc_mnc, 3);
	op->mccMnc.size = 3;
	op->gid1 = gid1;
	op->gid2 = gid2;
	untrack(gid1);
	untrack(gid2);
	return track(&asn_DEF_OperatorId, op);
}

/* A PprIds / pprFlags BIT STRING built from a bit mask, MSB first: bit 0 is 0x80 of the first byte. Only one byte
 * is ever needed for the rules this specification defines. */
static BIT_STRING_t *bit_string(uint8_t bits, int bits_unused)
{
	BIT_STRING_t *bs = IPA_CALLOC(1, sizeof(*bs));
	uint8_t *buf = IPA_CALLOC(1, 1);

	assert(bs && buf);
	buf[0] = bits;
	bs->buf = buf;
	bs->size = 1;
	bs->bits_unused = bits_unused;
	return track(&asn_DEF_BIT_STRING, bs);
}

#define BIT(n) (0x80 >> (n))

/* One PPAR: which rules it covers, who may use them, and whether consent is needed. The operators are passed as a
 * NULL terminated array. */
static ProfilePolicyAuthorisationRule_t *ppar(uint8_t ppr_bits, bool consent_required, OperatorId_t **operators)
{
	ProfilePolicyAuthorisationRule_t *rule = IPA_CALLOC(1, sizeof(*rule));
	BIT_STRING_t *ppr_ids = bit_string(ppr_bits, 5);
	BIT_STRING_t *flags = bit_string(consent_required ? BIT(0) : 0x00, 7);
	int i;

	assert(rule);
	/* Both members are values, not pointers, so the struct is copied and the two containers are done
	 * with -- but the bytes they point at now belong to the rule, so only the containers go. */
	rule->pprIds = *ppr_ids;
	rule->pprFlags = *flags;
	untrack(ppr_ids);
	untrack(flags);
	IPA_FREE(ppr_ids);
	IPA_FREE(flags);
	for (i = 0; operators[i]; i++) {
		ASN_SEQUENCE_ADD(&rule->allowedOperators.list, operators[i]);
		untrack(operators[i]);
	}

	return track(&asn_DEF_ProfilePolicyAuthorisationRule, rule);
}

static RulesAuthorisationTable_t *rat(ProfilePolicyAuthorisationRule_t **rules)
{
	RulesAuthorisationTable_t *table = IPA_CALLOC(1, sizeof(*table));
	int i;

	assert(table);
	for (i = 0; rules[i]; i++) {
		ASN_SEQUENCE_ADD(&table->list, rules[i]);
		untrack(rules[i]);
	}

	return track(&asn_DEF_RulesAuthorisationTable, table);
}

static void operator_matching_test(void)
{
	OperatorId_t *owner = operator_id(mcc_mnc_a, NULL, NULL);
	OperatorId_t *owner_gid = operator_id(mcc_mnc_a, octet_string(gid_1, 2), octet_string(gid_2, 2));

	/* Plain equality, and a different operator. */
	assert(ipa_ppr_operator_matches(operator_id(mcc_mnc_a, NULL, NULL), owner) == true);
	assert(ipa_ppr_operator_matches(operator_id(mcc_mnc_b, NULL, NULL), owner) == false);

	/* 'E' nibbles are wildcards, whole or partial. */
	assert(ipa_ppr_operator_matches(operator_id(mcc_mnc_any, NULL, NULL), owner) == true);
	assert(ipa_ppr_operator_matches(operator_id(mcc_mnc_a_partial, NULL, NULL), owner) == true);
	assert(ipa_ppr_operator_matches(operator_id(mcc_mnc_a_partial, NULL, NULL),
					operator_id(mcc_mnc_b, NULL, NULL)) == false);

	/* An omitted gid in the RAT matches only an absent gid on the profile owner. */
	assert(ipa_ppr_operator_matches(operator_id(mcc_mnc_a, NULL, NULL), owner_gid) == false);
	assert(ipa_ppr_operator_matches(operator_id(mcc_mnc_a, NULL, NULL), owner) == true);

	/* A present but empty gid in the RAT is a wildcard, and covers both. */
	assert(ipa_ppr_operator_matches(operator_id(mcc_mnc_a, octet_string(NULL, 0), octet_string(NULL, 0)),
					owner_gid) == true);
	assert(ipa_ppr_operator_matches(operator_id(mcc_mnc_a, octet_string(NULL, 0), octet_string(NULL, 0)),
					owner) == true);

	/* A present non-empty gid has to match exactly. */
	assert(ipa_ppr_operator_matches(operator_id(mcc_mnc_a, octet_string(gid_1, 2), octet_string(gid_2, 2)),
					owner_gid) == true);
	assert(ipa_ppr_operator_matches(operator_id(mcc_mnc_a, octet_string(gid_2, 2), octet_string(gid_2, 2)),
					owner_gid) == false);
	assert(ipa_ppr_operator_matches(operator_id(mcc_mnc_a, octet_string(gid_1, 1), octet_string(gid_2, 2)),
					owner_gid) == false);
	assert(ipa_ppr_operator_matches(operator_id(mcc_mnc_a, octet_string(gid_1, 2), octet_string(gid_2, 2)),
					owner) == false);

	/* The profile owner is what the RAT is compared against; without one nothing can match. */
	assert(ipa_ppr_operator_matches(operator_id(mcc_mnc_any, NULL, NULL), NULL) == false);

	free_fixtures();
}

static void no_ppr_test(void)
{
	struct ipa_ppr_consent consent = { .ppr1 = true, .ppr2 = true };

	/* No profilePolicyRules field at all, and a field with no rule set: nothing to authorise, and an empty RAT
	 * must not stand in the way. */
	assert(ipa_ppr_check_against_rat(NULL, NULL, NULL, &consent) == 0);
	assert(consent.ppr1 == false && consent.ppr2 == false);

	consent.ppr1 = consent.ppr2 = true;
	assert(ipa_ppr_check_against_rat(bit_string(0x00, 5), NULL, rat((ProfilePolicyAuthorisationRule_t *[]) { NULL }),
					 &consent) == 0);
	assert(consent.ppr1 == false && consent.ppr2 == false);

	/* pprUpdateControl has no meaning in StoreMetadata and is not a rule that needs authorising. */
	consent.ppr1 = consent.ppr2 = true;
	assert(ipa_ppr_check_against_rat(bit_string(BIT(PprIds_pprUpdateControl), 5), NULL, NULL, &consent) == 0);
	assert(consent.ppr1 == false && consent.ppr2 == false);

	free_fixtures();
}

static void ppr_authorisation_test(void)
{
	OperatorId_t *owner_a = operator_id(mcc_mnc_a, NULL, NULL);
	OperatorId_t *owner_b = operator_id(mcc_mnc_b, NULL, NULL);
	PprIds_t *ppr1 = bit_string(BIT(PprIds_ppr1), 5);
	PprIds_t *ppr2 = bit_string(BIT(PprIds_ppr2), 5);
	PprIds_t *ppr1_and_2 = bit_string(BIT(PprIds_ppr1) | BIT(PprIds_ppr2), 5);
	RulesAuthorisationTable_t *table;
	struct ipa_ppr_consent consent;

	/* "All PPRs forbidden for all Profile Owners" (SGP.22, section 2.9.2.2): an empty RAT. */
	table = rat((ProfilePolicyAuthorisationRule_t *[]) { NULL });
	assert(ipa_ppr_check_against_rat(ppr1, owner_a, table, &consent) == -EPERM);
	assert(ipa_ppr_check_against_rat(ppr2, owner_a, table, &consent) == -EPERM);

	/* A RAT the eUICC could not be asked for forbids everything as well. */
	assert(ipa_ppr_check_against_rat(ppr1, owner_a, NULL, &consent) == -EPERM);

	/* PPR1 for operator A only, no consent needed. */
	table = rat((ProfilePolicyAuthorisationRule_t *[]) {
		     ppar(BIT(PprIds_ppr1), false, (OperatorId_t *[]) { operator_id(mcc_mnc_a, NULL, NULL), NULL }),
		     NULL });
	assert(ipa_ppr_check_against_rat(ppr1, owner_a, table, &consent) == 0);
	assert(consent.ppr1 == false && consent.ppr2 == false);
	assert(ipa_ppr_check_against_rat(ppr1, owner_b, table, &consent) == -EPERM);
	/* The PPAR covers PPR1 only, so PPR2 stays forbidden -- for everyone. */
	assert(ipa_ppr_check_against_rat(ppr2, owner_a, table, &consent) == -EPERM);
	assert(ipa_ppr_check_against_rat(ppr1_and_2, owner_a, table, &consent) == -EPERM);

	/* "All PPRs allowed for all Profile Owners, End User Consent required". */
	table = rat((ProfilePolicyAuthorisationRule_t *[]) {
		     ppar(BIT(PprIds_ppr1) | BIT(PprIds_ppr2), true,
			  (OperatorId_t *[]) { operator_id(mcc_mnc_any, octet_string(NULL, 0), octet_string(NULL, 0)),
					       NULL }),
		     NULL });
	assert(ipa_ppr_check_against_rat(ppr1_and_2, owner_b, table, &consent) == 0);
	assert(consent.ppr1 == true && consent.ppr2 == true);

	/* The table of the worked example in section 2.9.2.1: PPR1 for A without consent, PPR2 for B without consent,
	 * both rules for anyone else with consent. The order matters -- the first PPAR that allows the owner decides
	 * whether consent is required. */
	table = rat((ProfilePolicyAuthorisationRule_t *[]) {
		     ppar(BIT(PprIds_ppr1), false, (OperatorId_t *[]) { operator_id(mcc_mnc_a, NULL, NULL), NULL }),
		     ppar(BIT(PprIds_ppr2), false, (OperatorId_t *[]) { operator_id(mcc_mnc_b, NULL, NULL), NULL }),
		     ppar(BIT(PprIds_ppr1) | BIT(PprIds_ppr2), true,
			  (OperatorId_t *[]) { operator_id(mcc_mnc_any, NULL, NULL), NULL }),
		     NULL });

	/* Operator A: PPR1 without consent, PPR2 with. */
	assert(ipa_ppr_check_against_rat(ppr1, owner_a, table, &consent) == 0);
	assert(consent.ppr1 == false && consent.ppr2 == false);
	assert(ipa_ppr_check_against_rat(ppr2, owner_a, table, &consent) == 0);
	assert(consent.ppr1 == false && consent.ppr2 == true);

	/* Operator B: the other way round. */
	assert(ipa_ppr_check_against_rat(ppr1, owner_b, table, &consent) == 0);
	assert(consent.ppr1 == true && consent.ppr2 == false);
	assert(ipa_ppr_check_against_rat(ppr2, owner_b, table, &consent) == 0);
	assert(consent.ppr1 == false && consent.ppr2 == false);

	/* Both rules at once: the flags are per rule, so the end user can be told which of the two is the one that
	 * needs the consent. Operator A owns PPR1 outright and needs consent only for PPR2. */
	assert(ipa_ppr_check_against_rat(ppr1_and_2, owner_a, table, &consent) == 0);
	assert(consent.ppr1 == false && consent.ppr2 == true);

	/* A PPAR that only sets pprUpdateControl authorises nothing; the LPA ignores that bit. */
	table = rat((ProfilePolicyAuthorisationRule_t *[]) {
		     ppar(BIT(PprIds_pprUpdateControl), false,
			  (OperatorId_t *[]) { operator_id(mcc_mnc_any, NULL, NULL), NULL }),
		     NULL });
	assert(ipa_ppr_check_against_rat(ppr1, owner_a, table, &consent) == -EPERM);

	/* Rules are set, but the metadata names no profile owner to compare the RAT against. */
	table = rat((ProfilePolicyAuthorisationRule_t *[]) {
		     ppar(BIT(PprIds_ppr1), false,
			  (OperatorId_t *[]) { operator_id(mcc_mnc_any, NULL, NULL), NULL }),
		     NULL });
	assert(ipa_ppr_check_against_rat(ppr1, NULL, table, &consent) == -EPERM);

	free_fixtures();
}

/* A rule this version of the specification does not know cannot be evaluated, so the profile must not be installed
 * -- no matter how permissive the RAT is. */
static void unknown_ppr_test(void)
{
	OperatorId_t *owner = operator_id(mcc_mnc_a, NULL, NULL);
	RulesAuthorisationTable_t *table = rat((ProfilePolicyAuthorisationRule_t *[]) {
					       ppar(0xff, false,
						    (OperatorId_t *[]) { operator_id(mcc_mnc_any, NULL, NULL), NULL }),
					       NULL });
	struct ipa_ppr_consent consent;

	assert(ipa_ppr_check_against_rat(bit_string(BIT(3), 4), owner, table, &consent) == -EPERM);
	assert(ipa_ppr_check_against_rat(bit_string(BIT(PprIds_ppr1) | BIT(7), 0), owner, table, &consent) == -EPERM);

	/* Bits past the end of the BIT STRING are absent, not set, so a short string is not "unknown rules set". */
	assert(ipa_ppr_check_against_rat(bit_string(BIT(PprIds_ppr1), 5), owner, table, &consent) == 0);

	free_fixtures();
}

int main(int argc, char **argv)
{
	operator_matching_test();
	no_ppr_test();
	ppr_authorisation_test();
	unknown_ppr_test();
	printf("ppr_test: all checks passed\n");
	return 0;
}

/* Stubs */
void *ipa_http_init(const char *cabundle, bool no_verif)
{
	return NULL;
}

struct ipa_buf *ipa_http_req(void *http_ctx, const struct ipa_buf *req, const char *url)
{
	return NULL;
}

void ipa_http_close(void *http_ctx)
{
	return;
}

void ipa_http_free(void *http_ctx)
{
	return;
}

void *ipa_scard_init(unsigned int reader_num)
{
	return NULL;
}

int ipa_scard_reset(void *scard_ctx)
{
	return 0;
}

int ipa_scard_atr(void *scard_ctx, struct ipa_buf *atr)
{
	return 0;
}

int ipa_scard_transceive(void *scard_ctx, struct ipa_buf *res, const struct ipa_buf *req)
{
	return 0;
}

int ipa_scard_free(void *scard_ctx)
{
	return 0;
}
