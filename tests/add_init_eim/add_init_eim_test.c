/*
 * Copyright (c) 2026 Onomondo ApS & sysmocom - s.f.m.c. GmbH & Iapyx Informatica Ltda. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * The cases below follow the mandatory content and the eUICC assigned defaults of GSMA SGP.32,
 * section 5.9.4 (Function (ES10b): AddInitialEim).
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <stdbool.h>
#include <onomondo/ipa/utils.h>
#include "src/ipa/libipa/context.h"
#include "src/ipa/libipa/es10b_add_init_eim.h"

/* id-ecPublicKey (1.2.840.10045.2.1), BER content octets. */
static const uint8_t oid_ec_public_key[] = { 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 };

/* The validation runs asn_check_constraints() over the whole entry, which recurses into this structure, so
 * it has to be as complete as ber_decode() would have left it -- a zeroed one fails on the unset OID. */
static void fill_spki(SubjectPublicKeyInfo_t *spki)
{
	spki->algorithm.algorithm.buf = malloc(sizeof(oid_ec_public_key));
	assert(spki->algorithm.algorithm.buf);
	memcpy(spki->algorithm.algorithm.buf, oid_ec_public_key, sizeof(oid_ec_public_key));
	spki->algorithm.algorithm.size = sizeof(oid_ec_public_key);

	spki->subjectPublicKey.buf = calloc(1, 1);
	assert(spki->subjectPublicKey.buf);
	spki->subjectPublicKey.size = 1;
}

static struct EimConfigurationData__eimPublicKeyData *public_key_data(void)
{
	struct EimConfigurationData__eimPublicKeyData *pk = calloc(1, sizeof(*pk));

	assert(pk);
	pk->present = EimConfigurationData__eimPublicKeyData_PR_eimPublicKey;
	fill_spki(&pk->choice.eimPublicKey);
	return pk;
}

static struct EimConfigurationData__trustedPublicKeyDataTls *tls_public_key_data(void)
{
	struct EimConfigurationData__trustedPublicKeyDataTls *pk = calloc(1, sizeof(*pk));

	assert(pk);
	pk->present = EimConfigurationData__trustedPublicKeyDataTls_PR_trustedEimPkTls;
	fill_spki(&pk->choice.trustedEimPkTls);
	return pk;
}

static long *make_long(long value)
{
	long *l = calloc(1, sizeof(*l));

	assert(l);
	*l = value;
	return l;
}

/* One entry with everything the specification demands, so each test can knock a single field out. */
static struct EimConfigurationData *valid_entry(const char *eim_id)
{
	struct EimConfigurationData *cfg = calloc(1, sizeof(*cfg));

	assert(cfg);
	assert(OCTET_STRING_fromBuf(&cfg->eimId, eim_id, strlen(eim_id)) == 0);
	cfg->counterValue = make_long(1);
	cfg->eimPublicKeyData = public_key_data();
	return cfg;
}

static struct AddInitialEimRequest *request_of(struct EimConfigurationData **entries, int count)
{
	struct AddInitialEimRequest *req = calloc(1, sizeof(*req));
	int i;

	assert(req);
	for (i = 0; i < count; i++)
		ASN_SEQUENCE_ADD(&req->eimConfigurationDataList.list, entries[i]);
	return req;
}

/* "The following sub-fields of EimConfigurationData SHALL be present in each entry of the
 * eimConfigurationDataList: eimId; counterValue; and either eimPublicKey or eimCertificate." */
static void mandatory_fields_test(void)
{
	struct EimConfigurationData *cfg;
	struct AddInitialEimRequest *req;

	printf("== mandatory_fields_test ==\n");

	/* The complete entry is accepted. */
	cfg = valid_entry("eim.example.com");
	req = request_of(&cfg, 1);
	assert(ipa_es10b_add_init_eim_validate(req) == 0);

	/* counterValue missing. */
	free(cfg->counterValue);
	cfg->counterValue = NULL;
	assert(ipa_es10b_add_init_eim_validate(req) ==
	       AddInitialEimResponse__addInitialEimError_commandError);
	cfg->counterValue = make_long(1);
	assert(ipa_es10b_add_init_eim_validate(req) == 0);

	/* Neither eimPublicKey nor eimCertificate. */
	free(cfg->eimPublicKeyData);
	cfg->eimPublicKeyData = NULL;
	assert(ipa_es10b_add_init_eim_validate(req) ==
	       AddInitialEimResponse__addInitialEimError_commandError);

	/* trustedPublicKeyDataTls is a different field -- the (D)TLS trust anchor, explicitly optional -- so it
	 * must NOT satisfy the requirement above. It is built as a structurally valid CHOICE on purpose, so that
	 * the rejection can only come from the missing eimPublicKeyData and not from a constraint violation. */
	cfg->trustedPublicKeyDataTls = tls_public_key_data();
	assert(ipa_es10b_add_init_eim_validate(req) ==
	       AddInitialEimResponse__addInitialEimError_commandError);

	/* Proof that the entry is otherwise sound: putting the signing key back makes it pass again. */
	cfg->eimPublicKeyData = public_key_data();
	assert(ipa_es10b_add_init_eim_validate(req) == 0);
	free(cfg->eimPublicKeyData);
	cfg->eimPublicKeyData = NULL;

	/* An empty list has nothing to configure and is refused as well. */
	req->eimConfigurationDataList.list.count = 0;
	assert(ipa_es10b_add_init_eim_validate(req) ==
	       AddInitialEimResponse__addInitialEimError_commandError);
}

/* eimId carries SIZE(1..128) in the ASN.1 module, which ber_decode() does not enforce by itself. */
static void eim_id_size_test(void)
{
	struct EimConfigurationData *cfg;
	struct AddInitialEimRequest *req;
	char long_id[130];

	printf("== eim_id_size_test ==\n");

	cfg = valid_entry("x");
	req = request_of(&cfg, 1);

	/* One character is the smallest allowed eimId. */
	assert(ipa_es10b_add_init_eim_validate(req) == 0);

	/* Exactly 128 characters is still allowed. */
	memset(long_id, 'a', 128);
	assert(OCTET_STRING_fromBuf(&cfg->eimId, long_id, 128) == 0);
	assert(ipa_es10b_add_init_eim_validate(req) == 0);

	/* 129 characters is one too many. */
	memset(long_id, 'a', 129);
	assert(OCTET_STRING_fromBuf(&cfg->eimId, long_id, 129) == 0);
	assert(ipa_es10b_add_init_eim_validate(req) ==
	       AddInitialEimResponse__addInitialEimError_commandError);

	/* An empty eimId is refused too: the size constraint starts at 1. */
	assert(OCTET_STRING_fromBuf(&cfg->eimId, "", 0) == 0);
	assert(ipa_es10b_add_init_eim_validate(req) ==
	       AddInitialEimResponse__addInitialEimError_commandError);
}

/* "It is IPA's responsibility to correctly formulate each entry, including the uniqueness of eimId". */
static void eim_id_uniqueness_test(void)
{
	struct EimConfigurationData *entries[3];
	struct AddInitialEimRequest *req;

	printf("== eim_id_uniqueness_test ==\n");

	entries[0] = valid_entry("eim-a");
	entries[1] = valid_entry("eim-b");
	entries[2] = valid_entry("eim-c");
	req = request_of(entries, 3);
	assert(ipa_es10b_add_init_eim_validate(req) == 0);

	/* Two entries claiming the same eimId make every later lookup ambiguous. */
	assert(OCTET_STRING_fromBuf(&entries[2]->eimId, "eim-a", 5) == 0);
	assert(ipa_es10b_add_init_eim_validate(req) ==
	       AddInitialEimResponse__addInitialEimError_commandError);

	/* A shared prefix is not a duplicate. */
	assert(OCTET_STRING_fromBuf(&entries[2]->eimId, "eim-a-2", 7) == 0);
	assert(ipa_es10b_add_init_eim_validate(req) == 0);
}

/* "If associationToken is not set to -1 the eUICC SHALL return an error code invalidAssociationToken." */
static void association_token_test(void)
{
	struct EimConfigurationData *cfg;
	struct AddInitialEimRequest *req;

	printf("== association_token_test ==\n");

	cfg = valid_entry("eim.example.com");
	req = request_of(&cfg, 1);

	/* Absent: the eIM simply does not use an association token. */
	assert(ipa_es10b_add_init_eim_check_assoc_tokens(req) == 0);

	/* -1 requests that the eUICC calculates one. */
	cfg->associationToken = make_long(-1);
	assert(ipa_es10b_add_init_eim_check_assoc_tokens(req) == 0);

	/* Anything else is an already resolved token, which an initial configuration may not present. */
	*cfg->associationToken = 7;
	assert(ipa_es10b_add_init_eim_check_assoc_tokens(req) ==
	       AddInitialEimResponse__addInitialEimError_invalidAssociationToken);

	*cfg->associationToken = 0;
	assert(ipa_es10b_add_init_eim_check_assoc_tokens(req) ==
	       AddInitialEimResponse__addInitialEimError_invalidAssociationToken);

	/* The token rule is deliberately not part of the shared validation, since the IoT eUICC emulation
	 * re-submits stored entries whose tokens have already been resolved. */
	assert(ipa_es10b_add_init_eim_validate(req) == 0);
}

/* The defaults a native IoT eUICC assigns when the IPA leaves an optional sub-field out. */
static void emulation_defaults_test(void)
{
	struct ipa_config cfg_ipa = { 0 };
	struct ipa_context ctx = { 0 };
	struct EimConfigurationData *cfg;
	uint8_t ci_pk_id_buf[] = { 0xde, 0xad, 0xbe, 0xef };
	SubjectKeyIdentifier_t ci_pk_id = { 0 };

	printf("== emulation_defaults_test ==\n");

	ctx.cfg = &cfg_ipa;
	ci_pk_id.buf = ci_pk_id_buf;
	ci_pk_id.size = sizeof(ci_pk_id_buf);

	cfg = valid_entry("eim.example.com");
	assert(complete_eim_cfg(&ctx, cfg, &ci_pk_id) == 0);

	/* "If the eimIdType is not provided, the eUICC SHALL assign the value eimIdTypeProprietary". */
	assert(cfg->eimIdType);
	assert(*cfg->eimIdType == EimIdType_eimIdTypeProprietary);

	/* "If not provided, the eUICC SHALL assign the value where only the eimProprietary bit is set". */
	assert(cfg->eimSupportedProtocol);
	assert(cfg->eimSupportedProtocol->size == 1);
	assert(cfg->eimSupportedProtocol->buf[0] == 0x08);	/* eimProprietary(4), MSB first */
	assert(cfg->eimSupportedProtocol->bits_unused == 3);

	/* "If not provided, the eUICC SHALL assign the value of first entry of euiccCiPKIdListForSigning". */
	assert(cfg->euiccCiPKId);
	assert(cfg->euiccCiPKId->size == (int)sizeof(ci_pk_id_buf));
	assert(memcmp(cfg->euiccCiPKId->buf, ci_pk_id_buf, sizeof(ci_pk_id_buf)) == 0);

	/* Values the caller did supply are left alone. */
	cfg = valid_entry("eim.example.com");
	cfg->eimIdType = make_long(EimIdType_eimIdTypeFqdn);
	assert(complete_eim_cfg(&ctx, cfg, &ci_pk_id) == 0);
	assert(*cfg->eimIdType == EimIdType_eimIdTypeFqdn);

	/* Without a CI public key identifier to fall back to, euiccCiPKId is left absent rather than guessed. */
	cfg = valid_entry("eim.example.com");
	assert(complete_eim_cfg(&ctx, cfg, NULL) == 0);
	assert(cfg->euiccCiPKId == NULL);
}

/* "Check if counterValue exceeds the maximum value supported by the eUICC." */
static void counter_value_range_test(void)
{
	struct ipa_config cfg_ipa = { 0 };
	struct ipa_context ctx = { 0 };
	struct EimConfigurationData *cfg;

	printf("== counter_value_range_test ==\n");
	ctx.cfg = &cfg_ipa;

	/* The largest value every eUICC must support, per SGP.32 section 2.11.1.1. */
	cfg = valid_entry("eim.example.com");
	*cfg->counterValue = 8388607;
	assert(complete_eim_cfg(&ctx, cfg, NULL) == 0);

	cfg = valid_entry("eim.example.com");
	*cfg->counterValue = 8388608;
	assert(complete_eim_cfg(&ctx, cfg, NULL) < 0);

	cfg = valid_entry("eim.example.com");
	*cfg->counterValue = -1;
	assert(complete_eim_cfg(&ctx, cfg, NULL) < 0);
}

/* An association token is only calculated when one was requested with -1. */
static void association_token_calculation_test(void)
{
	struct ipa_config cfg_ipa = { 0 };
	struct ipa_context ctx = { 0 };
	struct EimConfigurationData *cfg;

	printf("== association_token_calculation_test ==\n");
	ctx.cfg = &cfg_ipa;

	cfg = valid_entry("eim-a");
	cfg->associationToken = make_long(-1);
	assert(complete_eim_cfg(&ctx, cfg, NULL) == 0);
	assert(*cfg->associationToken == 1);

	/* "It SHALL NOT be possible to reset the counter": the next request gets the next value. */
	cfg = valid_entry("eim-b");
	cfg->associationToken = make_long(-1);
	assert(complete_eim_cfg(&ctx, cfg, NULL) == 0);
	assert(*cfg->associationToken == 2);

	/* No token requested, no token assigned. */
	cfg = valid_entry("eim-c");
	assert(complete_eim_cfg(&ctx, cfg, NULL) == 0);
	assert(cfg->associationToken == NULL);
	assert(ctx.nvstate.iot_euicc_emu.association_token_counter == 2);
}

int main(int argc, char **argv)
{
	mandatory_fields_test();
	eim_id_size_test();
	eim_id_uniqueness_test();
	association_token_test();
	emulation_defaults_test();
	counter_value_range_test();
	association_token_calculation_test();
	printf("add_init_eim_test: all checks passed\n");
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
