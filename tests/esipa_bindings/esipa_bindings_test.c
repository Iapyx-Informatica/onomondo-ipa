/*
 * Copyright (c) 2026 Onomondo ApS & sysmocom - s.f.m.c. GmbH & Iapyx Informatica Ltda. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * The cases below cover the transaction identifiers that ESipa requests have to carry, in both bindings:
 *  - GetBoundProfilePackage.transactionId, a required member of the JSON request body (section 6.4.1.3),
 *    derived from the PrepareDownloadResponse in both bindings;
 *  - InitiateAuthentication.eimTransactionId, which the IPA echoes from the ProfileDownloadTriggerRequest
 *    that started the download (sections 5.14.1 and 6.4.1.1).
 *
 * and the three optional members of GetEimPackage (sections 5.14.5 and 6.4.1.5): notifyStateChange,
 * stateChangeCause and rPLMN.  Those are driven through the public API and checked in the bytes the
 * library hands to the HTTP layer, so the whole path is covered rather than the encoder alone.
 */

#define _GNU_SOURCE		/* memmem() */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <stdbool.h>
#include <onomondo/ipa/utils.h>
#include <onomondo/ipa/ipad.h>
#include "src/ipa/libipa/context.h"
#include "src/ipa/libipa/length.h"
#include "src/ipa/libipa/esipa_get_bnd_prfle_pkg.h"
#include "src/ipa/libipa/esipa_init_auth.h"
#include "src/ipa/libipa/esipa_get_eim_pkg.h"
#include "src/ipa/libipa/esipa_auth_clnt.h"
#include "src/ipa/libipa/esipa_prvde_eim_pkg_rslt.h"
#include "src/ipa/libipa/esipa_json.h"
#include <EsipaMessageFromIpaToEim.h>
#include <EimPackageResult.h>
#include <EimPackageResultErrorCode.h>
#include <EuiccPackageRequest.h>

/* A DER sink both bindings need: the ASN.1 cases encode whole ESipa messages with it, and the JSON
 * cases use it to build the EimPackageResult that the JSON body carries base64-encoded. */
static uint8_t esipa_enc_buf[2048];
static size_t esipa_enc_len;

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

static int esipa_enc_sink(const void *b, size_t sz, void *key)
{
	(void)key;
	assert(esipa_enc_len + sz <= sizeof(esipa_enc_buf));
	memcpy(esipa_enc_buf + esipa_enc_len, b, sz);
	esipa_enc_len += sz;
	return 0;
}

static uint8_t transaction_id_bytes[] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };
#define TRANSACTION_ID_HEX "\"transactionId\":\"0123456789ABCDEF\""

/*
 * Fixtures here are released through the asn1c free functions, so they are allocated through the
 * asn1c allocators: CALLOC is IPA_CALLOC and MALLOC is IPA_ALLOC_N (asn_internal.h), and FREEMEM is
 * IPA_FREE.  Mixing plain calloc()/malloc() with those frees balances out under a normal build but
 * drives the -DMEM_EMIT_DEBUG=ON allocation counter negative.
 */
static void set_transaction_id(TransactionId_t *tid)
{
	/* Not inside the assert(): the copy has to happen under NDEBUG too. */
	int rc = OCTET_STRING_fromBuf(tid, (const char *)transaction_id_bytes, sizeof(transaction_id_bytes));

	assert(rc == 0);
	(void)rc;
}

/* A PrepareDownloadResponse complete enough to be DER encoded. */
static struct PrepareDownloadResponse *response_ok(void)
{
	struct PrepareDownloadResponse *pdr = IPA_CALLOC(1, sizeof(*pdr));
	static uint8_t otpk[] = { 0x04, 0xaa, 0xbb };
	static uint8_t sig[] = { 0xde, 0xad, 0xbe, 0xef };

	assert(pdr);
	pdr->present = PrepareDownloadResponse_PR_downloadResponseOk;
	set_transaction_id(&pdr->choice.downloadResponseOk.euiccSigned2.transactionId);
	assert(OCTET_STRING_fromBuf(&pdr->choice.downloadResponseOk.euiccSigned2.euiccOtpk,
				    (const char *)otpk, sizeof(otpk)) == 0);
	assert(OCTET_STRING_fromBuf(&pdr->choice.downloadResponseOk.euiccSignature2,
				    (const char *)sig, sizeof(sig)) == 0);
	return pdr;
}

static struct PrepareDownloadResponse *response_error(void)
{
	struct PrepareDownloadResponse *pdr = IPA_CALLOC(1, sizeof(*pdr));

	assert(pdr);
	pdr->present = PrepareDownloadResponse_PR_downloadResponseError;
	set_transaction_id(&pdr->choice.downloadResponseError.transactionId);
	pdr->choice.downloadResponseError.downloadErrorCode = DownloadErrorCode_undefinedError;
	return pdr;
}

/* The transaction id lives in a different place in each branch of the CHOICE; both bindings ask this helper
 * rather than knowing where it hides. */
static void transaction_id_lookup_test(void)
{
	struct PrepareDownloadResponse empty = { 0 };
	struct PrepareDownloadResponse *pdr;
	const TransactionId_t *tid;

	printf("== transaction_id_lookup_test ==\n");

	/* The fixture has to outlive the lookup: tid points into it, not at a copy. */
	pdr = response_ok();
	tid = ipa_esipa_get_bnd_prfle_pkg_transaction_id(pdr);
	assert(tid && tid->size == (int)sizeof(transaction_id_bytes));
	assert(memcmp(tid->buf, transaction_id_bytes, sizeof(transaction_id_bytes)) == 0);
	ASN_STRUCT_FREE(asn_DEF_PrepareDownloadResponse, pdr);

	pdr = response_error();
	tid = ipa_esipa_get_bnd_prfle_pkg_transaction_id(pdr);
	assert(tid && tid->size == (int)sizeof(transaction_id_bytes));
	assert(memcmp(tid->buf, transaction_id_bytes, sizeof(transaction_id_bytes)) == 0);
	ASN_STRUCT_FREE(asn_DEF_PrepareDownloadResponse, pdr);

	/* Neither branch selected: there is no transaction id to find. */
	empty.present = PrepareDownloadResponse_PR_NOTHING;
	assert(ipa_esipa_get_bnd_prfle_pkg_transaction_id(&empty) == NULL);
	assert(ipa_esipa_get_bnd_prfle_pkg_transaction_id(NULL) == NULL);
}

#ifdef IPA_HAVE_ESIPA_JSON

/* "required": ["transactionId", "prepareDownloadResponse"] */
static void json_request_test(void)
{
	struct ipa_esipa_get_bnd_prfle_pkg_req req = { 0 };
	struct PrepareDownloadResponse *pdr;
	struct ipa_buf *buf;

	printf("== json_request_test ==\n");

	/* The request holds prep_dwnld_res as const -- the encoder does not own it -- so the fixture is
	 * kept in a second, non-const handle to free it by. */

	/* The downloadResponseOk branch. */
	pdr = response_ok();
	req.prep_dwnld_res = pdr;
	buf = ipa_esipa_json_enc_get_bnd_prfle_pkg_req(&req);
	assert(buf);
	assert(memmem(buf->data, buf->len, TRANSACTION_ID_HEX, strlen(TRANSACTION_ID_HEX)));
	assert(memmem(buf->data, buf->len, "\"prepareDownloadResponse\"", 25));
	printf("   ok:    %.*s\n", (int)buf->len, (const char *)buf->data);
	ipa_buf_free(buf);
	ASN_STRUCT_FREE(asn_DEF_PrepareDownloadResponse, pdr);

	/* The downloadResponseError branch carries the transaction id somewhere else, and must still emit it. */
	pdr = response_error();
	req.prep_dwnld_res = pdr;
	buf = ipa_esipa_json_enc_get_bnd_prfle_pkg_req(&req);
	assert(buf);
	assert(memmem(buf->data, buf->len, TRANSACTION_ID_HEX, strlen(TRANSACTION_ID_HEX)));
	printf("   error: %.*s\n", (int)buf->len, (const char *)buf->data);
	ipa_buf_free(buf);
	ASN_STRUCT_FREE(asn_DEF_PrepareDownloadResponse, pdr);
}

/* AuthenticateClient carries an SGP32-AuthenticateServerResponse.  Where no raw eUICC bytes are available the
 * JSON binding encodes that field from the struct, and it has to reach for the SGP.32 descriptor: the SGP.22
 * AuthenticateServerResponse is a two-branch CHOICE with no slot for the compact form, so encoding through it
 * silently works for the two shared branches and then fails outright on the third. */
static void json_auth_clnt_descriptor_test(void)
{
	struct ipa_esipa_auth_clnt_req req = { 0 };
	static const uint8_t tid[4] = { 0xde, 0xad, 0xbe, 0xef };
	static const uint8_t sig[4] = { 0x11, 0x22, 0x33, 0x44 };
	static const uint8_t ecr[4] = { 0x0a, 0x0b, 0x0c, 0x0d };
	struct SGP32_AuthenticateServerResponse *asr = &req.req.authenticateServerResponse;
	struct CompactAuthenticateResponseOk *compact;
	struct ipa_buf *buf;

	printf("== json_auth_clnt_descriptor_test ==\n");

	assert(OCTET_STRING_fromBuf(&req.req.transactionId, (const char *)tid, sizeof(tid)) == 0);

	/* The error branch is the one reached today, since a successful response is forwarded as raw bytes.
	 * It encodes identically under either descriptor, which is exactly why the wrong one went unnoticed. */
	asr->present = SGP32_AuthenticateServerResponse_PR_authenticateResponseError;
	assert(OCTET_STRING_fromBuf(&asr->choice.authenticateResponseError.transactionId,
				    (const char *)tid, sizeof(tid)) == 0);
	asr->choice.authenticateResponseError.authenticateErrorCode = 1;
	buf = ipa_esipa_json_enc_auth_clnt_req(&req);
	assert(buf);
	assert(memmem(buf->data, buf->len, "\"authenticateServerResponse\"", 28));
	printf("   error branch:   encoded\n");
	ipa_buf_free(buf);

	/* The compact branch exists only in the SGP.32 type.  Under the SGP.22 descriptor der_encode() fails and
	 * the whole request comes back NULL; under the right one it encodes.  The error branch built above is
	 * released first: the memset that follows would otherwise drop its two OCTET STRINGs. */
	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_SGP32_AuthenticateServerResponse, asr);
	memset(asr, 0, sizeof(*asr));
	asr->present = SGP32_AuthenticateServerResponse_PR_compactAuthenticateResponseOk;
	compact = &asr->choice.compactAuthenticateResponseOk;
	compact->signedData.present = CompactAuthenticateResponseOk__signedData_PR_compactEuiccSigned1;
	assert(OCTET_STRING_fromBuf(&compact->signedData.choice.compactEuiccSigned1.extCardResource,
				    (const char *)ecr, sizeof(ecr)) == 0);
	assert(OCTET_STRING_fromBuf(&compact->euiccSignature1, (const char *)sig, sizeof(sig)) == 0);
	buf = ipa_esipa_json_enc_auth_clnt_req(&req);
	assert(buf);
	assert(memmem(buf->data, buf->len, "\"authenticateServerResponse\"", 28));
	printf("   compact branch: encoded\n");
	ipa_buf_free(buf);

	/* req is on the stack; both of these are members of it, so only their contents are released. */
	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_SGP32_AuthenticateServerResponse, asr);
	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_TransactionId, &req.req.transactionId);
}

/* Without a transaction id the request cannot satisfy the schema, so no request is produced at all. */
static void json_refuses_without_transaction_id_test(void)
{
	struct ipa_esipa_get_bnd_prfle_pkg_req req = { 0 };
	struct PrepareDownloadResponse empty = { 0 };

	printf("== json_refuses_without_transaction_id_test ==\n");

	empty.present = PrepareDownloadResponse_PR_NOTHING;
	req.prep_dwnld_res = &empty;
	assert(ipa_esipa_json_enc_get_bnd_prfle_pkg_req(&req) == NULL);

	req.prep_dwnld_res = NULL;
	assert(ipa_esipa_json_enc_get_bnd_prfle_pkg_req(&req) == NULL);
}


#endif /* IPA_HAVE_ESIPA_JSON */

#ifdef IPA_HAVE_ESIPA_ASN1
/* The same requirement in the ASN.1 binding: eimTransactionId [2] is OPTIONAL, so it is either encoded as a
 * context-tag-2 primitive or absent altogether. */
static void asn1_init_auth_transaction_id_test(void)
{
	static uint8_t challenge[16] = { 0 };
	/* eimTransactionId [2] IMPLICIT OCTET STRING holding the eight fixture bytes. */
	static const uint8_t encoded_tid[] = { 0x82, 0x08, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };
	struct ipa_esipa_init_auth_req req = { 0 };
	TransactionId_t tid = { 0 };
	struct ipa_buf *buf;

	printf("== asn1_init_auth_transaction_id_test ==\n");
	req.euicc_challenge = challenge;

	/* Not triggered by an eIM: the OPTIONAL field is simply not encoded. */
	buf = ipa_esipa_init_auth_enc_req(NULL, &req);
	assert(buf);
	assert(memmem(buf->data, buf->len, encoded_tid, sizeof(encoded_tid)) == NULL);
	printf("   without: %s\n", ipa_hexdump(buf->data, buf->len));
	ipa_buf_free(buf);

	/* Triggered by an eIM that supplied one: it appears in the encoded request. */
	set_transaction_id(&tid);
	req.eim_transaction_id = &tid;
	buf = ipa_esipa_init_auth_enc_req(NULL, &req);
	assert(buf);
	assert(memmem(buf->data, buf->len, encoded_tid, sizeof(encoded_tid)));
	printf("   with:    %s\n", ipa_hexdump(buf->data, buf->len));
	ipa_buf_free(buf);
	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_TransactionId, &tid);
}

#endif /* IPA_HAVE_ESIPA_ASN1 */

#ifdef IPA_HAVE_ESIPA_JSON

/* SGP.32, section 5.14.1: "If the eIM has sent eimTransactionId in ProfileDownloadTriggerRequest, the IPA
 * SHALL include the same eimTransactionId." Section 6.4.1.1 spells it as upper-case hex and leaves it out of
 * the "required" list, since a download the IPA started by itself has none. */
static void json_init_auth_transaction_id_test(void)
{
	static uint8_t challenge[16] = { 0 };
	struct ipa_esipa_init_auth_req req = { 0 };
	TransactionId_t tid = { 0 };
	struct ipa_buf *buf;

	printf("== json_init_auth_transaction_id_test ==\n");
	req.euicc_challenge = challenge;

	/* Not triggered by an eIM: the member stays out of the object entirely. */
	buf = ipa_esipa_json_enc_init_auth_req(&req);
	assert(buf);
	assert(memmem(buf->data, buf->len, "\"euiccChallenge\"", 16));
	assert(memmem(buf->data, buf->len, "eimTransactionId", 16) == NULL);
	printf("   without: %.*s\n", (int)buf->len, (const char *)buf->data);
	ipa_buf_free(buf);

	/* Triggered by an eIM that supplied one: echoed back as upper-case hex. */
	set_transaction_id(&tid);
	req.eim_transaction_id = &tid;
	buf = ipa_esipa_json_enc_init_auth_req(&req);
	assert(buf);
	assert(memmem(buf->data, buf->len, "\"eimTransactionId\":\"0123456789ABCDEF\"", 37));
	printf("   with:    %.*s\n", (int)buf->len, (const char *)buf->data);
	ipa_buf_free(buf);
	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_TransactionId, &tid);
}

#endif /* IPA_HAVE_ESIPA_JSON */

/* The eIM never answers in this test; what is under examination is the request the library builds, which
 * the ipa_http_req_with_ct() stub at the bottom of this file captures here. */
static struct ipa_buf *captured_req;

/* An EID is 32 decimal digits packed BCD, so every nibble is 0..9 -- the JSON binding renders it with
 * "^[0-9]{32}$" and would emit junk for anything else. */
static uint8_t eid_bytes[IPA_LEN_EID] = {
	0x89, 0x04, 0x40, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0x11, 0x22, 0x33
};
#define EID_DIGITS "89044011223344556677889900112233"

/* Poll the eIM and return what went out. The call itself fails (no eIM), which is fine: the request has
 * already been encoded and handed to the transport by then. */
static const struct ipa_buf *poll_eim(struct ipa_context *ctx)
{
	ipa_buf_free(captured_req);
	captured_req = NULL;
	ipa_esipa_get_eim_pkg_free(ipa_esipa_get_eim_pkg(ctx, eid_bytes));
	assert(captured_req);
	return captured_req;
}

static bool req_contains(const struct ipa_buf *req, const void *needle, size_t len)
{
	return memmem(req->data, req->len, needle, len) != NULL;
}

static struct ipa_context *test_ctx(struct ipa_config *cfg, int binding)
{
	struct ipa_context *ctx;

	memset(cfg, 0, sizeof(*cfg));
	cfg->esipa_binding = binding;
	cfg->esipa_req_retries = 0;	/* fail on the first try, so the test does not sleep */
	ctx = ipa_new_ctx(cfg, NULL);
	assert(ctx);
	/* ipa_new_ctx() must not leave this at the zero value, which would be IPA_STATE_CHANGE_OTHER_EIM
	 * and would have every first poll blame another eIM for a change that never happened. */
	assert(ctx->nvstate.state_change_cause == IPA_STATE_CHANGE_NONE);
	ctx->eim_fqdn = test_strdup("eim.example.com");
	assert(ctx->eim_fqdn);
	return ctx;
}

/* SGP.32 section 5.14.5: the MCC/MNC pair the host reports is packed per 3GPP TS 24.008 -- nibble-swapped
 * BCD, third MNC digit in the high nibble of the middle octet, 'F' there for a two-digit MNC. */
static void rplmn_encoding_test(void)
{
	static const struct {
		const char *mcc, *mnc;
		uint8_t encoded[IPA_LEN_PLMN];
	} cases[] = {
		{ "262", "01", { 0x62, 0xf2, 0x10 } },	/* two-digit MNC, 'F' filler */
		{ "310", "260", { 0x13, 0x00, 0x62 } },	/* three-digit MNC */
		{ "724", "05", { 0x27, 0xf4, 0x50 } },
		{ "001", "01", { 0x00, 0xf1, 0x10 } },
	};
	struct ipa_config cfg;
	struct ipa_context *ctx = test_ctx(&cfg, IPA_ESIPA_BINDING_ASN1);
	unsigned int i;

	printf("== rplmn_encoding_test ==\n");

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		assert(ipa_set_rplmn(ctx, cases[i].mcc, cases[i].mnc) == 0);
		assert(memcmp(ctx->rplmn, cases[i].encoded, IPA_LEN_PLMN) == 0);
		assert(ctx->rplmn_valid);
		printf("   MCC %s MNC %-3s -> %s\n", cases[i].mcc, cases[i].mnc,
		       ipa_hexdump(ctx->rplmn, IPA_LEN_PLMN));
	}

	/* Malformed input is refused, and -- important -- leaves the last good value alone: a bad call must
	 * not silently stop the eIM hearing about roaming. */
	assert(ipa_set_rplmn(ctx, "26", "01") < 0);
	assert(ipa_set_rplmn(ctx, "2620", "01") < 0);
	assert(ipa_set_rplmn(ctx, "262", "1") < 0);
	assert(ipa_set_rplmn(ctx, "262", "0123") < 0);
	assert(ipa_set_rplmn(ctx, "26A", "01") < 0);
	assert(ipa_set_rplmn(ctx, "262", "0X") < 0);
	assert(ipa_set_rplmn(ctx, "262", NULL) < 0);
	assert(ctx->rplmn_valid && memcmp(ctx->rplmn, cases[3].encoded, IPA_LEN_PLMN) == 0);

	/* A NULL MCC is the documented way to stop reporting one. */
	assert(ipa_set_rplmn(ctx, NULL, NULL) == 0);
	assert(!ctx->rplmn_valid);

	ipa_buf_free(ipa_free_ctx(ctx));
}

#ifdef IPA_HAVE_ESIPA_ASN1
/* rPLMN [2] and the notifyStateChange [0] / stateChangeCause [1] pair are independent OPTIONAL members:
 * each appears only when it has something to say. */
static void asn1_get_eim_pkg_test(void)
{
	static const uint8_t encoded_rplmn[] = { 0x82, 0x03, 0x62, 0xf2, 0x10 };
	static const uint8_t encoded_cause[] = { 0x80, 0x00, 0x81, 0x01, 0x01 };
	struct ipa_config cfg;
	struct ipa_context *ctx = test_ctx(&cfg, IPA_ESIPA_BINDING_ASN1);
	const struct ipa_buf *req;

	printf("== asn1_get_eim_pkg_test ==\n");

	/* Nothing to report: the EID alone. */
	req = poll_eim(ctx);
	assert(!req_contains(req, encoded_rplmn, sizeof(encoded_rplmn)));
	assert(!req_contains(req, encoded_cause, sizeof(encoded_cause)));
	printf("   bare:        %s\n", ipa_hexdump(req->data, req->len));

	/* Registered somewhere: rPLMN rides along on every poll from now on. */
	assert(ipa_set_rplmn(ctx, "262", "01") == 0);
	req = poll_eim(ctx);
	assert(req_contains(req, encoded_rplmn, sizeof(encoded_rplmn)));
	assert(!req_contains(req, encoded_cause, sizeof(encoded_cause)));
	printf("   rplmn:       %s\n", ipa_hexdump(req->data, req->len));

	/* A local state change adds the other two; SGP.32 Table 16 makes stateChangeCause C(1) on
	 * notifyStateChange, so they are never seen apart. */
	ipa_esipa_note_state_change(ctx, IPA_STATE_CHANGE_FALLBACK);
	req = poll_eim(ctx);
	assert(req_contains(req, encoded_rplmn, sizeof(encoded_rplmn)));
	assert(req_contains(req, encoded_cause, sizeof(encoded_cause)));
	printf("   both:        %s\n", ipa_hexdump(req->data, req->len));

	/* The poll failed, so the cause is still pending and must go out again. Losing it here would
	 * leave the eIM permanently unaware of the change. */
	assert(ctx->nvstate.state_change_cause == IPA_STATE_CHANGE_FALLBACK);
	req = poll_eim(ctx);
	assert(req_contains(req, encoded_cause, sizeof(encoded_cause)));

	/* rPLMN, unlike the cause, is standing state and is not cleared by a poll either. */
	assert(ctx->rplmn_valid);
	assert(ipa_set_rplmn(ctx, NULL, NULL) == 0);
	req = poll_eim(ctx);
	assert(!req_contains(req, encoded_rplmn, sizeof(encoded_rplmn)));
	printf("   cleared:     %s\n", ipa_hexdump(req->data, req->len));

	ipa_buf_free(ipa_free_ctx(ctx));
}
#endif /* IPA_HAVE_ESIPA_ASN1 */

#ifdef IPA_HAVE_ESIPA_JSON
/* Section 6.4.1.5 spells the member "rPlmn" and carries the three TS 24.008 bytes as plain base64. */
static void json_get_eim_pkg_test(void)
{
	struct ipa_config cfg;
	struct ipa_context *ctx = test_ctx(&cfg, IPA_ESIPA_BINDING_JSON);
	const struct ipa_buf *req;

	printf("== json_get_eim_pkg_test ==\n");

	req = poll_eim(ctx);
	assert(req_contains(req, "\"eidValue\":\"" EID_DIGITS "\"", 12 + 32 + 1));
	assert(!req_contains(req, "rPlmn", 5));
	assert(!req_contains(req, "stateChangeCause", 16));
	printf("   bare:  %.*s\n", (int)req->len, (const char *)req->data);

	assert(ipa_set_rplmn(ctx, "262", "01") == 0);
	ipa_esipa_note_state_change(ctx, IPA_STATE_CHANGE_FALLBACK);
	req = poll_eim(ctx);
	assert(req_contains(req, "\"rPlmn\": \"YvIQ\"", 15) || req_contains(req, "\"rPlmn\":\"YvIQ\"", 14));
	assert(req_contains(req, "\"notifyStateChange\"", 19));
	assert(req_contains(req, "\"stateChangeCause\"", 18));
	printf("   full:  %.*s\n", (int)req->len, (const char *)req->data);

	ipa_buf_free(ipa_free_ctx(ctx));
}
#endif /* IPA_HAVE_ESIPA_JSON */

#ifdef IPA_HAVE_ESIPA_ASN1
/* dec_prvde_eim_pkg_rslt_res() is not declared in a header; it is reached from the binding table in the
 * same file. */
struct ipa_esipa_prvde_eim_pkg_rslt_res *dec_prvde_eim_pkg_rslt_res(const struct ipa_buf *encoded);

/* DER-encode an EsipaMessageFromEimToIpa the way the eIM would put it on the wire. */
static struct ipa_buf *esipa_encode(const struct EsipaMessageFromEimToIpa *msg)
{
	asn_enc_rval_t er;

	esipa_enc_len = 0;
	er = der_encode(&asn_DEF_EsipaMessageFromEimToIpa, (void *)msg, esipa_enc_sink, NULL);
	assert(er.encoded > 0);
	return ipa_buf_alloc_data(esipa_enc_len, esipa_enc_buf);
}

/* The eIM answers ProvideEimPackageResult with one of three branches (SGP.32, section 6.3.2.7).  Two of
 * them carry no acknowledgements, and only prvde_eim_pkg_rslt_err separates "accepted, nothing to
 * acknowledge" from "refused, the result was never processed" -- a distinction the caller needs, because
 * on a refusal it must keep the eUICC Package Result instead of retiring it. */
static void asn1_prvde_eim_pkg_rslt_response_test(void)
{
	struct EsipaMessageFromEimToIpa msg = { 0 };
	struct ProvideEimPackageResultResponse *r = &msg.choice.provideEimPackageResultResponse;
	struct ipa_esipa_prvde_eim_pkg_rslt_res *res;
	struct ipa_buf *enc;
	long *seq;

	printf("== asn1_prvde_eim_pkg_rslt_response_test ==\n");
	msg.present = EsipaMessageFromEimToIpa_PR_provideEimPackageResultResponse;

	/* eimAcknowledgements: accepted, and the sequence numbers come back. */
	r->present = ProvideEimPackageResultResponse_PR_eimAcknowledgements;
	seq = IPA_CALLOC(1, sizeof(*seq));
	assert(seq);
	*seq = 7;
	ASN_SEQUENCE_ADD(&r->choice.eimAcknowledgements.list, seq);
	enc = esipa_encode(&msg);
	res = dec_prvde_eim_pkg_rslt_res(enc);
	assert(res && res->eim_acknowledgements && res->eim_acknowledgements->list.count == 1);
	assert(res->prvde_eim_pkg_rslt_err == 0);
	printf("   eimAcknowledgements          -> accepted, 1 ack\n");
	ipa_esipa_prvde_eim_pkg_rslt_free(res);
	ipa_buf_free(enc);
	ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_EimAcknowledgements, &r->choice.eimAcknowledgements);

	/* emptyResponse: also accepted, just with nothing to acknowledge. */
	memset(r, 0, sizeof(*r));
	r->present = ProvideEimPackageResultResponse_PR_emptyResponse;
	enc = esipa_encode(&msg);
	res = dec_prvde_eim_pkg_rslt_res(enc);
	assert(res && res->eim_acknowledgements == NULL);
	assert(res->prvde_eim_pkg_rslt_err == 0);
	printf("   emptyResponse                -> accepted, no acks\n");
	ipa_esipa_prvde_eim_pkg_rslt_free(res);
	ipa_buf_free(enc);

	/* provideEimPackageResultError: refused, and it must not look like the case above. */
	memset(r, 0, sizeof(*r));
	r->present = ProvideEimPackageResultResponse_PR_provideEimPackageResultError;
	r->choice.provideEimPackageResultError =
	    ProvideEimPackageResultResponse__provideEimPackageResultError_eidNotFound;
	enc = esipa_encode(&msg);
	res = dec_prvde_eim_pkg_rslt_res(enc);
	assert(res && res->eim_acknowledgements == NULL);
	assert(res->prvde_eim_pkg_rslt_err ==
	       ProvideEimPackageResultResponse__provideEimPackageResultError_eidNotFound);
	printf("   provideEimPackageResultError -> refused, eidNotFound reported\n");
	ipa_esipa_prvde_eim_pkg_rslt_free(res);
	ipa_buf_free(enc);
}

/* SGP.32 sections 3.2.3.1 and 3.2.3.2, steps 3 and 4: an eIM Package the IPA cannot use is answered with
 * invalidPackageFormat, not with silence.  Section 6.3.2.7 adds that the eimTransactionId of the package
 * has to come back with it -- without it the eIM has a rejection it cannot attribute to any of the
 * operations it dispatched, which is no better than the timeout it was already going to get.
 *
 * This drives the encoder the reporting path uses and reads the result back out of the DER. */
static void asn1_eim_pkg_err_report_test(void)
{
	struct ipa_esipa_prvde_eim_pkg_rslt_req req = { 0 };
	struct EsipaMessageFromIpaToEim *msg = NULL;
	struct EimPackageResultResponseError *err;
	struct ipa_config cfg;
	struct ipa_context *ctx = test_ctx(&cfg, IPA_ESIPA_BINDING_ASN1);
	TransactionId_t eim_tid = { 0 };
	asn_dec_rval_t dr;
	struct ipa_buf *enc;

	printf("== asn1_eim_pkg_err_report_test ==\n");
	memcpy(ctx->eid, eid_bytes, IPA_LEN_EID);
	set_transaction_id(&eim_tid);

	req.eim_pkg_err = EimPackageResultErrorCode_invalidPackageFormat;
	req.eim_transaction_id = &eim_tid;
	enc = ipa_esipa_prvde_eim_pkg_rslt_enc_req(ctx, &req);
	assert(enc);

	dr = ber_decode(NULL, &asn_DEF_EsipaMessageFromIpaToEim, (void **)&msg, enc->data, enc->len);
	assert(dr.code == RC_OK && msg);
	assert(msg->present == EsipaMessageFromIpaToEim_PR_provideEimPackageResult);
	assert(msg->choice.provideEimPackageResult.eimPackageResult.present ==
	       EimPackageResult_PR_eimPackageResultResponseError);
	err = &msg->choice.provideEimPackageResult.eimPackageResult.choice.eimPackageResultResponseError;
	assert(err->eimPackageResultErrorCode == EimPackageResultErrorCode_invalidPackageFormat);
	assert(err->eimTransactionId);
	assert(err->eimTransactionId->size == sizeof(transaction_id_bytes));
	assert(memcmp(err->eimTransactionId->buf, transaction_id_bytes, sizeof(transaction_id_bytes)) == 0);
	printf("   invalidPackageFormat         -> reported, eimTransactionId echoed\n");
	ASN_STRUCT_FREE(asn_DEF_EsipaMessageFromIpaToEim, msg);
	ipa_buf_free(enc);

	/* An eIM that sent no transaction id must not have one invented for it: the member is OPTIONAL and
	 * section 6.3.2.7 conditions the echo on the package having carried one. */
	msg = NULL;
	req.eim_transaction_id = NULL;
	enc = ipa_esipa_prvde_eim_pkg_rslt_enc_req(ctx, &req);
	assert(enc);
	dr = ber_decode(NULL, &asn_DEF_EsipaMessageFromIpaToEim, (void **)&msg, enc->data, enc->len);
	assert(dr.code == RC_OK && msg);
	err = &msg->choice.provideEimPackageResult.eimPackageResult.choice.eimPackageResultResponseError;
	assert(err->eimPackageResultErrorCode == EimPackageResultErrorCode_invalidPackageFormat);
	assert(err->eimTransactionId == NULL);
	printf("   trigger without a transaction id -> reported, no eimTransactionId invented\n");
	ASN_STRUCT_FREE(asn_DEF_EsipaMessageFromIpaToEim, msg);
	ipa_buf_free(enc);

	free(eim_tid.buf);
	ipa_buf_free(ipa_free_ctx(ctx));
}


/* eim_pkg_exec() is not declared in a header; the poll loop in the same file is its only caller. */
int eim_pkg_exec(struct ipa_context *ctx, const struct ipa_esipa_get_eim_pkg_res *get_eim_pkg_res);

/* The two encoder cases above prove the message can be built.  This proves the procedure actually builds
 * it: an unusable ProfileDownloadTriggerRequest used to end the poll cycle with nothing sent, leaving the
 * eIM to time the dispatched operation out.  Sections 3.2.3.1 / 3.2.3.2 step 3 require the IPA to answer.
 *
 * Driven through eim_pkg_exec() with the HTTP stub capturing what went out, so what is checked is the
 * request the library put on the wire, not an encoder called directly. */
static void asn1_trigger_rejection_test(void)
{
	static const struct {
		const char *what;
		bool with_download_data;
	} cases[] = {
		{ "no profileDownloadData    ", false },
		{ "profileDownloadData != AC ", true },
	};
	struct ipa_config cfg;
	struct ipa_context *ctx = test_ctx(&cfg, IPA_ESIPA_BINDING_ASN1);
	unsigned int i;

	printf("== asn1_trigger_rejection_test ==\n");
	memcpy(ctx->eid, eid_bytes, IPA_LEN_EID);

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		struct ipa_esipa_get_eim_pkg_res get_eim_pkg_res = { 0 };
		struct ProfileDownloadTriggerRequest trigger = { 0 };
		struct ProfileDownloadData dwnld_data = { 0 };
		struct EsipaMessageFromIpaToEim *msg = NULL;
		struct EimPackageResultResponseError *err;
		TransactionId_t eim_tid = { 0 };
		asn_dec_rval_t dr;

		set_transaction_id(&eim_tid);
		trigger.eimTransactionId = &eim_tid;
		if (cases[i].with_download_data) {
			/* A branch this IPAd does not implement: the data is there, but not as an
			 * Activation Code, so it still cannot start a download. */
			dwnld_data.present = ProfileDownloadData_PR_contactDefaultSmdp;
			trigger.profileDownloadData = &dwnld_data;
		}
		get_eim_pkg_res.dwnld_trigger_request = &trigger;

		ipa_buf_free(captured_req);
		captured_req = NULL;
		assert(eim_pkg_exec(ctx, &get_eim_pkg_res) < 0);

		/* The point of the whole fix: something was sent. */
		assert(captured_req);
		dr = ber_decode(NULL, &asn_DEF_EsipaMessageFromIpaToEim, (void **)&msg,
				captured_req->data, captured_req->len);
		assert(dr.code == RC_OK && msg);
		assert(msg->present == EsipaMessageFromIpaToEim_PR_provideEimPackageResult);
		assert(msg->choice.provideEimPackageResult.eimPackageResult.present ==
		       EimPackageResult_PR_eimPackageResultResponseError);
		err = &msg->choice.provideEimPackageResult.eimPackageResult.choice.eimPackageResultResponseError;
		assert(err->eimPackageResultErrorCode == EimPackageResultErrorCode_invalidPackageFormat);
		assert(err->eimTransactionId &&
		       err->eimTransactionId->size == sizeof(transaction_id_bytes) &&
		       memcmp(err->eimTransactionId->buf, transaction_id_bytes,
			      sizeof(transaction_id_bytes)) == 0);
		printf("   %s -> invalidPackageFormat sent, eimTransactionId echoed\n", cases[i].what);
		ASN_STRUCT_FREE(asn_DEF_EsipaMessageFromIpaToEim, msg);
		free(eim_tid.buf);
	}

	ipa_buf_free(captured_req);
	captured_req = NULL;
	ipa_buf_free(ipa_free_ctx(ctx));
}


/* The trigger sites above are not the only eIM Packages that can turn out to be unusable.  A
 * GetEimPackageResponse that carries none of the request types this IPA implements used to end the
 * poll cycle in silence too, and SGP.32 section 6.3.2.7's echo rule applies to whatever is reported.
 *
 * unknownPackage carries no eimTransactionId, and that is not an omission: the id travels inside the
 * request object, and which request this is, is exactly what could not be established. */
static void asn1_unknown_package_test(void)
{
	struct ipa_esipa_get_eim_pkg_res get_eim_pkg_res = { 0 };
	struct EsipaMessageFromIpaToEim *msg = NULL;
	struct EimPackageResultResponseError *err;
	struct ipa_config cfg;
	struct ipa_context *ctx = test_ctx(&cfg, IPA_ESIPA_BINDING_ASN1);
	asn_dec_rval_t dr;

	printf("== asn1_unknown_package_test ==\n");
	memcpy(ctx->eid, eid_bytes, IPA_LEN_EID);

	/* Every request member left NULL: nothing this IPA knows how to act on. */
	ipa_buf_free(captured_req);
	captured_req = NULL;
	assert(eim_pkg_exec(ctx, &get_eim_pkg_res) < 0);

	assert(captured_req);
	dr = ber_decode(NULL, &asn_DEF_EsipaMessageFromIpaToEim, (void **)&msg,
			captured_req->data, captured_req->len);
	assert(dr.code == RC_OK && msg);
	assert(msg->present == EsipaMessageFromIpaToEim_PR_provideEimPackageResult);
	assert(msg->choice.provideEimPackageResult.eimPackageResult.present ==
	       EimPackageResult_PR_eimPackageResultResponseError);
	err = &msg->choice.provideEimPackageResult.eimPackageResult.choice.eimPackageResultResponseError;
	assert(err->eimPackageResultErrorCode == EimPackageResultErrorCode_unknownPackage);
	assert(err->eimTransactionId == NULL);
	printf("   unsupported request type -> unknownPackage sent, no transaction id to echo\n");
	ASN_STRUCT_FREE(asn_DEF_EsipaMessageFromIpaToEim, msg);

	ipa_buf_free(captured_req);
	captured_req = NULL;
	ipa_buf_free(ipa_free_ctx(ctx));
}


/* An eUICC Package the eUICC never answered.  There is no EuiccPackageResult to forward -- the eUICC
 * produces that, and it produced nothing -- so the eIM hears nothing at all unless the IPA says so
 * itself.  The eimTransactionId to echo is the one the eIM signed into euiccPackageSigned.
 *
 * The eUICC here is the stub at the bottom of this file, which answers nothing, so LoadEuiccPackage
 * fails the way it would against an unresponsive card. */
static void asn1_euicc_pkg_failure_test(void)
{
	struct ipa_esipa_get_eim_pkg_res get_eim_pkg_res = { 0 };
	struct EuiccPackageRequest euicc_package_request = { 0 };
	struct EsipaMessageFromIpaToEim *msg = NULL;
	struct EimPackageResultResponseError *err;
	struct ipa_config cfg;
	struct ipa_context *ctx = test_ctx(&cfg, IPA_ESIPA_BINDING_ASN1);
	TransactionId_t eim_tid = { 0 };
	asn_dec_rval_t dr;

	printf("== asn1_euicc_pkg_failure_test ==\n");
	memcpy(ctx->eid, eid_bytes, IPA_LEN_EID);
	set_transaction_id(&eim_tid);
	euicc_package_request.euiccPackageSigned.eimTransactionId = &eim_tid;
	get_eim_pkg_res.euicc_package_request = &euicc_package_request;

	ipa_buf_free(captured_req);
	captured_req = NULL;
	assert(eim_pkg_exec(ctx, &get_eim_pkg_res) < 0);

	assert(captured_req);
	dr = ber_decode(NULL, &asn_DEF_EsipaMessageFromIpaToEim, (void **)&msg,
			captured_req->data, captured_req->len);
	assert(dr.code == RC_OK && msg);
	assert(msg->choice.provideEimPackageResult.eimPackageResult.present ==
	       EimPackageResult_PR_eimPackageResultResponseError);
	err = &msg->choice.provideEimPackageResult.eimPackageResult.choice.eimPackageResultResponseError;
	/* Not invalidPackageFormat: the package may well have been fine, the eUICC just did not answer. */
	assert(err->eimPackageResultErrorCode == EimPackageResultErrorCode_undefinedError);
	assert(err->eimTransactionId && err->eimTransactionId->size == sizeof(transaction_id_bytes));
	assert(memcmp(err->eimTransactionId->buf, transaction_id_bytes, sizeof(transaction_id_bytes)) == 0);
	printf("   eUICC did not answer     -> undefinedError sent, eimTransactionId echoed\n");
	ASN_STRUCT_FREE(asn_DEF_EsipaMessageFromIpaToEim, msg);

	free(eim_tid.buf);
	ipa_buf_free(captured_req);
	captured_req = NULL;
	ipa_buf_free(ipa_free_ctx(ctx));
}

#endif /* IPA_HAVE_ESIPA_ASN1 */


#ifdef IPA_HAVE_ESIPA_JSON
/* The JSON binding used to decode any response body it could parse as a success: it allocated an "Ok"
 * structure up front and attached it whatever the body turned out to contain.  An eIM reporting a
 * failure therefore reached the procedure layer as a successful call with every field absent, and the
 * "no Ok member" guard there could not catch it because the member was always present.
 *
 * These feed each decoder a response the eIM would send on failure and check two things: the code is
 * reported, and no "Ok" structure is attached. */
static struct ipa_buf *json_body(const char *text)
{
	struct ipa_buf *buf = ipa_buf_alloc(strlen(text));

	memcpy(buf->data, text, strlen(text));
	buf->len = strlen(text);
	return buf;
}

/* Build a <JSON responseMessage>: the responseHeader of SGP.22 section 6.5.1.4, which SGP.32 section
 * 6.1.2 binds the ESipa JSON responses to, followed by whatever body the function defines. */
static struct ipa_buf *json_failed(const char *subject_code, const char *reason_code, const char *body)
{
	char buf[512];

	snprintf(buf, sizeof(buf),
		 "{\"header\":{\"functionExecutionStatus\":{\"status\":\"Failed\","
		 "\"statusCodeData\":{\"subjectCode\":\"%s\",\"reasonCode\":\"%s\","
		 "\"message\":\"test\"}}}%s%s}",
		 subject_code, reason_code, body ? "," : "", body ? body : "");
	return json_body(buf);
}

static void json_error_response_test(void)
{
	struct ipa_buf *body;

	printf("== json_error_response_test ==\n");

	{
		struct ipa_esipa_init_auth_res *res;

		/* Section 5.14.1, Table 9a: 8.8.1 / 3.10 "(maps to smdpAddressMismatch)". */
		body = json_failed("8.8.1", "3.10", NULL);
		res = ipa_esipa_json_dec_init_auth_res(body);
		assert(res);
		assert(res->init_auth_err ==
		       InitiateAuthenticationResponseEsipa__initiateAuthenticationErrorEsipa_smdpAddressMismatch);
		assert(res->init_auth_ok == NULL);
		printf("   InitiateAuthentication  8.8.1/3.10  -> smdpAddressMismatch, no Ok attached\n");
		ipa_esipa_init_auth_res_free(res);
		ipa_buf_free(body);

		/* 8.8 and 8.8.1 share a reason code and differ only in the subject, so a prefix match would
		 * confuse the two. */
		body = json_failed("8.8", "3.10", NULL);
		res = ipa_esipa_json_dec_init_auth_res(body);
		assert(res);
		assert(res->init_auth_err ==
		       InitiateAuthenticationResponseEsipa__initiateAuthenticationErrorEsipa_smdpOidMismatch);
		printf("   InitiateAuthentication  8.8/3.10    -> smdpOidMismatch, not confused with 8.8.1\n");
		ipa_esipa_init_auth_res_free(res);
		ipa_buf_free(body);

		/* A code Table 9a does not list still has to fail the call, as undefinedError. */
		body = json_failed("1.3.1", "2.1", NULL);
		res = ipa_esipa_json_dec_init_auth_res(body);
		assert(res);
		assert(res->init_auth_err ==
		       InitiateAuthenticationResponseEsipa__initiateAuthenticationErrorEsipa_undefinedError);
		assert(res->init_auth_ok == NULL);
		printf("   InitiateAuthentication  unlisted    -> undefinedError, no Ok attached\n");
		ipa_esipa_init_auth_res_free(res);
		ipa_buf_free(body);
	}

	{
		struct ipa_esipa_auth_clnt_res *res;

		/* Section 5.14.3, Table 13a: 8.2.8 / 1.2 "(maps to pprNotAllowed)". */
		body = json_failed("8.2.8", "1.2", NULL);
		res = ipa_esipa_json_dec_auth_clnt_res(body, NULL);
		assert(res);
		assert(res->auth_clnt_err ==
		       AuthenticateClientResponseEsipa__authenticateClientErrorEsipa_pprNotAllowed);
		assert(res->auth_clnt_ok_dpe == NULL);
		assert(res->auth_clnt_ok_dse == NULL);
		printf("   AuthenticateClient      8.2.8/1.2   -> pprNotAllowed, no Ok attached\n");
		ipa_esipa_auth_clnt_res_free(res);
		ipa_buf_free(body);
	}

	{
		struct ipa_esipa_get_bnd_prfle_pkg_res *res;

		/* Section 5.14.2, Table 11a: 8.2.9 / 3.11 "(maps to metadataMismatch)".  The one with a
		 * procedure consequence: section 3.2.3.3 requires the CancelSession that follows to carry
		 * reason code metadataMismatch, which proc_prfle_dwnld.c derives from this field. */
		body = json_failed("8.2.9", "3.11", NULL);
		res = ipa_esipa_json_dec_get_bnd_prfle_pkg_res(body);
		assert(res);
		assert(res->get_bnd_prfle_pkg_err ==
		       GetBoundProfilePackageResponseEsipa__getBoundProfilePackageErrorEsipa_metadataMismatch);
		assert(res->get_bnd_prfle_pkg_ok == NULL);
		printf("   GetBoundProfilePackage  8.2.9/3.11  -> metadataMismatch, no Ok attached\n");
		ipa_esipa_get_bnd_prfle_pkg_res_free(res);
		ipa_buf_free(body);
	}

	{
		struct ipa_esipa_get_eim_pkg_res *res;

		/* GetEimPackage is the only function with both mechanisms, so both are checked.  Section
		 * 5.14.5 Table 18: 8.1.1 / 3.9 "(maps to eidNotFound)". */
		body = json_failed("8.1.1", "3.9", NULL);
		res = ipa_esipa_json_dec_get_eim_pkg_res(body);
		assert(res);
		assert(res->eim_pkg_err == GetEimPackageResponse__eimPackageError_eidNotFound);
		assert(res->euicc_package_request == NULL);
		assert(res->ipa_euicc_data_request == NULL);
		assert(res->dwnld_trigger_request == NULL);
		printf("   GetEimPackage           8.1.1/3.9   -> eidNotFound via the response header\n");
		ipa_esipa_get_eim_pkg_free(res);
		ipa_buf_free(body);

		/* The body arm of section 6.4.1.5, which this function has in addition to the header.  The
		 * header is mandatory either way, so a conforming eIM using the body arm still sends one. */
		body = json_body("{\"header\":{\"functionExecutionStatus\":{\"status\":\"Executed-Success\"}},"
				 "\"eimPackageError\":2}");
		res = ipa_esipa_json_dec_get_eim_pkg_res(body);
		assert(res);
		assert(res->eim_pkg_err == GetEimPackageResponse__eimPackageError_eidNotFound);
		printf("   GetEimPackage           body arm    -> eidNotFound via eimPackageError\n");
		ipa_esipa_get_eim_pkg_free(res);
		ipa_buf_free(body);

		/* A success must survive a header that says so, and still be decoded from the body. */
		body = json_body("{\"header\":{\"functionExecutionStatus\":{\"status\":\"Executed-Success\"}},"
				 "\"eimPackageError\":1}");
		res = ipa_esipa_json_dec_get_eim_pkg_res(body);
		assert(res);
		assert(res->eim_pkg_err == GetEimPackageResponse__eimPackageError_noEimPackageAvailable);
		printf("   GetEimPackage           success hdr -> body still decoded\n");
		ipa_esipa_get_eim_pkg_free(res);
		ipa_buf_free(body);
	}

	{
		struct ipa_esipa_prvde_eim_pkg_rslt_res *res;

		/* Section 5.14.6, Table 21: 8.1.1 / 2.2 "(maps to missingEid)".  A refusal and an acceptance
		 * with nothing to acknowledge both leave eimAcknowledgements NULL, so this code is the only
		 * thing that separates them -- and the caller must keep the result on a refusal. */
		body = json_failed("8.1.1", "2.2", NULL);
		res = ipa_esipa_json_dec_prvde_eim_pkg_rslt_res(body);
		assert(res);
		assert(res->prvde_eim_pkg_rslt_err ==
		       ProvideEimPackageResultResponse__provideEimPackageResultError_missingEid);
		assert(res->eim_acknowledgements == NULL);
		printf("   ProvideEimPackageResult 8.1.1/2.2   -> missingEid, result must be kept\n");
		ipa_esipa_prvde_eim_pkg_rslt_free(res);
		ipa_buf_free(body);
	}
}

/* A body that carries neither a result nor an error code must not become a success either.  This is
 * the case the procedure layer's "no Ok member" guard was written for, and that the unconditional
 * allocation defeated. */
/* The response header of SGP.22 section 6.5.1.4 is mandatory on every ESipa response (SGP.32 section
 * 6.1.2), and it is what says whether the function succeeded.  A response that omits it, or that
 * reports a status this interface does not define, cannot be read as a success -- and must not be
 * read as one just because it never said otherwise. */
static void json_malformed_header_test(void)
{
	static const struct {
		const char *what;
		const char *body;
	} cases[] = {
		{ "no header at all       ", "{}" },
		{ "header, no status      ", "{\"header\":{\"functionExecutionStatus\":{}}}" },
		{ "status of another kind ", "{\"header\":{\"functionExecutionStatus\":"
					     "{\"status\":\"Executed-WithWarning\"}}}" },
		{ "status not a string    ", "{\"header\":{\"functionExecutionStatus\":{\"status\":7}}}" },
		{ "header not an object   ", "{\"header\":\"Executed-Success\"}" },
		/* statusCodeData is OPTIONAL, so a bare "Failed" is conforming -- it just does not say why. */
		{ "failed, no status code ", "{\"header\":{\"functionExecutionStatus\":{\"status\":\"Failed\"}}}" },
		/* subjectCode and reasonCode are required together; one alone says no more than neither. */
		{ "reasonCode missing     ", "{\"header\":{\"functionExecutionStatus\":{\"status\":\"Failed\","
					     "\"statusCodeData\":{\"subjectCode\":\"8.8.1\"}}}}" },
	};
	unsigned int i;

	printf("== json_malformed_header_test ==\n");

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		struct ipa_buf *body = json_body(cases[i].body);
		struct ipa_esipa_init_auth_res *ia;
		struct ipa_esipa_auth_clnt_res *ac;
		struct ipa_esipa_get_bnd_prfle_pkg_res *gb;

		ia = ipa_esipa_json_dec_init_auth_res(body);
		assert(ia && ia->init_auth_ok == NULL);
		assert(ia->init_auth_err ==
		       InitiateAuthenticationResponseEsipa__initiateAuthenticationErrorEsipa_undefinedError);
		ipa_esipa_init_auth_res_free(ia);

		ac = ipa_esipa_json_dec_auth_clnt_res(body, NULL);
		assert(ac && ac->auth_clnt_ok_dpe == NULL && ac->auth_clnt_ok_dse == NULL);
		assert(ac->auth_clnt_err ==
		       AuthenticateClientResponseEsipa__authenticateClientErrorEsipa_undefinedError);
		ipa_esipa_auth_clnt_res_free(ac);

		gb = ipa_esipa_json_dec_get_bnd_prfle_pkg_res(body);
		assert(gb && gb->get_bnd_prfle_pkg_ok == NULL);
		assert(gb->get_bnd_prfle_pkg_err ==
		       GetBoundProfilePackageResponseEsipa__getBoundProfilePackageErrorEsipa_undefinedError);
		ipa_esipa_get_bnd_prfle_pkg_res_free(gb);

		printf("   %s -> undefinedError, no Ok attached\n", cases[i].what);
		ipa_buf_free(body);
	}
}

/* CancelSession has no response body of its own (section 6.4.1.8), so the header is the entire
 * response and the only place a refusal can appear.  The JSON decoder used to ignore the body outright
 * and report success unconditionally. */
static void json_cancel_session_status_test(void)
{
	struct ipa_buf *body;

	printf("== json_cancel_session_status_test ==\n");

	body = json_body("{\"header\":{\"functionExecutionStatus\":{\"status\":\"Executed-Success\"}}}");
	assert(ipa_esipa_json_exec_ok(body, "CancelSession"));
	printf("   Executed-Success        -> accepted\n");
	ipa_buf_free(body);

	body = json_failed("1.3.1", "2.1", NULL);
	assert(!ipa_esipa_json_exec_ok(body, "CancelSession"));
	printf("   Failed                  -> refused\n");
	ipa_buf_free(body);

	body = json_body("{}");
	assert(!ipa_esipa_json_exec_ok(body, "CancelSession"));
	printf("   no header               -> refused\n");
	ipa_buf_free(body);

	body = json_body("not json at all");
	assert(!ipa_esipa_json_exec_ok(body, "CancelSession"));
	printf("   unparseable             -> refused\n");
	ipa_buf_free(body);
}
/* The JSON binding carries the very same EimPackageResult, base64 of its DER (section 6.4.1.6), so the
 * rejection and its echoed eimTransactionId have to survive that route unchanged.  Checking the bytes
 * rather than a re-decode keeps the two bindings honest against one another: the expected value here is
 * built independently and must come out identical to what the encoder produced. */
static void json_eim_pkg_err_report_test(void)
{
	static const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	struct ipa_esipa_prvde_eim_pkg_rslt_req req = { 0 };
	struct EimPackageResult expected = { 0 };
	struct ipa_config cfg;
	struct ipa_context *ctx = test_ctx(&cfg, IPA_ESIPA_BINDING_JSON);
	TransactionId_t eim_tid = { 0 };
	char encoded[512];
	asn_enc_rval_t er;
	struct ipa_buf *enc;
	size_t i, o = 0;

	printf("== json_eim_pkg_err_report_test ==\n");
	memcpy(ctx->eid, eid_bytes, IPA_LEN_EID);
	set_transaction_id(&eim_tid);

	/* What the wire should carry, built here rather than taken from the encoder under test. */
	expected.present = EimPackageResult_PR_eimPackageResultResponseError;
	expected.choice.eimPackageResultResponseError.eimPackageResultErrorCode =
	    EimPackageResultErrorCode_invalidPackageFormat;
	expected.choice.eimPackageResultResponseError.eimTransactionId = &eim_tid;
	esipa_enc_len = 0;
	er = der_encode(&asn_DEF_EimPackageResult, &expected, esipa_enc_sink, NULL);
	assert(er.encoded > 0);

	for (i = 0; i + 2 < esipa_enc_len; i += 3) {
		uint32_t v = (esipa_enc_buf[i] << 16) | (esipa_enc_buf[i + 1] << 8) | esipa_enc_buf[i + 2];
		encoded[o++] = b64[(v >> 18) & 0x3f];
		encoded[o++] = b64[(v >> 12) & 0x3f];
		encoded[o++] = b64[(v >> 6) & 0x3f];
		encoded[o++] = b64[v & 0x3f];
	}
	if (esipa_enc_len - i == 1) {
		encoded[o++] = b64[(esipa_enc_buf[i] >> 2) & 0x3f];
		encoded[o++] = b64[(esipa_enc_buf[i] << 4) & 0x3f];
		encoded[o++] = '=';
		encoded[o++] = '=';
	} else if (esipa_enc_len - i == 2) {
		uint32_t v = (esipa_enc_buf[i] << 8) | esipa_enc_buf[i + 1];
		encoded[o++] = b64[(v >> 10) & 0x3f];
		encoded[o++] = b64[(v >> 4) & 0x3f];
		encoded[o++] = b64[(v << 2) & 0x3f];
		encoded[o++] = '=';
	}
	encoded[o] = '\0';

	req.eim_pkg_err = EimPackageResultErrorCode_invalidPackageFormat;
	req.eim_transaction_id = &eim_tid;
	enc = ipa_esipa_json_enc_prvde_eim_pkg_rslt_req(ctx, &req);
	assert(enc);
	printf("   %.*s\n", (int)enc->len, (const char *)enc->data);
	assert(req_contains(enc, "\"eidValue\":\"" EID_DIGITS "\"", strlen("\"eidValue\":\"" EID_DIGITS "\"")));
	assert(req_contains(enc, encoded, o));
	printf("   invalidPackageFormat         -> same EimPackageResult DER as the ASN.1 binding\n");
	ipa_buf_free(enc);

	free(eim_tid.buf);
	ipa_buf_free(ipa_free_ctx(ctx));
}

#endif /* IPA_HAVE_ESIPA_JSON */

/* Both bindings must describe one error code by one name.  #25 fixed a case where the ASN.1 binding
 * printed the wrong one; nothing should reintroduce a second table. */
static void error_name_test(void)
{
	printf("== error_name_test ==\n");

	assert(strcmp(ipa_esipa_auth_clnt_err_str(
		      AuthenticateClientResponseEsipa__authenticateClientErrorEsipa_pprNotAllowed),
		      "pprNotAllowed") == 0);
	assert(strcmp(ipa_esipa_auth_clnt_err_str(
		      AuthenticateClientResponseEsipa__authenticateClientErrorEsipa_eidMismatch),
		      "eidMismatch") == 0);
	assert(strcmp(ipa_esipa_init_auth_err_str(
		      InitiateAuthenticationResponseEsipa__initiateAuthenticationErrorEsipa_smdpOidMismatch),
		      "smdpOidMismatch") == 0);
	assert(strcmp(ipa_esipa_get_bnd_prfle_pkg_err_str(
		      GetBoundProfilePackageResponseEsipa__getBoundProfilePackageErrorEsipa_metadataMismatch),
		      "metadataMismatch") == 0);
	assert(strcmp(ipa_esipa_get_eim_pkg_err_str(
		      GetEimPackageResponse__eimPackageError_missingEid), "missingEid") == 0);
	/* A code the set does not define must not be given a neighbour's name. */
	assert(strcmp(ipa_esipa_auth_clnt_err_str(9999), "(unknown)") == 0);
	printf("   shared tables           -> both bindings name codes identically\n");
}

int main(int argc, char **argv)
{
	transaction_id_lookup_test();
	rplmn_encoding_test();
	error_name_test();
#ifdef IPA_HAVE_ESIPA_ASN1
	asn1_init_auth_transaction_id_test();
	asn1_get_eim_pkg_test();
	asn1_prvde_eim_pkg_rslt_response_test();
	asn1_eim_pkg_err_report_test();
	asn1_trigger_rejection_test();
	asn1_unknown_package_test();
	asn1_euicc_pkg_failure_test();
#else
	printf("== ASN.1 binding not built, its encoder cases skipped ==\n");
#endif
#ifdef IPA_HAVE_ESIPA_JSON
	json_request_test();
	json_auth_clnt_descriptor_test();
	json_refuses_without_transaction_id_test();
	json_init_auth_transaction_id_test();
	json_get_eim_pkg_test();
	json_error_response_test();
	json_malformed_header_test();
	json_cancel_session_status_test();
	json_eim_pkg_err_report_test();
#else
	printf("== JSON binding not built, its encoder cases skipped ==\n");
#endif
	printf("esipa_bindings_test: all checks passed\n");
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

struct ipa_buf *ipa_http_req_with_ct(void *http_ctx, const struct ipa_buf *req, const char *url,
				     const char *content_type)
{
	/* Keep what the library wanted to send, then fail the request: the tests above examine the
	 * captured bytes, and no eIM response is needed to do that. */
	ipa_buf_free(captured_req);
	captured_req = ipa_buf_dup((struct ipa_buf *)req);
	return NULL;
}

/* The stub above never lets a request complete, so there is never a status to report. */
long ipa_http_last_status(void *http_ctx)
{
	return 0;
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
