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
#include "src/ipa/libipa/esipa_json.h"

static uint8_t transaction_id_bytes[] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };
#define TRANSACTION_ID_HEX "\"transactionId\":\"0123456789ABCDEF\""

static void set_transaction_id(TransactionId_t *tid)
{
	tid->buf = malloc(sizeof(transaction_id_bytes));
	assert(tid->buf);
	memcpy(tid->buf, transaction_id_bytes, sizeof(transaction_id_bytes));
	tid->size = sizeof(transaction_id_bytes);
}

/* A PrepareDownloadResponse complete enough to be DER encoded. */
static struct PrepareDownloadResponse *response_ok(void)
{
	struct PrepareDownloadResponse *pdr = calloc(1, sizeof(*pdr));
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
	struct PrepareDownloadResponse *pdr = calloc(1, sizeof(*pdr));

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
	const TransactionId_t *tid;

	printf("== transaction_id_lookup_test ==\n");

	tid = ipa_esipa_get_bnd_prfle_pkg_transaction_id(response_ok());
	assert(tid && tid->size == (int)sizeof(transaction_id_bytes));
	assert(memcmp(tid->buf, transaction_id_bytes, sizeof(transaction_id_bytes)) == 0);

	tid = ipa_esipa_get_bnd_prfle_pkg_transaction_id(response_error());
	assert(tid && tid->size == (int)sizeof(transaction_id_bytes));
	assert(memcmp(tid->buf, transaction_id_bytes, sizeof(transaction_id_bytes)) == 0);

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
	struct ipa_buf *buf;

	printf("== json_request_test ==\n");

	/* The downloadResponseOk branch. */
	req.prep_dwnld_res = response_ok();
	buf = ipa_esipa_json_enc_get_bnd_prfle_pkg_req(&req);
	assert(buf);
	assert(memmem(buf->data, buf->len, TRANSACTION_ID_HEX, strlen(TRANSACTION_ID_HEX)));
	assert(memmem(buf->data, buf->len, "\"prepareDownloadResponse\"", 25));
	printf("   ok:    %.*s\n", (int)buf->len, (const char *)buf->data);
	ipa_buf_free(buf);

	/* The downloadResponseError branch carries the transaction id somewhere else, and must still emit it. */
	req.prep_dwnld_res = response_error();
	buf = ipa_esipa_json_enc_get_bnd_prfle_pkg_req(&req);
	assert(buf);
	assert(memmem(buf->data, buf->len, TRANSACTION_ID_HEX, strlen(TRANSACTION_ID_HEX)));
	printf("   error: %.*s\n", (int)buf->len, (const char *)buf->data);
	ipa_buf_free(buf);
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
	ctx->eim_fqdn = strdup("eim.example.com");
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

int main(int argc, char **argv)
{
	transaction_id_lookup_test();
	rplmn_encoding_test();
#ifdef IPA_HAVE_ESIPA_ASN1
	asn1_init_auth_transaction_id_test();
	asn1_get_eim_pkg_test();
#else
	printf("== ASN.1 binding not built, its encoder cases skipped ==\n");
#endif
#ifdef IPA_HAVE_ESIPA_JSON
	json_request_test();
	json_refuses_without_transaction_id_test();
	json_init_auth_transaction_id_test();
	json_get_eim_pkg_test();
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
