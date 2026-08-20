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
 */

#define _GNU_SOURCE		/* memmem() */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <stdbool.h>
#include <onomondo/ipa/utils.h>
#include "src/ipa/libipa/esipa_get_bnd_prfle_pkg.h"
#include "src/ipa/libipa/esipa_init_auth.h"
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

#ifdef IPA_HAVE_JANSSON

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

#endif /* IPA_HAVE_JANSSON */

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

#ifdef IPA_HAVE_JANSSON

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

#endif /* IPA_HAVE_JANSSON */

int main(int argc, char **argv)
{
	transaction_id_lookup_test();
	asn1_init_auth_transaction_id_test();
#ifdef IPA_HAVE_JANSSON
	json_request_test();
	json_refuses_without_transaction_id_test();
	json_init_auth_transaction_id_test();
#else
	printf("== JSON binding not built (jansson missing), encoder cases skipped ==\n");
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
