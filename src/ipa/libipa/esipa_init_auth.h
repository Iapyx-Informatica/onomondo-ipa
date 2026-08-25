/*
 * Copyright (c) 2025 Onomondo ApS & sysmocom - s.f.m.c. GmbH. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#pragma once

#include <stdint.h>
#include <EUICCInfo1.h>
#include <TransactionId.h>
#include <EsipaMessageFromEimToIpa.h>
#include <InitiateAuthenticationOkEsipa.h>
struct ipa_context;

struct ipa_esipa_init_auth_req {
	const uint8_t *euicc_challenge;
	const char *smdp_addr;
	const EUICCInfo1_t *euicc_info_1;

	/*! Transaction id the eIM sent in the ProfileDownloadTriggerRequest that started this download, NULL when
	 *  the download was not triggered by an eIM. SGP.32, section 5.14.1: "If the eIM has sent
	 *  eimTransactionId in ProfileDownloadTriggerRequest, the IPA SHALL include the same
	 *  eimTransactionId", which is how the eIM identifies the session it belongs to. */
	const TransactionId_t *eim_transaction_id;
};

struct ipa_esipa_init_auth_res {
	struct EsipaMessageFromEimToIpa *msg_to_ipa;
	struct InitiateAuthenticationOkEsipa *init_auth_ok;
	long init_auth_err;
};

/* Encode an ESipa.InitiateAuthentication request in the ASN.1 binding. ctx is unused and may be NULL; the
 * signature matches ipa_esipa_enc_cb so it can be handed to ipa_esipa_call(). Exposed for the unit tests. */
struct ipa_buf *ipa_esipa_init_auth_enc_req(struct ipa_context *ctx, const void *req);

struct ipa_esipa_init_auth_res *ipa_esipa_init_auth(struct ipa_context *ctx, const struct ipa_esipa_init_auth_req *req);
void ipa_esipa_init_auth_res_free(struct ipa_esipa_init_auth_res *res);

/*! Name of an ESipa.InitiateAuthentication error code, for log messages.  Shared by the ASN.1 and
 *  JSON bindings so that one code is never described by two different names. */
const char *ipa_esipa_init_auth_err_str(long err);
