/*
 * Copyright (c) 2025 Onomondo ApS & sysmocom - s.f.m.c. GmbH. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#pragma once

#include <EsipaMessageFromEimToIpa.h>
#include <EsipaMessageFromIpaToEim.h>
#include <SGP32-RetrieveNotificationsListResponse.h>
#include <RetrieveNotificationsListResponse.h>
struct ipa_buf;

#define IPA_LOGP_ESIPA(func, level, fmt, args...) \
	IPA_LOGP(SESIPA, level, "%s: " fmt, func, ## args)

#define IPA_ESIPA_URL_MAXLEN 1024

char *ipa_esipa_get_eim_url(struct ipa_context *ctx);
char *ipa_esipa_get_eim_url_for(struct ipa_context *ctx, const char *function_name);
struct EsipaMessageFromEimToIpa *ipa_esipa_msg_to_ipa_dec(const struct ipa_buf *msg_to_ipa_encoded,
							  const char *function_name,
							  enum EsipaMessageFromEimToIpa_PR epected_res_type);
struct ipa_buf *ipa_esipa_msg_to_eim_enc(const struct EsipaMessageFromIpaToEim *msg_to_eim, const char *function_name);
struct ipa_buf *ipa_esipa_req(struct ipa_context *ctx, const struct ipa_buf *esipa_req, const char *function_name);
void ipa_esipa_close(struct ipa_context *ctx);

/* Encode an ESipa request body from an opaque per-function request object.
 * ctx is passed for the few encoders that need it (e.g. ProvideEimPackageResult);
 * others ignore it.  Returns a newly allocated buffer, NULL on error. */
typedef struct ipa_buf *(*ipa_esipa_enc_cb)(struct ipa_context *ctx, const void *req);

/* Decode an ESipa response body into a newly allocated per-function result
 * object.  req is passed for the few decoders that cross-check the request
 * (e.g. AuthenticateClient transaction id); others ignore it.  Returns NULL on
 * error. */
typedef void *(*ipa_esipa_dec_cb)(const struct ipa_buf *res, const void *req);

/*! Pass a binding's encoder/decoder pair to ipa_esipa_call(), or a pair of NULLs when this build does not have that
 *  binding (see ESIPA_BINDING_ASN1 / ESIPA_BINDING_JSON in the top-level CMakeLists.txt).  The per-function
 *  encoders and decoders behind them are compiled under the same conditions, so a binding that is not built leaves
 *  nothing to link and nothing to strip. */
#ifdef IPA_HAVE_ESIPA_ASN1
#define IPA_ESIPA_ASN1_CB(enc, dec) (enc), (dec)
#else
#define IPA_ESIPA_ASN1_CB(enc, dec) NULL, NULL
#endif
#ifdef IPA_HAVE_ESIPA_JSON
#define IPA_ESIPA_JSON_CB(enc, dec) (enc), (dec)
#else
#define IPA_ESIPA_JSON_CB(enc, dec) NULL, NULL
#endif

/*! Run the common ESipa round-trip shared by every ipa_esipa_* function:
 *  select the ASN.1 vs JSON binding from ctx->cfg->esipa_binding, encode the
 *  request, send it via ipa_esipa_req(), then decode the response.  Both
 *  intermediate buffers are always freed before returning.  The callbacks of a
 *  binding this build does not have are NULL (see IPA_ESIPA_ASN1_CB above), and
 *  asking for such a binding fails the call with a log line saying so.
 *  \returns the decoded result object, or NULL on any failure. */
void *ipa_esipa_call(struct ipa_context *ctx, const char *function_name, const void *req,
		     ipa_esipa_enc_cb enc, ipa_esipa_dec_cb dec,
		     ipa_esipa_enc_cb json_enc, ipa_esipa_dec_cb json_dec);

/*! A helper macro to free the basic contents of an ESIPA response. This macro is intended to be used from within the
 *  concrete implementation of an ESIPA function. It only frees the common contents and the struct itsself. In case
 *  there are other additional fields, the caller must free those first before calling this macro.
 *  \param[in] res pointer struct that holds the ESIPA response. */
#define IPA_ESIPA_RES_FREE(res) ({ \
	if (!(res)) \
		return; \
	ASN_STRUCT_FREE(asn_DEF_EsipaMessageFromEimToIpa, (res)->msg_to_ipa); \
	IPA_FREE((res)); \
})
