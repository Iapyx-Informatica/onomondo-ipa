/*
 * Copyright (c) 2025 Onomondo ApS & sysmocom - s.f.m.c. GmbH. All rights reserved.
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * NEW in v1.1/v1.2: §6.4 — JSON binding for the ESipa interface.
 *
 * Design notes
 * ------------
 * Most JSON fields carry a base64 wrapping of a DER-encoded ASN.1 structure
 * (section numbers and notes per v1.2 §6.4.1.*).  We therefore reuse the
 * existing libasn codec to produce / consume those DER bytes, and only
 * add a base64 wrapping layer plus the outer JSON envelope.
 *
 * A handful of fields do not follow the base64+DER convention:
 *   - TransactionId:   hex string ("^[0-9A-F]{2,32}$"), no base64.
 *   - eidValue:        32-digit decimal string.
 *   - euiccChallenge:  base64 of the raw OCTET STRING *value* only (no DER
 *                      tag / length).
 *   - matchingId, smdpAddress: plain JSON strings.
 *   - eimPackageError, stateChangeCause: plain JSON integers.
 *
 * Compile-time switch: IPA_HAVE_ESIPA_JSON (set from CMake when jansson is
 * detected).  When absent, every entrypoint returns NULL / -1 so the
 * ASN.1 binding continues to work unchanged.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <ctype.h>
#include <onomondo/ipa/mem.h>
#include <onomondo/ipa/utils.h>
#include <onomondo/ipa/ipad.h>
#include <onomondo/ipa/log.h>
#include "length.h"
#include "utils.h"
#include "esipa.h"
#include "esipa_json.h"
#include "esipa_init_auth.h"
#include "esipa_auth_clnt.h"
#include "esipa_get_bnd_prfle_pkg.h"
#include "esipa_get_eim_pkg.h"
#include "esipa_prvde_eim_pkg_rslt.h"
#include "esipa_handle_notif.h"
#include "esipa_cancel_session.h"
#include "context.h"

#ifdef IPA_HAVE_ESIPA_JSON

#include <jansson.h>
#include <AuthenticateServerResponse.h>
#include <SGP32-AuthenticateServerResponse.h>
#include <EsipaMessageFromEimToIpa.h>
#include <EsipaMessageFromIpaToEim.h>
#include <EuiccPackageRequest.h>
#include <IpaEuiccDataRequest.h>
#include <IpaEuiccDataResponse.h>
#include <ProfileDownloadTriggerRequest.h>
#include <ProfileDownloadTriggerResult.h>
#include <EuiccPackageResult.h>
#include <ProfileInstallationResult.h>
#include <CancelSessionResponse.h>
#include <SGP32-CancelSessionResponse.h>
#include <SGP32-PrepareDownloadResponse.h>
#include <SGP32-RetrieveNotificationsListResponse.h>
#include <SGP32-PendingNotification.h>
#include <SGP32-PendingNotificationList.h>
#include <BoundProfilePackage.h>
#include <SmdpSigned2.h>
#include <Certificate.h>
#include <ServerSigned1.h>
#include <CtxParams1.h>
#include <StoreMetadataRequest.h>
#include <Octet32.h>
#include <InitiateAuthenticationOkEsipa.h>
#include <AuthenticateClientOkDPEsipa.h>
#include <AuthenticateClientOkDSEsipa.h>
#include <GetBoundProfilePackageOkEsipa.h>
#include <EimAcknowledgements.h>

/* ---------------------------------------------------------------------- */
/* URL paths per v1.2 §6.4.1                                               */
/* ---------------------------------------------------------------------- */

struct esipa_path_entry {
	const char *function_name;
	const char *url_path;
};

static const struct esipa_path_entry g_paths[] = {
	{ "InitiateAuthentication",  "/gsma/rsp2/esipa/initiateAuthentication"  },
	{ "AuthenticateClient",      "/gsma/rsp2/esipa/authenticateClient"      },
	{ "GetBoundProfilePackage",  "/gsma/rsp2/esipa/getBoundProfilePackage"  },
	{ "TransferEimPackage",      "/gsma/rsp2/esipa/transferEimPackage"      },
	{ "GetEimPackage",           "/gsma/rsp2/esipa/getEimPackage"           },
	{ "ProvideEimPackageResult", "/gsma/rsp2/esipa/provideEimPackageResult" },
	{ "HandleNotification",      "/gsma/rsp2/esipa/handleNotification"      },
	{ "CancelSession",           "/gsma/rsp2/esipa/cancelSession"           },
	{ NULL, NULL }
};

/* ---------------------------------------------------------------------- */
/* Base64 (RFC 4648) and hex helpers                                       */
/* ---------------------------------------------------------------------- */

static const char b64_enc_tbl[65] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int b64_dec(char c)
{
	if (c >= 'A' && c <= 'Z') return c - 'A';
	if (c >= 'a' && c <= 'z') return c - 'a' + 26;
	if (c >= '0' && c <= '9') return c - '0' + 52;
	if (c == '+') return 62;
	if (c == '/') return 63;
	return -1;
}

/* Encode `len` bytes of `data` as base64.  Result is malloc'd
 * NUL-terminated string owned by the caller (IPA_FREE it). */
static char *b64_encode(const uint8_t *data, size_t len)
{
	size_t out_len = 4 * ((len + 2) / 3);
	char *out = IPA_ALLOC_N(out_len + 1);
	size_t i, j = 0;
	if (!out)
		return NULL;
	for (i = 0; i < len; i += 3) {
		uint32_t v = (uint32_t)data[i] << 16;
		if (i + 1 < len) v |= (uint32_t)data[i + 1] << 8;
		if (i + 2 < len) v |= (uint32_t)data[i + 2];
		out[j++] = b64_enc_tbl[(v >> 18) & 0x3f];
		out[j++] = b64_enc_tbl[(v >> 12) & 0x3f];
		out[j++] = (i + 1 < len) ? b64_enc_tbl[(v >> 6) & 0x3f] : '=';
		out[j++] = (i + 2 < len) ? b64_enc_tbl[v & 0x3f] : '=';
	}
	out[j] = '\0';
	return out;
}

/* Decode a base64 string into a fresh ipa_buf.  Returns NULL on invalid
 * input.  Caller owns the buffer (ipa_buf_free). */
static struct ipa_buf *b64_decode(const char *s)
{
	if (!s) return NULL;
	size_t slen = strlen(s);
	if (slen == 0) return ipa_buf_alloc(0);
	if (slen % 4) return NULL;
	size_t pad = 0;
	if (slen >= 1 && s[slen - 1] == '=') pad++;
	if (slen >= 2 && s[slen - 2] == '=') pad++;
	size_t out_len = (slen / 4) * 3 - pad;
	struct ipa_buf *buf = ipa_buf_alloc(out_len);
	if (!buf) return NULL;
	buf->len = out_len;
	size_t i, j = 0;
	for (i = 0; i < slen; i += 4) {
		int a = b64_dec(s[i]);
		int b = b64_dec(s[i + 1]);
		int c = (s[i + 2] == '=') ? 0 : b64_dec(s[i + 2]);
		int d = (s[i + 3] == '=') ? 0 : b64_dec(s[i + 3]);
		if (a < 0 || b < 0 || c < 0 || d < 0) {
			ipa_buf_free(buf);
			return NULL;
		}
		if (j < out_len) buf->data[j++] = (a << 2) | (b >> 4);
		if (j < out_len) buf->data[j++] = ((b & 0x0f) << 4) | (c >> 2);
		if (j < out_len) buf->data[j++] = ((c & 0x03) << 6) | d;
	}
	return buf;
}

/* Hex encode `len` bytes as upper-case ASCII, NUL-terminated.  Caller owns. */
static char *hex_encode(const uint8_t *data, size_t len)
{
	static const char h[] = "0123456789ABCDEF";
	char *out = IPA_ALLOC_N(len * 2 + 1);
	if (!out) return NULL;
	for (size_t i = 0; i < len; i++) {
		out[i * 2] = h[(data[i] >> 4) & 0xf];
		out[i * 2 + 1] = h[data[i] & 0xf];
	}
	out[len * 2] = '\0';
	return out;
}

/* Hex decode `s` into a fresh ipa_buf (odd-length rejected). */
static struct ipa_buf *hex_decode(const char *s)
{
	if (!s) return NULL;
	size_t slen = strlen(s);
	if (slen % 2) return NULL;
	struct ipa_buf *buf = ipa_buf_alloc(slen / 2);
	if (!buf) return NULL;
	buf->len = slen / 2;
	for (size_t i = 0; i < slen; i += 2) {
		int hi, lo;
		char c = s[i];
		if (c >= '0' && c <= '9') hi = c - '0';
		else if (c >= 'A' && c <= 'F') hi = c - 'A' + 10;
		else if (c >= 'a' && c <= 'f') hi = c - 'a' + 10;
		else { ipa_buf_free(buf); return NULL; }
		c = s[i + 1];
		if (c >= '0' && c <= '9') lo = c - '0';
		else if (c >= 'A' && c <= 'F') lo = c - 'A' + 10;
		else if (c >= 'a' && c <= 'f') lo = c - 'a' + 10;
		else { ipa_buf_free(buf); return NULL; }
		buf->data[i / 2] = (uint8_t)((hi << 4) | lo);
	}
	return buf;
}

/* ---------------------------------------------------------------------- */
/* ASN.1 <-> base64 round-tripping                                         */
/* ---------------------------------------------------------------------- */

/* DER-encode an ASN.1 struct into a fresh ipa_buf. */
static struct ipa_buf *asn1_to_der(asn_TYPE_descriptor_t *td, const void *struct_ptr)
{
	struct ipa_buf *buf = NULL;
	asn_enc_rval_t r = der_encode(td, (void *)struct_ptr, ipa_asn1c_consume_bytes_cb, &buf);
	if (r.encoded <= 0) {
		IPA_FREE(buf);
		return NULL;
	}
	return buf;
}

/* DER-encode `struct_ptr`, then add to `obj` under `key` as base64.
 * Returns 0 on success, -1 on error. */
static int json_set_asn1_b64(json_t *obj, const char *key,
			     asn_TYPE_descriptor_t *td, const void *struct_ptr)
{
	struct ipa_buf *der = asn1_to_der(td, struct_ptr);
	if (!der) return -1;
	char *b64 = b64_encode(der->data, der->len);
	ipa_buf_free(der);
	if (!b64) return -1;
	int rc = json_object_set_new(obj, key, json_string(b64));
	IPA_FREE(b64);
	return rc;
}

/* BER-decode a base64 JSON field into a new ASN.1 struct.  Caller owns the
 * returned struct (ASN_STRUCT_FREE to release). */
static void *json_get_asn1_b64(json_t *obj, const char *key, asn_TYPE_descriptor_t *td)
{
	json_t *j = json_object_get(obj, key);
	if (!j || !json_is_string(j)) return NULL;
	struct ipa_buf *der = b64_decode(json_string_value(j));
	if (!der) return NULL;
	void *out = NULL;
	asn_dec_rval_t r = ber_decode(NULL, td, &out, der->data, der->len);
	ipa_buf_free(der);
	if (r.code != RC_OK) {
		ASN_STRUCT_FREE(*td, out);
		return NULL;
	}
	return out;
}

/* Add a raw byte buffer to the JSON object as base64. */
static int json_set_bytes_b64(json_t *obj, const char *key, const uint8_t *data, size_t len)
{
	char *b64 = b64_encode(data, len);
	if (!b64) return -1;
	int rc = json_object_set_new(obj, key, json_string(b64));
	IPA_FREE(b64);
	return rc;
}

/* Dump a JSON object into a fresh ipa_buf (not NUL-terminated). */
static struct ipa_buf *json_dump_to_buf(json_t *obj)
{
	char *s = json_dumps(obj, JSON_COMPACT);
	if (!s) return NULL;
	size_t len = strlen(s);
	struct ipa_buf *buf = ipa_buf_alloc(len);
	if (!buf) { free(s); return NULL; }
	memcpy(buf->data, s, len);
	buf->len = len;
	free(s);
	return buf;
}

/* Load an ipa_buf into a JSON object (or return NULL on parse error). */
static json_t *json_load_from_buf(const struct ipa_buf *body)
{
	if (!body || body->len == 0) return NULL;
	json_error_t err;
	return json_loadb((const char *)body->data, body->len, 0, &err);
}

/* ---------------------------------------------------------------------- */
/* Public: URL paths and content types                                     */
/* ---------------------------------------------------------------------- */

const char *ipa_esipa_json_url_path(const char *function_name)
{
	if (!function_name) return NULL;
	for (const struct esipa_path_entry *e = g_paths; e->function_name; e++) {
		if (strcmp(e->function_name, function_name) == 0)
			return e->url_path;
	}
	return NULL;
}

bool ipa_esipa_json_available(void) { return true; }

/* Is a member present as a JSON string?  Used to check the member a response body cannot be without
 * before an "Ok" structure is built for it -- the sections 6.4.1.x schemas name these in their
 * "required" lists.  Only the one member that identifies the response is checked, not the whole list:
 * the point is to tell a result apart from no result, and an eIM that omits one of the others is
 * answering imprecisely rather than not answering.  Attaching an empty "Ok" to a body with no result
 * at all would present it to the caller as a success.
 *
 * This backstops the response header, which is where a failure is normally reported: a body arriving
 * without a result and without a header saying why is still not a success.
 *
 * The check has to happen before the structure is populated rather than after: some members are
 * filled in with pointers that must not be freed (see matchingId below), so a half-built "Ok" cannot
 * simply be thrown away again. */
static bool json_has_str(json_t *obj, const char *member)
{
	json_t *j = json_object_get(obj, member);

	return j && json_is_string(j);
}

/* One row of a function's "Specific Status Codes" table (SGP.32, sections 5.14.1 to 5.14.6).  A table
 * is terminated by an entry with a NULL subject_code. */
struct esipa_json_status_map {
	const char *subject_code;
	const char *reason_code;
	long err;
};

/* Read the <JSON responseHeader> and turn a reported failure into the error code the caller expects.
 *
 * SGP.32 section 6.1.2 binds the ESipa JSON response to SGP.22 section 6.5.1.4: the response message is
 * a <JSON responseHeader> followed by the <JSON responseBody>, and the header carries
 * header.functionExecutionStatus with status "Executed-Success" or "Failed" (SGP.22 section 5.2.5 rules
 * the other two values out).  This -- not the HTTP status -- is where a failed ESipa function is
 * reported: SGP.22 section 6.3 requires status code 200 "regardless whether the function response is an
 * error or a success", so a 4xx or 5xx means the request never reached function execution at all, which
 * is why ipa_esipa_req() rejects those separately and earlier.
 *
 * A failure identifies itself with a (subjectCode, reasonCode) pair rather than with the integer the
 * ASN.1 binding carries.  Each function's "Specific Status Codes" table maps the pairs onto exactly
 * those integers -- the "(maps to ...)" note in each table's Description column -- which is what lets
 * one caller handle both bindings without knowing which one is in use.
 *
 * DONE for v1.2: CR12011R00 / sections 5.2.6, 5.14, 6.1 — the JSON to ASN.1 status code mapping.  Each
 * function's table lives next to its decoder below.
 *
 * Note the asymmetry with the request direction: section 6.1.2 says ESipa messages SHALL NOT contain
 * the <JSON requestHeader>, and says no such thing about the response header.
 *
 * \returns 0 when the function succeeded, otherwise the mapped error code (undefined_err for a failure
 * the function's table does not list, and for a malformed header, because something went wrong and
 * saying which is beyond what was received). */
static long json_exec_status(json_t *obj, const struct esipa_json_status_map *map, long undefined_err,
			     const char *function_name)
{
	json_t *hdr, *fes, *status, *scd, *subject, *reason, *message;
	const char *status_str, *subject_str, *reason_str;
	unsigned int i;

	/* header, header.functionExecutionStatus and its status are each "required" in SGP.22 section
	 * 6.5.1.4, and section 6.1.2 puts that header on every ESipa response.  A response missing any of
	 * them is not the message this interface defines, and cannot be read as a success just because it
	 * failed to say otherwise.  json_is_object() and json_is_string() are NULL-safe, so the whole
	 * chain collapses into one check. */
	hdr = json_object_get(obj, "header");
	fes = json_object_get(hdr, "functionExecutionStatus");
	status = json_object_get(fes, "status");
	if (!json_is_string(status)) {
		IPA_LOGP_ESIPA(function_name, LERROR,
			       "response carries no header.functionExecutionStatus.status, so there is no saying whether the function succeeded\n");
		return undefined_err;
	}

	status_str = json_string_value(status);
	if (strcmp(status_str, "Executed-Success") == 0)
		return 0;
	if (strcmp(status_str, "Failed") != 0) {
		/* SGP.22 section 5.2.5 forbids Executed-WithWarning and Expired here, leaving "Failed" as the
		 * only other value.  Anything else is a response this interface does not define; report the
		 * value received so a non-conforming eIM can be identified from the log. */
		IPA_LOGP_ESIPA(function_name, LERROR,
			       "response reports function execution status \"%s\", which this interface does not define\n",
			       status_str);
		return undefined_err;
	}

	/* statusCodeData is optional -- section 6.5.1.4 requires only status -- so a bare "Failed" is a
	 * conforming answer that does not say why.  Where it is present, subjectCode and reasonCode are
	 * both required, and one without the other says no more than neither. */
	scd = json_object_get(fes, "statusCodeData");
	subject = json_object_get(scd, "subjectCode");
	reason = json_object_get(scd, "reasonCode");
	if (!json_is_string(subject) || !json_is_string(reason)) {
		IPA_LOGP_ESIPA(function_name, LERROR,
			       "function failed, without a status code saying why\n");
		return undefined_err;
	}
	subject_str = json_string_value(subject);
	reason_str = json_string_value(reason);

	/* message is optional and purely human-readable, which makes it worth logging and nothing else. */
	message = json_object_get(scd, "message");

	for (i = 0; map && map[i].subject_code; i++) {
		if (strcmp(map[i].subject_code, subject_str) != 0 || strcmp(map[i].reason_code, reason_str) != 0)
			continue;
		if (json_is_string(message))
			IPA_LOGP_ESIPA(function_name, LDEBUG, "eIM says: %s\n", json_string_value(message));
		return map[i].err;
	}

	/* A status code outside this function's table.  The generic codes of SGP.22 section 5.2.6 can turn
	 * up on any function, and the ASN.1 error enums have no room for them, so they collapse onto
	 * undefinedError -- which still fails the call, only less precisely. */
	IPA_LOGP_ESIPA(function_name, LERROR,
		       "function failed with status code %s/%s, which it does not define%s%s\n",
		       subject_str, reason_str, json_is_string(message) ? ": " : "",
		       json_is_string(message) ? json_string_value(message) : "");
	return undefined_err;
}

/* Did the eIM report a failure, for a function with no response body of its own?
 *
 * ESipa.CancelSession is the only one: section 6.4.1.8 ends with "ESipa.CancelSession function has no
 * <JSON responseBody>", which leaves the response header of section 6.1.2 as the entire response, and
 * therefore as the only place a failure can be stated.  Section 5.14.8 defines no Specific Status Codes
 * for it, so there is nothing to map -- the question is only whether it failed.
 *
 * \returns true when the eIM reported success. */
bool ipa_esipa_json_exec_ok(const struct ipa_buf *body, const char *function_name)
{
	json_t *obj = json_load_from_buf(body);
	long err;

	if (!obj) {
		IPA_LOGP_ESIPA(function_name, LERROR,
			       "response is not the JSON responseHeader this function is supposed to carry\n");
		return false;
	}
	err = json_exec_status(obj, NULL, -1, function_name);
	json_decref(obj);
	return err == 0;
}

/* ---------------------------------------------------------------------- */
/* §6.4.1.1  InitiateAuthentication                                        */
/* ---------------------------------------------------------------------- */

struct ipa_buf *ipa_esipa_json_enc_init_auth_req(const struct ipa_esipa_init_auth_req *req)
{
	json_t *obj = json_object();
	if (!obj) return NULL;
	/* euiccChallenge: base64 of the raw OCTET STRING *value* (no DER tag/len). */
	if (json_set_bytes_b64(obj, "euiccChallenge", req->euicc_challenge, IPA_LEN_EUICC_CHLG) < 0)
		goto err;
	/* euiccInfo1: base64(DER(EUICCInfo1)) */
	if (req->euicc_info_1 &&
	    json_set_asn1_b64(obj, "euiccInfo1", &asn_DEF_EUICCInfo1, req->euicc_info_1) < 0)
		goto err;
	/* smdpAddress: plain string (optional) */
	if (req->smdp_addr)
		json_object_set_new(obj, "smdpAddress", json_string(req->smdp_addr));
	/* eimTransactionId: hex, present only when the eIM supplied one in the
	 * ProfileDownloadTriggerRequest that started this download. */
	if (req->eim_transaction_id) {
		char *eim_tid_hex = hex_encode(req->eim_transaction_id->buf, req->eim_transaction_id->size);
		if (!eim_tid_hex) goto err;
		json_object_set_new(obj, "eimTransactionId", json_string(eim_tid_hex));
		IPA_FREE(eim_tid_hex);
	}

	struct ipa_buf *buf = json_dump_to_buf(obj);
	json_decref(obj);
	return buf;
err:
	json_decref(obj);
	return NULL;
}

/* SGP.32, section 5.14.1, Table 9a. */
static const struct esipa_json_status_map init_auth_status_map[] = {
	{ "8.31.2", "3.10", InitiateAuthenticationResponseEsipa__initiateAuthenticationErrorEsipa_invalidEimTransactionId },
	{ "8.8.1", "3.10", InitiateAuthenticationResponseEsipa__initiateAuthenticationErrorEsipa_smdpAddressMismatch },
	{ "8.8", "3.10", InitiateAuthenticationResponseEsipa__initiateAuthenticationErrorEsipa_smdpOidMismatch },
	{ NULL, NULL, 0 }
};

struct ipa_esipa_init_auth_res *ipa_esipa_json_dec_init_auth_res(const struct ipa_buf *body)
{
	json_t *obj = json_load_from_buf(body);
	if (!obj) return NULL;
	struct ipa_esipa_init_auth_res *res = IPA_ALLOC_ZERO(struct ipa_esipa_init_auth_res);
	if (!res) { json_decref(obj); return NULL; }

	/* A failure reported in the response header.  No Ok structure is attached, so the caller's "no Ok
	 * member" guard trips even if it never inspects the code. */
	res->init_auth_err = json_exec_status(obj, init_auth_status_map,
					      InitiateAuthenticationResponseEsipa__initiateAuthenticationErrorEsipa_undefinedError,
					      "InitiateAuthentication");
	if (res->init_auth_err) {
		IPA_LOGP_ESIPA("InitiateAuthentication", LERROR, "function failed with error code %ld=%s!\n",
			       res->init_auth_err, ipa_esipa_init_auth_err_str(res->init_auth_err));
		json_decref(obj);
		return res;
	}

	/* The JSON body is *not* wrapped in EsipaMessageFromEimToIpa, so we
	 * synthesise the inner InitiateAuthenticationOkEsipa manually. */
	/* The header reported no failure, yet the body carries no result either: nothing here is usable,
	 * and attaching an empty "Ok" would hand the caller a success it never received. */
	if (!json_has_str(obj, "serverSigned1")) {
		IPA_LOGP_ESIPA("InitiateAuthentication", LERROR,
			       "response reported success but carries no serverSigned1, treating it as a failure\n");
		json_decref(obj);
		return res;
	}

	struct InitiateAuthenticationOkEsipa *ok = IPA_ALLOC_ZERO(struct InitiateAuthenticationOkEsipa);
	if (!ok) { IPA_FREE(res); json_decref(obj); return NULL; }

	/* transactionId: hex string (optional) */
	json_t *j = json_object_get(obj, "transactionId");
	if (j && json_is_string(j)) {
		struct ipa_buf *hx = hex_decode(json_string_value(j));
		if (hx) {
			TransactionId_t *tid = IPA_ALLOC_ZERO(TransactionId_t);
			tid->buf = IPA_ALLOC_N(hx->len);
			memcpy(tid->buf, hx->data, hx->len);
			tid->size = hx->len;
			ok->transactionId = tid;
			ipa_buf_free(hx);
		}
	}
	/* serverSigned1: base64(DER) */
	struct ServerSigned1 *ss1 = json_get_asn1_b64(obj, "serverSigned1", &asn_DEF_ServerSigned1);
	if (ss1) { ok->serverSigned1 = *ss1; IPA_FREE(ss1); }
	/* serverSignature1: base64(DER OCTET STRING) */
	j = json_object_get(obj, "serverSignature1");
	if (j && json_is_string(j)) {
		/* The description says base64(DER).  However the response object is
		 * the "signature as required by ES10b.AuthenticateServer" so we treat
		 * it as a base64 of the signature value and wrap into OCTET_STRING. */
		struct ipa_buf *sig = b64_decode(json_string_value(j));
		if (sig) {
			ok->serverSignature1.buf = IPA_ALLOC_N(sig->len);
			memcpy(ok->serverSignature1.buf, sig->data, sig->len);
			ok->serverSignature1.size = sig->len;
			ipa_buf_free(sig);
		}
	}
	/* euiccCiPKIdentifierToBeUsed: base64 */
	j = json_object_get(obj, "euiccCiPKIdentifierToBeUsed");
	if (j && json_is_string(j)) {
		struct ipa_buf *b = b64_decode(json_string_value(j));
		if (b) {
			ok->euiccCiPKIdentifierToBeUsed.buf = IPA_ALLOC_N(b->len);
			memcpy(ok->euiccCiPKIdentifierToBeUsed.buf, b->data, b->len);
			ok->euiccCiPKIdentifierToBeUsed.size = b->len;
			ipa_buf_free(b);
		}
	}
	/* serverCertificate: base64(DER Certificate) */
	Certificate_t *cert = json_get_asn1_b64(obj, "serverCertificate", &asn_DEF_Certificate);
	if (cert) { ok->serverCertificate = *cert; IPA_FREE(cert); }

	/* matchingId: plain string (optional) */
	j = json_object_get(obj, "matchingId");
	if (j && json_is_string(j)) {
		/* Heap, not a function-static.  A static would be shared by every response decoded in this
		 * process -- each call overwriting the previous result's matchingId and orphaning its buffer
		 * -- and, worse, would make the enclosing "Ok" unfreeable, because ASN_STRUCT_FREE would
		 * reach a free() of an object that was never allocated. */
		UTF8String_t *mid = IPA_ALLOC_ZERO(UTF8String_t);
		size_t l = strlen(json_string_value(j));
		mid->buf = IPA_ALLOC_N(l);
		memcpy(mid->buf, json_string_value(j), l);
		mid->size = l;
		ok->matchingId = mid;
	}
	/* ctxParams1: base64(DER) (optional) */
	CtxParams1_t *cp1 = json_get_asn1_b64(obj, "ctxParams1", &asn_DEF_CtxParams1);
	if (cp1) ok->ctxParams1 = cp1;

	res->init_auth_ok = ok;
	res->msg_to_ipa = NULL; /* JSON path does not synthesise this wrapper */
	json_decref(obj);
	return res;
}

/* ---------------------------------------------------------------------- */
/* §6.4.1.2  AuthenticateClient                                            */
/* ---------------------------------------------------------------------- */

struct ipa_buf *ipa_esipa_json_enc_auth_clnt_req(const struct ipa_esipa_auth_clnt_req *req)
{
	json_t *obj = json_object();
	if (!obj) return NULL;
	/* transactionId: hex */
	char *tid_hex = hex_encode(req->req.transactionId.buf, req->req.transactionId.size);
	if (!tid_hex) { json_decref(obj); return NULL; }
	json_object_set_new(obj, "transactionId", json_string(tid_hex));
	IPA_FREE(tid_hex);
	/* authenticateServerResponse: base64 of raw bytes when available (to
	 * preserve euiccSigned1 byte representation for euiccSignature1
	 * verification at the SM-DP+), or base64(DER) on the fallback path. */
	if (req->raw_authenticate_server_response) {
		if (json_set_bytes_b64(obj, "authenticateServerResponse",
				       req->raw_authenticate_server_response->data,
				       req->raw_authenticate_server_response->len) < 0) {
			json_decref(obj);
			return NULL;
		}
	} else {
		/* The field is an SGP32-AuthenticateServerResponse, so it needs the SGP.32 descriptor.  The
		 * SGP.22 one has only two CHOICE members and cannot encode the compact branch at all. */
		if (json_set_asn1_b64(obj, "authenticateServerResponse",
				      &asn_DEF_SGP32_AuthenticateServerResponse,
				      &req->req.authenticateServerResponse) < 0) {
			json_decref(obj);
			return NULL;
		}
	}
	struct ipa_buf *buf = json_dump_to_buf(obj);
	json_decref(obj);
	return buf;
}

/* SGP.32, section 5.14.3, Table 13a. */
static const struct esipa_json_status_map auth_clnt_status_map[] = {
	{ "8.2.8", "1.2", AuthenticateClientResponseEsipa__authenticateClientErrorEsipa_pprNotAllowed },
	{ NULL, NULL, 0 }
};

struct ipa_esipa_auth_clnt_res *ipa_esipa_json_dec_auth_clnt_res(const struct ipa_buf *body,
								 const struct ipa_esipa_auth_clnt_req *req)
{
	(void)req; /* reserved for future correlation use */
	json_t *obj = json_load_from_buf(body);
	if (!obj) return NULL;
	struct ipa_esipa_auth_clnt_res *res = IPA_ALLOC_ZERO(struct ipa_esipa_auth_clnt_res);
	if (!res) { json_decref(obj); return NULL; }

	/* A failure reported in the response header.  No Ok structure is attached, so the caller's "no Ok
	 * member" guard trips even if it never inspects the code. */
	res->auth_clnt_err = json_exec_status(obj, auth_clnt_status_map,
					      AuthenticateClientResponseEsipa__authenticateClientErrorEsipa_undefinedError,
					      "AuthenticateClient");
	if (res->auth_clnt_err) {
		IPA_LOGP_ESIPA("AuthenticateClient", LERROR, "function failed with error code %ld=%s!\n",
			       res->auth_clnt_err, ipa_esipa_auth_clnt_err_str(res->auth_clnt_err));
		json_decref(obj);
		return res;
	}

	/* §6.4.1.2 response body is NOT a CHOICE in JSON — it's an object with
	 * the DP-case fields.  The DS-case (smds) path is transported via
	 * profileDownloadTriggerResult in GetEimPackage/TransferEimPackage in
	 * the JSON binding, so we always decode as DP here. */
	/* The header reported no failure, yet the body carries no result either: nothing here is usable,
	 * and attaching an empty "Ok" would hand the caller a success it never received. */
	if (!json_has_str(obj, "smdpSigned2")) {
		IPA_LOGP_ESIPA("AuthenticateClient", LERROR,
			       "response reported success but carries no smdpSigned2, treating it as a failure\n");
		json_decref(obj);
		return res;
	}

	struct AuthenticateClientOkDPEsipa *ok =
	    IPA_ALLOC_ZERO(struct AuthenticateClientOkDPEsipa);
	if (!ok) { IPA_FREE(res); json_decref(obj); return NULL; }

	json_t *j = json_object_get(obj, "transactionId");
	if (j && json_is_string(j)) {
		struct ipa_buf *hx = hex_decode(json_string_value(j));
		if (hx) {
			TransactionId_t *tid = IPA_ALLOC_ZERO(TransactionId_t);
			tid->buf = IPA_ALLOC_N(hx->len);
			memcpy(tid->buf, hx->data, hx->len);
			tid->size = hx->len;
			ok->transactionId = tid;
			ipa_buf_free(hx);
		}
	}
	StoreMetadataRequest_t *smr = json_get_asn1_b64(obj, "profileMetadata", &asn_DEF_StoreMetadataRequest);
	if (smr) ok->profileMetaData = smr;
	SmdpSigned2_t *s2 = json_get_asn1_b64(obj, "smdpSigned2", &asn_DEF_SmdpSigned2);
	bool have_smdp_signed2 = s2 != NULL;
	if (s2) { ok->smdpSigned2 = *s2; IPA_FREE(s2); }
	j = json_object_get(obj, "smdpSignature2");
	if (j && json_is_string(j)) {
		struct ipa_buf *b = b64_decode(json_string_value(j));
		if (b) {
			ok->smdpSignature2.buf = IPA_ALLOC_N(b->len);
			memcpy(ok->smdpSignature2.buf, b->data, b->len);
			ok->smdpSignature2.size = b->len;
			ipa_buf_free(b);
		}
	}
	Certificate_t *cert = json_get_asn1_b64(obj, "smdpCertificate", &asn_DEF_Certificate);
	if (cert) { ok->smdpCertificate = *cert; IPA_FREE(cert); }
	Octet32_t *hc = json_get_asn1_b64(obj, "hashCc", &asn_DEF_Octet32);
	if (hc) ok->hashCc = hc;

	res->auth_clnt_ok_dpe = ok;
	/* Same rule as the ASN.1 binding: SGP.32 section 5.14.3 makes transactionId optional because
	 * smdpSigned2 carries it too, and the eIM omits it towards an IPA with IPA Capability
	 * minimizeEsipaBytes.  Fall back to the signed copy rather than leaving the session without one. */
	if (ok->transactionId)
		res->transaction_id = ok->transactionId;
	else if (have_smdp_signed2)
		res->transaction_id = &ok->smdpSigned2.transactionId;
	json_decref(obj);
	return res;
}

/* ---------------------------------------------------------------------- */
/* §6.4.1.3  GetBoundProfilePackage                                        */
/* ---------------------------------------------------------------------- */

struct ipa_buf *ipa_esipa_json_enc_get_bnd_prfle_pkg_req(const struct ipa_esipa_get_bnd_prfle_pkg_req *req)
{
	json_t *obj = json_object();
	if (!obj) return NULL;
	const struct PrepareDownloadResponse *pdr = req->prep_dwnld_res;
	/* transactionId: hex, and required by the schema of section 6.4.1.3. It is not a member of the request
	 * struct; it sits inside the PrepareDownloadResponse, which is where the ASN.1 binding takes it from
	 * too (see ipa_esipa_get_bnd_prfle_pkg_transaction_id). */
	const TransactionId_t *tid = ipa_esipa_get_bnd_prfle_pkg_transaction_id(pdr);
	if (!tid) {
		IPA_LOGP_ESIPA("GetBoundProfilePackage", LERROR,
			       "prepare download response carries no transaction id, cannot encode request\n");
		json_decref(obj);
		return NULL;
	}
	char *tid_hex = hex_encode(tid->buf, tid->size);
	if (!tid_hex) { json_decref(obj); return NULL; }
	json_object_set_new(obj, "transactionId", json_string(tid_hex));
	IPA_FREE(tid_hex);
	if (json_set_asn1_b64(obj, "prepareDownloadResponse",
			      &asn_DEF_PrepareDownloadResponse, pdr) < 0) {
		json_decref(obj);
		return NULL;
	}
	struct ipa_buf *buf = json_dump_to_buf(obj);
	json_decref(obj);
	return buf;
}

/* SGP.32, section 5.14.2, Table 11a. */
static const struct esipa_json_status_map get_bnd_prfle_pkg_status_map[] = {
	{ "8.2.9", "3.11", GetBoundProfilePackageResponseEsipa__getBoundProfilePackageErrorEsipa_metadataMismatch },
	{ NULL, NULL, 0 }
};

struct ipa_esipa_get_bnd_prfle_pkg_res *ipa_esipa_json_dec_get_bnd_prfle_pkg_res(const struct ipa_buf *body)
{
	json_t *obj = json_load_from_buf(body);
	if (!obj) return NULL;
	struct ipa_esipa_get_bnd_prfle_pkg_res *res = IPA_ALLOC_ZERO(struct ipa_esipa_get_bnd_prfle_pkg_res);
	if (!res) { json_decref(obj); return NULL; }
	/* A failure reported in the response header.  No Ok structure is attached, so the caller's "no Ok
	 * member" guard trips even if it never inspects the code. */
	res->get_bnd_prfle_pkg_err = json_exec_status(obj, get_bnd_prfle_pkg_status_map,
						      GetBoundProfilePackageResponseEsipa__getBoundProfilePackageErrorEsipa_undefinedError,
						      "GetBoundProfilePackage");
	if (res->get_bnd_prfle_pkg_err) {
		IPA_LOGP_ESIPA("GetBoundProfilePackage", LERROR, "function failed with error code %ld=%s!\n",
			       res->get_bnd_prfle_pkg_err, ipa_esipa_get_bnd_prfle_pkg_err_str(res->get_bnd_prfle_pkg_err));
		json_decref(obj);
		return res;
	}

	/* The header reported no failure, yet the body carries no result either: nothing here is usable,
	 * and attaching an empty "Ok" would hand the caller a success it never received. */
	if (!json_has_str(obj, "boundProfilePackage")) {
		IPA_LOGP_ESIPA("GetBoundProfilePackage", LERROR,
			       "response reported success but carries no boundProfilePackage, treating it as a failure\n");
		json_decref(obj);
		return res;
	}

	struct GetBoundProfilePackageOkEsipa *ok = IPA_ALLOC_ZERO(struct GetBoundProfilePackageOkEsipa);
	if (!ok) { IPA_FREE(res); json_decref(obj); return NULL; }

	json_t *j = json_object_get(obj, "transactionId");
	if (j && json_is_string(j)) {
		struct ipa_buf *hx = hex_decode(json_string_value(j));
		if (hx) {
			TransactionId_t *tid = IPA_ALLOC_ZERO(TransactionId_t);
			tid->buf = IPA_ALLOC_N(hx->len);
			memcpy(tid->buf, hx->data, hx->len);
			tid->size = hx->len;
			ok->transactionId = tid;
			ipa_buf_free(hx);
		}
	}
	BoundProfilePackage_t *bpp = json_get_asn1_b64(obj, "boundProfilePackage", &asn_DEF_BoundProfilePackage);
	if (bpp) { ok->boundProfilePackage = *bpp; IPA_FREE(bpp); }

	res->get_bnd_prfle_pkg_ok = ok;
	json_decref(obj);
	return res;
}

/* ---------------------------------------------------------------------- */
/* §6.4.1.5  GetEimPackage                                                 */
/* ---------------------------------------------------------------------- */

struct ipa_buf *ipa_esipa_json_enc_get_eim_pkg_req(const uint8_t *eid, bool notify_state_change,
						   int state_change_cause, const uint8_t *rplmn)
{
	json_t *obj = json_object();
	if (!obj) return NULL;
	/* eidValue per spec "^[0-9]{32}$" — 32-digit decimal BCD representation
	 * of the 16-byte EID.  Each nibble is a decimal digit. */
	char eid_str[33];
	for (int i = 0; i < IPA_LEN_EID; i++) {
		eid_str[i * 2]     = '0' + ((eid[i] >> 4) & 0x0f);
		eid_str[i * 2 + 1] = '0' + (eid[i] & 0x0f);
	}
	eid_str[32] = '\0';
	json_object_set_new(obj, "eidValue", json_string(eid_str));
	if (notify_state_change)
		json_object_set_new(obj, "notifyStateChange", json_true());
	if (state_change_cause >= 0)
		json_object_set_new(obj, "stateChangeCause", json_integer(state_change_cause));
	/* Section 6.4.1.5 spells this one "rPlmn", not "rPLMN" as the ASN.1 does, and carries the three
	 * TS 24.008 bytes as plain base64 rather than the base64+DER most other fields here use. */
	if (rplmn) {
		char *rplmn_b64 = b64_encode(rplmn, IPA_LEN_PLMN);

		if (rplmn_b64) {
			json_object_set_new(obj, "rPlmn", json_string(rplmn_b64));
			IPA_FREE(rplmn_b64);
		}
	}
	struct ipa_buf *buf = json_dump_to_buf(obj);
	json_decref(obj);
	return buf;
}

/* SGP.32, section 5.14.5, Table 18. */
static const struct esipa_json_status_map get_eim_pkg_status_map[] = {
	{ "8.1.1", "3.7", GetEimPackageResponse__eimPackageError_noEimPackageAvailable },
	{ "8.1.1", "2.1", GetEimPackageResponse__eimPackageError_invalidEid },
	{ "8.1.1", "2.2", GetEimPackageResponse__eimPackageError_missingEid },
	{ "8.1.1", "3.9", GetEimPackageResponse__eimPackageError_eidNotFound },
	{ NULL, NULL, 0 }
};

struct ipa_esipa_get_eim_pkg_res *ipa_esipa_json_dec_get_eim_pkg_res(const struct ipa_buf *body)
{
	json_t *obj = json_load_from_buf(body);
	if (!obj) return NULL;
	struct ipa_esipa_get_eim_pkg_res *res = IPA_ALLOC_ZERO(struct ipa_esipa_get_eim_pkg_res);
	if (!res) { json_decref(obj); return NULL; }

	/* This is the one ESipa function whose JSON response body has an error branch of its own: section
	 * 6.4.1.5 makes eimPackageError one arm of the body's "oneOf", alongside the three request types.
	 * The response header of section 6.1.2 applies here as well, and Table 18 maps its status codes to
	 * the very same four values, so the two cannot contradict each other -- but only the header is
	 * available when the eIM reports the failure the general way. Consult it first, and fall back to
	 * the body arm. */
	res->eim_pkg_err = json_exec_status(obj, get_eim_pkg_status_map,
					    GetEimPackageResponse__eimPackageError_undefinedError, "GetEimPackage");
	if (res->eim_pkg_err) {
		IPA_LOGP_ESIPA("GetEimPackage", LERROR, "function failed with error code %ld=%s!\n",
			       res->eim_pkg_err, ipa_esipa_get_eim_pkg_err_str(res->eim_pkg_err));
		json_decref(obj);
		return res;
	}

	/* oneOf: euiccPackageRequest | ipaEuiccDataRequest |
	 * profileDownloadTriggerRequest | eimPackageError */
	json_t *j;
	if ((j = json_object_get(obj, "euiccPackageRequest")) && json_is_string(j)) {
		res->euicc_package_request = json_get_asn1_b64(obj, "euiccPackageRequest",
							       &asn_DEF_EuiccPackageRequest);
	} else if ((j = json_object_get(obj, "ipaEuiccDataRequest")) && json_is_string(j)) {
		res->ipa_euicc_data_request = json_get_asn1_b64(obj, "ipaEuiccDataRequest",
								&asn_DEF_IpaEuiccDataRequest);
	} else if ((j = json_object_get(obj, "profileDownloadTriggerRequest")) && json_is_string(j)) {
		res->dwnld_trigger_request = json_get_asn1_b64(obj, "profileDownloadTriggerRequest",
							       &asn_DEF_ProfileDownloadTriggerRequest);
	} else if ((j = json_object_get(obj, "eimPackageError")) && json_is_integer(j)) {
		res->eim_pkg_err = (long)json_integer_value(j);
		IPA_LOGP_ESIPA("GetEimPackage", LERROR, "function failed with error code %ld=%s!\n",
			       res->eim_pkg_err, ipa_esipa_get_eim_pkg_err_str(res->eim_pkg_err));
	}
	json_decref(obj);
	return res;
}

/* ---------------------------------------------------------------------- */
/* §6.4.1.6  ProvideEimPackageResult                                       */
/* ---------------------------------------------------------------------- */

struct ipa_buf *ipa_esipa_json_enc_prvde_eim_pkg_rslt_req(const struct ipa_context *ctx,
							  const struct ipa_esipa_prvde_eim_pkg_rslt_req *req)
{
	json_t *obj = json_object();
	if (!obj) return NULL;

	/* eidValue - CR12014R02: include when known. */
	if (ctx) {
		char eid_str[33];
		for (int i = 0; i < IPA_LEN_EID; i++) {
			eid_str[i * 2]     = '0' + ((ctx->eid[i] >> 4) & 0x0f);
			eid_str[i * 2 + 1] = '0' + (ctx->eid[i] & 0x0f);
		}
		eid_str[32] = '\0';
		json_object_set_new(obj, "eidValue", json_string(eid_str));
	}

	/* eimPackageResult: base64(EimPackageResult bytes).
	 * When raw eUICC bytes are available (real eUICC, non-error, non-rollback
	 * path) embed them verbatim so the eUICC's euiccSignEPR signature over
	 * euiccPackageResultDataSigned is not broken by a BER→DER re-encode. */
	if (req->raw_euicc_package_result && req->eim_pkg_err == 0) {
		struct ipa_buf *eim_der = ipa_esipa_build_eim_pkg_result_der(
		    req->raw_euicc_package_result, req->sgp32_notification_list);
		if (!eim_der) {
			json_decref(obj);
			return NULL;
		}
		int rc = json_set_bytes_b64(obj, "eimPackageResult",
					    eim_der->data, eim_der->len);
		IPA_FREE(eim_der);
		if (rc < 0) {
			json_decref(obj);
			return NULL;
		}
	} else {
		/* Emulation / rollback / error path: re-encode from the decoded
		 * C struct (BER→DER round-trip acceptable when no signature
		 * integrity is required on the euiccPackageResultDataSigned). */
		struct ProvideEimPackageResult pepr;
		struct EimPackageResult *epr;
		memset(&pepr, 0, sizeof(pepr));
		epr = &pepr.eimPackageResult;
		if (req->eim_pkg_err != 0) {
			epr->present = EimPackageResult_PR_eimPackageResultResponseError;
			epr->choice.eimPackageResultResponseError.eimPackageResultErrorCode = req->eim_pkg_err;
			/* Section 6.3.2.7 requires the eimTransactionId of the eIM Package to be echoed;
			 * the JSON binding carries the very same EimPackageResult DER (section 6.4.1.6),
			 * so the rule applies here unchanged. */
			epr->choice.eimPackageResultResponseError.eimTransactionId =
			    (TransactionId_t *) req->eim_transaction_id;
		} else if (req->euicc_package_result && req->sgp32_notification_list) {
			epr->present = EimPackageResult_PR_ePRAndNotifications;
			epr->choice.ePRAndNotifications.euiccPackageResult = *req->euicc_package_result;
			if (req->sgp32_notification_list->present ==
			    SGP32_RetrieveNotificationsListResponse_PR_notificationList)
				epr->choice.ePRAndNotifications.notificationList =
				    req->sgp32_notification_list->choice.notificationList;
		} else if (req->euicc_package_result) {
			epr->present = EimPackageResult_PR_euiccPackageResult;
			epr->choice.euiccPackageResult = *req->euicc_package_result;
		} else if (req->ipa_euicc_data_resp) {
			epr->present = EimPackageResult_PR_ipaEuiccDataResponse;
			epr->choice.ipaEuiccDataResponse = *req->ipa_euicc_data_resp;
		} else if (req->prfle_dwnld_trig_req_rslt) {
			epr->present = EimPackageResult_PR_profileDownloadTriggerResult;
			epr->choice.profileDownloadTriggerResult = *req->prfle_dwnld_trig_req_rslt;
		} else {
			epr->present = EimPackageResult_PR_eimPackageResultResponseError;
			epr->choice.eimPackageResultResponseError.eimPackageResultErrorCode =
			    EimPackageResultErrorCode_undefinedError;
			epr->choice.eimPackageResultResponseError.eimTransactionId =
			    (TransactionId_t *) req->eim_transaction_id;
		}
		if (json_set_asn1_b64(obj, "eimPackageResult",
				      &asn_DEF_EimPackageResult, epr) < 0) {
			json_decref(obj);
			return NULL;
		}
	}

	struct ipa_buf *buf = json_dump_to_buf(obj);
	json_decref(obj);
	return buf;
}

/* SGP.32, section 5.14.6, Table 21. */
static const struct esipa_json_status_map prvde_eim_pkg_rslt_status_map[] = {
	{ "8.1.1", "2.1", ProvideEimPackageResultResponse__provideEimPackageResultError_invalidEid },
	{ "8.1.1", "2.2", ProvideEimPackageResultResponse__provideEimPackageResultError_missingEid },
	{ "8.1.1", "3.9", ProvideEimPackageResultResponse__provideEimPackageResultError_eidNotFound },
	{ NULL, NULL, 0 }
};

struct ipa_esipa_prvde_eim_pkg_rslt_res *ipa_esipa_json_dec_prvde_eim_pkg_rslt_res(const struct ipa_buf *body)
{
	struct ipa_esipa_prvde_eim_pkg_rslt_res *res = IPA_ALLOC_ZERO(struct ipa_esipa_prvde_eim_pkg_rslt_res);
	if (!res) return NULL;
	if (!body || body->len == 0) return res;
	json_t *obj = json_load_from_buf(body);
	if (!obj) return res;

	/* The eIM refusing the eIM Package Result matters to the caller: on a refusal the result was never
	 * processed, so it must be kept rather than retired.  An acceptance with nothing to acknowledge
	 * leaves eimAcknowledgements NULL too, which is why the two are told apart by this code and not by
	 * the absence of the member. */
	res->prvde_eim_pkg_rslt_err = json_exec_status(obj, prvde_eim_pkg_rslt_status_map,
						       ProvideEimPackageResultResponse__provideEimPackageResultError_undefinedError,
						       "ProvideEimPackageResult");
	if (res->prvde_eim_pkg_rslt_err) {
		IPA_LOGP_ESIPA("ProvideEimPackageResult", LERROR, "function failed with error code %ld=%s!\n",
			       res->prvde_eim_pkg_rslt_err,
			       ipa_esipa_prvde_eim_pkg_rslt_err_str(res->prvde_eim_pkg_rslt_err));
		json_decref(obj);
		return res;
	}

	/* eimAcknowledgements optional — base64(DER) */
	EimAcknowledgements_t *acks = json_get_asn1_b64(obj, "eimAcknowledgements", &asn_DEF_EimAcknowledgements);
	if (acks) res->eim_acknowledgements = acks;
	json_decref(obj);
	return res;
}

/* ---------------------------------------------------------------------- */
/* §6.4.1.7  HandleNotification (no response body)                         */
/* ---------------------------------------------------------------------- */

struct ipa_buf *ipa_esipa_json_enc_handle_notif_req(const struct ipa_esipa_handle_notif_req *req)
{
	json_t *obj = json_object();
	if (!obj) return NULL;
	if (req->profile_installation_result) {
		if (json_set_asn1_b64(obj, "pendingNotification",
				      &asn_DEF_ProfileInstallationResult,
				      req->profile_installation_result) < 0)
			goto err;
	} else if (req->pending_notification) {
		if (json_set_asn1_b64(obj, "pendingNotification",
				      &asn_DEF_SGP32_PendingNotification,
				      req->pending_notification) < 0)
			goto err;
	} else {
		goto err;
	}
	struct ipa_buf *buf = json_dump_to_buf(obj);
	json_decref(obj);
	return buf;
err:
	json_decref(obj);
	return NULL;
}

/* ---------------------------------------------------------------------- */
/* §6.4.1.8  CancelSession (no response body)                              */
/* ---------------------------------------------------------------------- */

struct ipa_buf *ipa_esipa_json_enc_cancel_session_req(const struct ipa_esipa_cancel_session_req *req)
{
	json_t *obj = json_object();
	if (!obj || !req->transaction_id) { if (obj) json_decref(obj); return NULL; }
	char *tid_hex = hex_encode(req->transaction_id->buf, req->transaction_id->size);
	if (!tid_hex) { json_decref(obj); return NULL; }
	json_object_set_new(obj, "transactionId", json_string(tid_hex));
	IPA_FREE(tid_hex);
	/* The caller currently holds a CancelSessionResponse ASN.1 struct;
	 * encode it via asn1->b64 helper.  cancel_session_ok is the "ok"
	 * branch; its sibling cancel_session_err is the error code path.
	 * Both map onto the same CancelSessionResponse wire type. */
	if (req->cancel_session_ok) {
		CancelSessionResponse_t wrapped = { 0 };
		wrapped.present = CancelSessionResponse_PR_cancelSessionResponseOk;
		wrapped.choice.cancelSessionResponseOk = *req->cancel_session_ok;
		if (json_set_asn1_b64(obj, "cancelSessionResponse",
				      &asn_DEF_CancelSessionResponse, &wrapped) < 0) {
			json_decref(obj);
			return NULL;
		}
	}
	struct ipa_buf *buf = json_dump_to_buf(obj);
	json_decref(obj);
	return buf;
}

/* ---------------------------------------------------------------------- */
/* §6.4.1.4  TransferEimPackage                                            */
/*                                                                         */
/* The IPA sends the RESPONSE half of TransferEimPackage (i.e. transfer    */
/* the result of executing an eIM package).  The request half is sent by   */
/* the eIM and we don't originate those.  Note that TransferEimPackage     */
/* response shares content with ProvideEimPackageResult but with a         */
/* different top-level schema.                                             */
/* ---------------------------------------------------------------------- */

struct ipa_buf *ipa_esipa_json_enc_transfer_eim_pkg_rsp(const struct ipa_esipa_prvde_eim_pkg_rslt_req *req)
{
	json_t *obj = json_object();
	if (!obj) return NULL;

	if (req->eim_pkg_err != 0) {
		json_object_set_new(obj, "eimPackageError", json_integer(req->eim_pkg_err));
	} else if (req->euicc_package_result && req->sgp32_notification_list &&
		   req->sgp32_notification_list->present ==
		       SGP32_RetrieveNotificationsListResponse_PR_notificationList) {
		json_t *sub = json_object();
		/* euiccPackageResult: use raw bytes when available to preserve the
		 * signed euiccPackageResultDataSigned byte representation. */
		if (req->raw_euicc_package_result) {
			if (json_set_bytes_b64(sub, "euiccPackageResult",
					       req->raw_euicc_package_result->data,
					       req->raw_euicc_package_result->len) < 0) {
				json_decref(sub);
				goto err;
			}
		} else {
			if (json_set_asn1_b64(sub, "euiccPackageResult",
					      &asn_DEF_EuiccPackageResult,
					      req->euicc_package_result) < 0) {
				json_decref(sub);
				goto err;
			}
		}
		/* notificationList as PendingNotificationList */
		if (json_set_asn1_b64(sub, "notificationList",
				      &asn_DEF_SGP32_PendingNotificationList,
				      &req->sgp32_notification_list->choice.notificationList) < 0) {
			json_decref(sub);
			goto err;
		}
		json_object_set_new(obj, "ePRAndNotifications", sub);
	} else if (req->euicc_package_result) {
		/* Use raw bytes when available for the same signature-preservation reason. */
		if (req->raw_euicc_package_result) {
			if (json_set_bytes_b64(obj, "euiccPackageResult",
					       req->raw_euicc_package_result->data,
					       req->raw_euicc_package_result->len) < 0)
				goto err;
		} else {
			if (json_set_asn1_b64(obj, "euiccPackageResult",
					      &asn_DEF_EuiccPackageResult,
					      req->euicc_package_result) < 0)
				goto err;
		}
	} else if (req->ipa_euicc_data_resp) {
		if (json_set_asn1_b64(obj, "ipaEuiccDataResponse",
				      &asn_DEF_IpaEuiccDataResponse,
				      req->ipa_euicc_data_resp) < 0)
			goto err;
	} else {
		goto err;
	}

	struct ipa_buf *buf = json_dump_to_buf(obj);
	json_decref(obj);
	return buf;
err:
	json_decref(obj);
	return NULL;
}

#else  /* !IPA_HAVE_ESIPA_JSON --------------------------------------------- */

#include <errno.h>

/* Compile-time stubs when jansson is not present.  All encoders return
 * NULL and all decoders return NULL so the caller's fall-through (or the
 * ASN.1 binding) takes over.  This lets the build succeed without jansson
 * while keeping the public API shape identical. */

const char *ipa_esipa_json_url_path(const char *function_name) { (void)function_name; return NULL; }
bool ipa_esipa_json_available(void) { return false; }

struct ipa_buf *ipa_esipa_json_enc_init_auth_req(const struct ipa_esipa_init_auth_req *req) { (void)req; return NULL; }
struct ipa_buf *ipa_esipa_json_enc_auth_clnt_req(const struct ipa_esipa_auth_clnt_req *req) { (void)req; return NULL; }
struct ipa_buf *ipa_esipa_json_enc_get_bnd_prfle_pkg_req(const struct ipa_esipa_get_bnd_prfle_pkg_req *req) { (void)req; return NULL; }
struct ipa_buf *ipa_esipa_json_enc_get_eim_pkg_req(const uint8_t *eid, bool n, int s, const uint8_t *r)
{ (void)eid; (void)n; (void)s; (void)r; return NULL; }
struct ipa_buf *ipa_esipa_json_enc_prvde_eim_pkg_rslt_req(const struct ipa_context *ctx,
							  const struct ipa_esipa_prvde_eim_pkg_rslt_req *req) { (void)ctx; (void)req; return NULL; }
struct ipa_buf *ipa_esipa_json_enc_handle_notif_req(const struct ipa_esipa_handle_notif_req *req) { (void)req; return NULL; }
struct ipa_buf *ipa_esipa_json_enc_cancel_session_req(const struct ipa_esipa_cancel_session_req *req) { (void)req; return NULL; }
struct ipa_buf *ipa_esipa_json_enc_transfer_eim_pkg_rsp(const struct ipa_esipa_prvde_eim_pkg_rslt_req *req) { (void)req; return NULL; }

struct ipa_esipa_init_auth_res *ipa_esipa_json_dec_init_auth_res(const struct ipa_buf *body) { (void)body; return NULL; }
struct ipa_esipa_auth_clnt_res *ipa_esipa_json_dec_auth_clnt_res(const struct ipa_buf *body,
								 const struct ipa_esipa_auth_clnt_req *req) { (void)body; (void)req; return NULL; }
struct ipa_esipa_get_bnd_prfle_pkg_res *ipa_esipa_json_dec_get_bnd_prfle_pkg_res(const struct ipa_buf *body) { (void)body; return NULL; }
struct ipa_esipa_get_eim_pkg_res *ipa_esipa_json_dec_get_eim_pkg_res(const struct ipa_buf *body) { (void)body; return NULL; }
struct ipa_esipa_prvde_eim_pkg_rslt_res *ipa_esipa_json_dec_prvde_eim_pkg_rslt_res(const struct ipa_buf *body) { (void)body; return NULL; }

#endif /* IPA_HAVE_ESIPA_JSON */

/* ---------------------------------------------------------------------- */
/* Content-Type helper (available regardless of jansson presence)          */
/* ---------------------------------------------------------------------- */

const char *ipa_esipa_content_type(int esipa_binding)
{
	if (esipa_binding == (int)IPA_ESIPA_BINDING_JSON)
		return "application/json;charset=UTF-8";
	return "application/x-gsma-rsp-asn1";
}
