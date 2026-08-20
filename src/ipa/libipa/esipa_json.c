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
 * Compile-time switch: IPA_HAVE_JANSSON (set from CMake when jansson is
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

#ifdef IPA_HAVE_JANSSON

#include <jansson.h>
#include <AuthenticateServerResponse.h>
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

struct ipa_esipa_init_auth_res *ipa_esipa_json_dec_init_auth_res(const struct ipa_buf *body)
{
	json_t *obj = json_load_from_buf(body);
	if (!obj) return NULL;
	struct ipa_esipa_init_auth_res *res = IPA_ALLOC_ZERO(struct ipa_esipa_init_auth_res);
	if (!res) { json_decref(obj); return NULL; }

	/* The JSON body is *not* wrapped in EsipaMessageFromEimToIpa, so we
	 * synthesise the inner InitiateAuthenticationOkEsipa manually. */
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
		static UTF8String_t mid;
		size_t l = strlen(json_string_value(j));
		mid.buf = IPA_ALLOC_N(l);
		memcpy(mid.buf, json_string_value(j), l);
		mid.size = l;
		ok->matchingId = &mid;
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
		if (json_set_asn1_b64(obj, "authenticateServerResponse",
				      &asn_DEF_AuthenticateServerResponse,
				      &req->req.authenticateServerResponse) < 0) {
			json_decref(obj);
			return NULL;
		}
	}
	struct ipa_buf *buf = json_dump_to_buf(obj);
	json_decref(obj);
	return buf;
}

struct ipa_esipa_auth_clnt_res *ipa_esipa_json_dec_auth_clnt_res(const struct ipa_buf *body,
								 const struct ipa_esipa_auth_clnt_req *req)
{
	(void)req; /* reserved for future correlation use */
	json_t *obj = json_load_from_buf(body);
	if (!obj) return NULL;
	struct ipa_esipa_auth_clnt_res *res = IPA_ALLOC_ZERO(struct ipa_esipa_auth_clnt_res);
	if (!res) { json_decref(obj); return NULL; }

	/* §6.4.1.2 response body is NOT a CHOICE in JSON — it's an object with
	 * the DP-case fields.  The DS-case (smds) path is transported via
	 * profileDownloadTriggerResult in GetEimPackage/TransferEimPackage in
	 * the JSON binding, so we always decode as DP here. */
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
	if (ok->transactionId) res->transaction_id = ok->transactionId;
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

struct ipa_esipa_get_bnd_prfle_pkg_res *ipa_esipa_json_dec_get_bnd_prfle_pkg_res(const struct ipa_buf *body)
{
	json_t *obj = json_load_from_buf(body);
	if (!obj) return NULL;
	struct ipa_esipa_get_bnd_prfle_pkg_res *res = IPA_ALLOC_ZERO(struct ipa_esipa_get_bnd_prfle_pkg_res);
	if (!res) { json_decref(obj); return NULL; }
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
						   int state_change_cause)
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
	struct ipa_buf *buf = json_dump_to_buf(obj);
	json_decref(obj);
	return buf;
}

struct ipa_esipa_get_eim_pkg_res *ipa_esipa_json_dec_get_eim_pkg_res(const struct ipa_buf *body)
{
	json_t *obj = json_load_from_buf(body);
	if (!obj) return NULL;
	struct ipa_esipa_get_eim_pkg_res *res = IPA_ALLOC_ZERO(struct ipa_esipa_get_eim_pkg_res);
	if (!res) { json_decref(obj); return NULL; }

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

struct ipa_esipa_prvde_eim_pkg_rslt_res *ipa_esipa_json_dec_prvde_eim_pkg_rslt_res(const struct ipa_buf *body)
{
	struct ipa_esipa_prvde_eim_pkg_rslt_res *res = IPA_ALLOC_ZERO(struct ipa_esipa_prvde_eim_pkg_rslt_res);
	if (!res) return NULL;
	if (!body || body->len == 0) return res;
	json_t *obj = json_load_from_buf(body);
	if (!obj) return res;
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

#else  /* !IPA_HAVE_JANSSON --------------------------------------------- */

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
struct ipa_buf *ipa_esipa_json_enc_get_eim_pkg_req(const uint8_t *eid, bool n, int s) { (void)eid; (void)n; (void)s; return NULL; }
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

#endif /* IPA_HAVE_JANSSON */

/* ---------------------------------------------------------------------- */
/* Content-Type helper (available regardless of jansson presence)          */
/* ---------------------------------------------------------------------- */

const char *ipa_esipa_content_type(int esipa_binding)
{
	if (esipa_binding == (int)IPA_ESIPA_BINDING_JSON)
		return "application/json;charset=UTF-8";
	return "application/x-gsma-rsp-asn1";
}
