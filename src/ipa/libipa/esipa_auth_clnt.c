/*
 * Copyright (c) 2025 Onomondo ApS & sysmocom - s.f.m.c. GmbH. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Author: Philipp Maier <pmaier@sysmocom.de> / sysmocom - s.f.m.c. GmbH
 *
 * See also: GSMA SGP.32, section 5.14.3: Function: (Esipa) AuthenticateClient
 *
 * =====================================================================
 * v1.1/v1.2 migration notes for this file:
 * =====================================================================
 * UPDATE for v1.1: 5.14.3 — AuthenticateClient procedure description changed.
 *   SGP.32 now defines its own EuiccSigned1 (overrides the SGP.22 type) and
 *   its own AuthenticateResponseOk.  This client forwards the eUICC's
 *   AuthenticateServer response; once libasn is regenerated against the
 *   updated .asn, the embedded signed structures will carry the SGP.32 shape
 *   automatically — but review the procedure text to confirm there are no
 *   new required steps (e.g. extra signature checks) on the IPA side.
 * UPDATE for v1.1: 5.6.1 — SGP.32 also defines its own AuthenticateClientRequest
 *   (§5.6.1); the code here uses AuthenticateClientRequestEsipa which is
 *   unchanged, but anywhere the raw AuthenticateClientRequest is referenced
 *   must be reviewed after regeneration.
 * =====================================================================
 */

#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <onomondo/ipa/http.h>
#include <onomondo/ipa/mem.h>
#include <onomondo/ipa/log.h>
#include <onomondo/ipa/ipad.h>
#include <onomondo/ipa/utils.h>
#include <EsipaMessageFromIpaToEim.h>
#include <AuthenticateClientResponseEsipa.h>
#include "utils.h"
#include "length.h"
#include "context.h"
#include "esipa.h"
#include "esipa_json.h"
#include "esipa_auth_clnt.h"

/* The error codes of ESipa.AuthenticateClient (SGP.32, section 6.3.2.2), which are those of
 * ES9+'.AuthenticateClient plus pprNotAllowed(50) from section 5.14.3.  Not to be confused with
 * AuthenticateErrorCode, the unrelated ES10b.AuthenticateServer set used in es10b_auth_serv.c: the two
 * overlap numerically but name entirely different failures. */
#define AC_ERR(name) \
	{ AuthenticateClientResponseEsipa__authenticateClientErrorEsipa_##name, #name }
static const struct num_str_map error_code_strings[] = {
	AC_ERR(eumCertificateInvalid),
	AC_ERR(eumCertificateExpired),
	AC_ERR(euiccCertificateInvalid),
	AC_ERR(euiccCertificateExpired),
	AC_ERR(euiccSignatureInvalid),
	AC_ERR(matchingIdRefused),
	AC_ERR(eidMismatch),
	AC_ERR(noEligibleProfile),
	AC_ERR(ciPKUnknown),
	AC_ERR(invalidTransactionId),
	AC_ERR(insufficientMemory),
	/* NEW in v1.2: 5.14.3 — status code 8.2.8 "PPR - Not Allowed" maps onto this. */
	AC_ERR(pprNotAllowed),
	AC_ERR(eventIdUnknown),
	AC_ERR(undefinedError),
	{ 0, NULL }
};
#undef AC_ERR

/*! Name of an ESipa.AuthenticateClient error code, for log messages.
 *  \param[in] err the error code as decoded from the eIM response.
 *  \returns the code's name from the ASN.1 definition (section 6.3.2.2), or "(unknown)".
 *
 *  Shared by both wire bindings on purpose: the JSON binding carries the same codes, and the two
 *  must not describe one code by two different names. */
const char *ipa_esipa_auth_clnt_err_str(long err)
{
	return ipa_str_from_num(error_code_strings, err, "(unknown)");
}

#ifdef IPA_HAVE_ESIPA_ASN1		/* ESipa ASN.1 binding, SGP.32 section 6.3 */

static struct ipa_buf *enc_auth_clnt_req(const struct ipa_esipa_auth_clnt_req *req)
{
	struct EsipaMessageFromIpaToEim msg_to_eim = { 0 };

	msg_to_eim.present = EsipaMessageFromIpaToEim_PR_authenticateClientRequestEsipa;
	msg_to_eim.choice.authenticateClientRequestEsipa = req->req;

	/* Encode */
	return ipa_esipa_msg_to_eim_enc(&msg_to_eim, "AuthenticateClient");
}

/*
 * DER length helpers (kept private to this file).
 */
static size_t auth_clnt_der_length_size(size_t val)
{
	if (val < 0x80) return 1;
	if (val < 0x100) return 2;
	if (val < 0x10000) return 3;
	if (val < 0x1000000) return 4;
	return 5;
}

static size_t auth_clnt_der_write_length(uint8_t *p, size_t val)
{
	if (val < 0x80) { p[0] = (uint8_t)val; return 1; }
	if (val < 0x100) { p[0] = 0x81; p[1] = (uint8_t)val; return 2; }
	if (val < 0x10000) {
		p[0] = 0x82; p[1] = (uint8_t)(val >> 8); p[2] = (uint8_t)val;
		return 3;
	}
	if (val < 0x1000000) {
		p[0] = 0x83; p[1] = (uint8_t)(val >> 16);
		p[2] = (uint8_t)(val >> 8); p[3] = (uint8_t)val;
		return 4;
	}
	p[0] = 0x84; p[1] = (uint8_t)(val >> 24); p[2] = (uint8_t)(val >> 16);
	p[3] = (uint8_t)(val >> 8); p[4] = (uint8_t)val;
	return 5;
}

/*
 * Build AuthenticateClientRequestEsipa manually so that the eUICC's
 * AuthenticateServerResponse bytes are embedded verbatim (not re-encoded).
 *
 * Wire format (ASN.1/BER binding):
 *
 *   BF3B <len>             EsipaMessageFromIpaToEim [59] (== outer tag of
 *                          AuthenticateClientRequestEsipa SEQUENCE)
 *     80 <tid_len> <tid>   transactionId [0] IMPLICIT OCTET STRING
 *     BF38 ...             authenticateServerResponse — raw bytes from eUICC
 *                          (AuthenticateServerResponse outer tag = BF38, which
 *                          is identical to SGP32_AuthenticateServerResponse
 *                          outer tag used in AuthenticateClientRequestEsipa)
 *
 * The raw bytes already carry the correct BF38 tag — no re-wrapping needed.
 */
static struct ipa_buf *enc_auth_clnt_req_passthru(const struct ipa_esipa_auth_clnt_req *req)
{
	const struct ipa_buf *raw = req->raw_authenticate_server_response;

	/* transactionId field: 0x80 <len> <bytes>
	 * Access .buf/.size directly on the OCTET_STRING value — avoids any
	 * pointer-to-typedef type mismatch with struct TransactionId. */
	size_t tid_body_len = req->req.transactionId.size;
	size_t tid_hdr_len  = 1 + auth_clnt_der_length_size(tid_body_len);
	size_t tid_tlv_len  = tid_hdr_len + tid_body_len;

	/* inner content of BF3B = tid TLV + raw authenticateServerResponse */
	size_t inner_len = tid_tlv_len + raw->len;

	/* outer BF3B header: tag is 2 bytes (BF 3B) + length */
	size_t outer_hdr_len = 2 + auth_clnt_der_length_size(inner_len);
	size_t total_len = outer_hdr_len + inner_len;

	struct ipa_buf *msg = ipa_buf_alloc(total_len);
	if (!msg)
		return NULL;

	size_t off = 0;

	/* BF3B outer tag (context [59] constructed, multi-byte) */
	msg->data[off++] = 0xBF;
	msg->data[off++] = 0x3B;
	off += auth_clnt_der_write_length(msg->data + off, inner_len);

	/* transactionId [0] IMPLICIT OCTET STRING = tag 0x80 */
	msg->data[off++] = 0x80;
	off += auth_clnt_der_write_length(msg->data + off, tid_body_len);
	memcpy(msg->data + off, req->req.transactionId.buf, tid_body_len);
	off += tid_body_len;

	/* authenticateServerResponse: raw BF38 bytes verbatim */
	memcpy(msg->data + off, raw->data, raw->len);
	off += raw->len;

	assert(off == total_len);
	msg->len = total_len;
	return msg;
}

static void *dec_auth_clnt_res(const struct ipa_buf *msg_to_ipa_encoded, const void *req_)
{
	const struct ipa_esipa_auth_clnt_req *req = req_;
	struct EsipaMessageFromEimToIpa *msg_to_ipa = NULL;
	struct ipa_esipa_auth_clnt_res *res = NULL;

	if (msg_to_ipa_encoded->len == 0) {
		IPA_LOGP_ESIPA("AuthenticateClient", LERROR, "eIM response is empty!\n");
		return NULL;
	}

	msg_to_ipa = ipa_esipa_msg_to_ipa_dec(msg_to_ipa_encoded, "AuthenticateClient",
					      EsipaMessageFromEimToIpa_PR_authenticateClientResponseEsipa);
	if (!msg_to_ipa)
		return NULL;

	res = IPA_ALLOC_ZERO(struct ipa_esipa_auth_clnt_res);
	res->msg_to_ipa = msg_to_ipa;

	switch (msg_to_ipa->choice.authenticateClientResponseEsipa.present) {
	case AuthenticateClientResponseEsipa_PR_authenticateClientOkDPEsipa:
		res->auth_clnt_ok_dpe =
		    &msg_to_ipa->choice.authenticateClientResponseEsipa.choice.authenticateClientOkDPEsipa;
		/* SGP.32 section 5.14.3: transactionId is OPTIONAL here because it is also carried inside
		 * smdpSigned2, and the eIM SHALL NOT send it to an IPA with IPA Capability minimizeEsipaBytes.
		 * Fall back to the signed copy when the explicit field is absent, so that the session still has a
		 * transaction ID and the check below still runs -- an omitted field must not become a way around
		 * it. Both alternatives live in the decoded message, so neither outlives the response. */
		res->transaction_id = res->auth_clnt_ok_dpe->transactionId ?
		    res->auth_clnt_ok_dpe->transactionId : &res->auth_clnt_ok_dpe->smdpSigned2.transactionId;
		if (!IPA_ASN_STR_CMP(res->transaction_id, &req->req.transactionId)) {
			IPA_LOGP_ESIPA("AuthenticateClient", LERROR,
				       "eIM responded with unexpected transaction ID (expected: %s, got: %s)\n",
				       ipa_hexdump(req->req.transactionId.buf, req->req.transactionId.size),
				       ipa_hexdump(res->transaction_id->buf, res->transaction_id->size));
			res->auth_clnt_err = -1;
		}
		break;
	case AuthenticateClientResponseEsipa_PR_authenticateClientOkDSEsipa:
		res->auth_clnt_ok_dse =
		    &msg_to_ipa->choice.authenticateClientResponseEsipa.choice.authenticateClientOkDSEsipa;
		res->transaction_id = &res->auth_clnt_ok_dse->transactionId;
		break;
	case AuthenticateClientResponseEsipa_PR_authenticateClientErrorEsipa:
		res->auth_clnt_err =
		    msg_to_ipa->choice.authenticateClientResponseEsipa.choice.authenticateClientErrorEsipa;
		IPA_LOGP_ESIPA("AuthenticateClient", LERROR, "function failed with error code %ld=%s!\n",
			       res->auth_clnt_err, ipa_str_from_num(error_code_strings, res->auth_clnt_err,
								    "(unknown)"));
		break;
	default:
		IPA_LOGP_ESIPA("AuthenticateClient", LERROR, "unexpected response content!\n");
		res->auth_clnt_err = -1;
	}

	return res;
}

/* ASN.1/BER binding: use the passthru encoder when raw eUICC bytes are
 * available to avoid breaking euiccSignature1 via a BER→DER re-encode. */
static struct ipa_buf *enc_auth_clnt_req_cb(struct ipa_context *ctx, const void *req_)
{
	const struct ipa_esipa_auth_clnt_req *req = req_;
	(void)ctx;

	if (req->raw_authenticate_server_response)
		return enc_auth_clnt_req_passthru(req);
	return enc_auth_clnt_req(req);
}

#endif /* IPA_HAVE_ESIPA_ASN1 */

#ifdef IPA_HAVE_ESIPA_JSON		/* ESipa JSON binding, SGP.32 section 6.4 */
static struct ipa_buf *json_enc_auth_clnt_req(struct ipa_context *ctx, const void *req)
{
	(void)ctx;
	return ipa_esipa_json_enc_auth_clnt_req(req);
}

static void *json_dec_auth_clnt_res(const struct ipa_buf *res, const void *req)
{
	return ipa_esipa_json_dec_auth_clnt_res(res, req);
}

#endif /* IPA_HAVE_ESIPA_JSON */

/*! Function: (Esipa) AuthenticateClient.
 *  \param[inout] ctx pointer to ipa_context.
 *  \param[in] req pointer to struct that holds the function parameters.
 *  \returns pointer newly allocated struct with function result, NULL on error. */
struct ipa_esipa_auth_clnt_res *ipa_esipa_auth_clnt(struct ipa_context *ctx, const struct ipa_esipa_auth_clnt_req *req)
{
	IPA_LOGP_ESIPA("AuthenticateClient", LINFO, "Requesting client authentication\n");

	return ipa_esipa_call(ctx, "AuthenticateClient", req,
			      IPA_ESIPA_ASN1_CB(enc_auth_clnt_req_cb, dec_auth_clnt_res),
			      IPA_ESIPA_JSON_CB(json_enc_auth_clnt_req, json_dec_auth_clnt_res));
}

/*! Free results of function: (Esipa) AuthenticateClient.
 *  \param[in] res pointer to function result. */
void ipa_esipa_auth_clnt_res_free(struct ipa_esipa_auth_clnt_res *res)
{
	IPA_ESIPA_RES_FREE(res);
}
