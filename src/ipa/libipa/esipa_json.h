/*
 * Copyright (c) 2025 Onomondo ApS & sysmocom - s.f.m.c. GmbH. All rights reserved.
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * NEW in v1.1/v1.2: §6.4 — JSON binding for the ESipa interface.
 *
 * The JSON binding is an alternative wire encoding for ESipa messages (v1.2
 * §6.4).  Most fields are simply base64 of the DER-encoded corresponding
 * ASN.1 structure; a handful are hex (TransactionId) or plain strings
 * (matchingId, smdpAddress).  This header exposes per-function JSON
 * encoders/decoders that the public esipa_*.c files dispatch to when
 * ctx->cfg->esipa_binding == IPA_ESIPA_BINDING_JSON.
 *
 * Requires libjansson at build time (auto-detected in libipa/CMakeLists.txt).
 * If jansson is absent, each of these returns NULL / -1.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

struct ipa_buf;
struct ipa_context;
struct EsipaMessageFromIpaToEim;
struct EsipaMessageFromEimToIpa;

struct ipa_esipa_init_auth_req;
struct ipa_esipa_init_auth_res;
struct ipa_esipa_auth_clnt_req;
struct ipa_esipa_auth_clnt_res;
struct ipa_esipa_get_eim_pkg_res;
struct ipa_esipa_prvde_eim_pkg_rslt_req;
struct ipa_esipa_prvde_eim_pkg_rslt_res;
struct ipa_esipa_get_bnd_prfle_pkg_req;
struct ipa_esipa_get_bnd_prfle_pkg_res;
struct ipa_esipa_handle_notif_req;
struct ipa_esipa_cancel_session_req;

/* Per-function URL path suffix for JSON binding.  Returns a pointer to a
 * static string or NULL if the function name is unknown. */
const char *ipa_esipa_json_url_path(const char *function_name);

/* HTTP Content-Type for the given binding. */
const char *ipa_esipa_content_type(int esipa_binding);

/* Is the JSON binding actually compiled in (jansson present)? */
bool ipa_esipa_json_available(void);

/* ---- Encoders (IPA -> eIM requests / notifications) ------------------- */

struct ipa_buf *ipa_esipa_json_enc_init_auth_req(const struct ipa_esipa_init_auth_req *req);
struct ipa_buf *ipa_esipa_json_enc_auth_clnt_req(const struct ipa_esipa_auth_clnt_req *req);
struct ipa_buf *ipa_esipa_json_enc_get_bnd_prfle_pkg_req(const struct ipa_esipa_get_bnd_prfle_pkg_req *req);
struct ipa_buf *ipa_esipa_json_enc_get_eim_pkg_req(const uint8_t *eid, bool notify_state_change,
						   int state_change_cause /* -1 = absent */,
						   const uint8_t *rplmn /* NULL = absent */);
struct ipa_buf *ipa_esipa_json_enc_prvde_eim_pkg_rslt_req(const struct ipa_context *ctx,
							  const struct ipa_esipa_prvde_eim_pkg_rslt_req *req);
struct ipa_buf *ipa_esipa_json_enc_handle_notif_req(const struct ipa_esipa_handle_notif_req *req);
struct ipa_buf *ipa_esipa_json_enc_cancel_session_req(const struct ipa_esipa_cancel_session_req *req);
struct ipa_buf *ipa_esipa_json_enc_transfer_eim_pkg_rsp(const struct ipa_esipa_prvde_eim_pkg_rslt_req *req);

/* Report whether the eIM's response header says the function succeeded.  For ESipa.CancelSession,
 * which section 6.4.1.8 gives no response body, that header is the whole response. */
bool ipa_esipa_json_exec_ok(const struct ipa_buf *body, const char *function_name);

/* ---- Decoders (eIM -> IPA responses) ---------------------------------- */

/* All decoders allocate the result struct via IPA_ALLOC_ZERO and return it
 * (NULL on error).  The fields inside that struct may point into an inner
 * ASN.1 tree owned by the result (e.g. auth_clnt_ok_dpe); callers free via
 * the existing ipa_esipa_*_free() helpers. */
struct ipa_esipa_init_auth_res *ipa_esipa_json_dec_init_auth_res(const struct ipa_buf *body);
struct ipa_esipa_auth_clnt_res *ipa_esipa_json_dec_auth_clnt_res(const struct ipa_buf *body,
								 const struct ipa_esipa_auth_clnt_req *req);
struct ipa_esipa_get_bnd_prfle_pkg_res *ipa_esipa_json_dec_get_bnd_prfle_pkg_res(const struct ipa_buf *body);
struct ipa_esipa_get_eim_pkg_res *ipa_esipa_json_dec_get_eim_pkg_res(const struct ipa_buf *body);
struct ipa_esipa_prvde_eim_pkg_rslt_res *ipa_esipa_json_dec_prvde_eim_pkg_rslt_res(const struct ipa_buf *body);
