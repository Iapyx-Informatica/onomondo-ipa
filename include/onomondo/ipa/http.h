/*
 * Copyright (c) 2025 Onomondo ApS & sysmocom - s.f.m.c. GmbH. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
struct ipa_buf;

/* This is the initial buffer size. The HTTP client will automatically re-alloc more memory if needed. */
#define IPA_LEN_HTTP_RESPONSE_BUF 512	/* bytes */

void *ipa_http_init(const char *cabundle, bool no_verif);
struct ipa_buf *ipa_http_req(void *http_ctx, const struct ipa_buf *req, const char *url);
/* NEW v1.2 §6.4: variant taking an explicit Content-Type header so the
 * JSON binding can request application/json while the ASN.1 binding keeps
 * application/x-gsma-rsp-asn1.  Passing NULL content_type behaves identically
 * to ipa_http_req() (ASN.1 default). */
struct ipa_buf *ipa_http_req_with_ct(void *http_ctx, const struct ipa_buf *req,
				     const char *url, const char *content_type);
void ipa_http_close(void *http_ctx);
void ipa_http_free(void *http_ctx);

/* Signing callback used for TLS client authentication with a hardware key.
 * The TLS layer calls this when it needs the ECDSA CertificateVerify signature.
 *   hash/hash_len — pre-computed digest bytes (e.g. 32 bytes for SHA-256).
 *   sig/sig_len   — output buffer; *sig_len is the buffer capacity on entry
 *                   and is updated to the actual signature length on exit.
 *                   The signature must be DER-encoded ECDSA (r, s SEQUENCE).
 * Returns 1 on success, 0 on failure. */
typedef int (*ipa_tls_sign_fn)(void *arg,
			       const unsigned char *hash, unsigned int hash_len,
			       unsigned char *sig, unsigned int *sig_len);

/* Set the CA certificate used to verify the eIM TLS server, from a
 * DER-encoded X.509 blob.  When set this supersedes the cabundle path
 * given to ipa_http_init() and the trust store is limited to this
 * single certificate (no system-default CAs).
 * The DER bytes are parsed and copied; the caller may free der after return.
 * Returns 0 on success, -EINVAL on parse failure. */
int ipa_http_set_ca_cert_der(void *http_ctx, const uint8_t *der, size_t len);

/* Set the TLS client certificate and signing callback for mutual TLS.
 * cert_der/cert_len — DER-encoded eUICC X.509 certificate.
 * sign_fn/sign_arg  — callback and opaque argument; the callback must
 *                     invoke the eUICC to perform the ECDSA signing
 *                     (e.g. via ES10b or a raw PC/SC APDU).
 * Both cert and sign_fn must be non-NULL; the certificate is parsed and
 * copied immediately.  Returns 0 on success, -EINVAL on failure. */
int ipa_http_set_client_cert_der(void *http_ctx,
				 const uint8_t *cert_der, size_t cert_len,
				 ipa_tls_sign_fn sign_fn, void *sign_arg);
