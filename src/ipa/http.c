/*
 * Copyright (c) 2025 Onomondo ApS & sysmocom - s.f.m.c. GmbH. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Author: Philipp Maier <pmaier@sysmocom.de> / sysmocom - s.f.m.c. GmbH
 * Author: Harald Welte <hwelte@sysmocom.de> / sysmocom - s.f.m.c. GmbH
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <assert.h>
#include <string.h>
#include <curl/curl.h>
/* OpenSSL is used to install eUICC-provisioned TLS credentials into the
 * SSL_CTX before each handshake via CURLOPT_SSL_CTX_FUNCTION. */
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <onomondo/ipa/utils.h>
#include <onomondo/ipa/http.h>
#include <onomondo/ipa/http_hdr.h>
#include <onomondo/ipa/log.h>
#include <onomondo/ipa/mem.h>

/* -------------------------------------------------------------------------
 * Per-key signing context — carries the ipa_tls_sign_fn pointer and its
 * opaque argument, stored as OpenSSL EC_KEY ex-data so the module-wide
 * EC_KEY_METHOD can reach back to the per-connection callback.
 * ------------------------------------------------------------------------- */
struct http_sign_ctx {
	ipa_tls_sign_fn fn;
	void *arg;
};

/* OpenSSL ex-data free callback: releases http_sign_ctx when the EC_KEY
 * that owns it is freed (e.g. at the end of a TLS handshake). */
static void sign_ctx_ex_free(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
			     int idx, long argl, void *argp)
{
	(void)parent;
	(void)ad;
	(void)idx;
	(void)argl;
	(void)argp;
	IPA_FREE(ptr);
}

/* Module-wide EC_KEY_METHOD and its ex-data index; initialised once. */
static int g_sign_ctx_ex_idx = -1;
static EC_KEY_METHOD *g_sign_method;

/* ECDSA sign_sig hook — called by the OpenSSL ECDSA path with the
 * pre-computed hash bytes.  Delegates the actual signing to the eUICC
 * via the per-key ipa_tls_sign_fn stored in ex-data.
 * The function must return a heap-allocated ECDSA_SIG * on success, or
 * NULL on failure; OpenSSL frees the returned struct. */
static ECDSA_SIG *tls_ecdsa_sign_sig(const unsigned char *dgst, int dlen,
				     const BIGNUM *kinv, const BIGNUM *rp,
				     EC_KEY *ec)
{
	struct http_sign_ctx *sc;
	unsigned char raw[256]; /* DER ECDSA sig; 256 bytes covers P-521 */
	unsigned int raw_len = sizeof(raw);
	const unsigned char *p;

	(void)kinv;
	(void)rp;

	sc = EC_KEY_get_ex_data(ec, g_sign_ctx_ex_idx);
	if (!sc || !sc->fn)
		return NULL;

	if (!sc->fn(sc->arg, dgst, (unsigned int)dlen, raw, &raw_len))
		return NULL;

	/* Decode the DER-encoded ECDSA signature returned by the eUICC */
	p = raw;
	return d2i_ECDSA_SIG(NULL, &p, (long)raw_len);
}

static void init_sign_method_once(void)
{
	if (g_sign_method)
		return;
	g_sign_ctx_ex_idx = EC_KEY_get_ex_new_index(0, NULL, NULL, NULL,
						     sign_ctx_ex_free);
	g_sign_method = EC_KEY_METHOD_new(EC_KEY_OpenSSL());
	/* Override only the sign_sig leaf; leave sign and sign_setup NULL so
	 * OpenSSL uses its default k-generation but routes the actual signing
	 * through our callback. */
	EC_KEY_METHOD_set_sign(g_sign_method, NULL, NULL, tls_ecdsa_sign_sig);
}

/* -------------------------------------------------------------------------
 * HTTP client context
 * ------------------------------------------------------------------------- */
struct http_ctx {
	bool initialized;
	const char *cabundle;  /* path-based CA bundle (legacy / fallback) */
	bool no_verif;
	CURL *curl;
	/* eUICC-provisioned TLS credentials; both are NULL when not set. */
	X509 *ca_cert;	       /* CA for TLS server verification */
	X509 *client_cert;     /* eUICC cert for TLS client authentication */
	ipa_tls_sign_fn sign_fn;
	void *sign_arg;
};

/* -------------------------------------------------------------------------
 * CURLOPT_SSL_CTX_FUNCTION callback
 *
 * Called by curl once per new TLS connection, immediately after the
 * SSL_CTX is created and before certificate validation begins.  We use
 * this to:
 *   1. Replace the trust store with one that contains only the eUICC-
 *      provisioned CA certificate (when ca_cert is set), ensuring the
 *      IPA trusts exactly the CA registered on the eUICC and nothing else.
 *   2. Install the eUICC client certificate and a custom ECDSA signing
 *      key backed by the ipa_tls_sign_fn callback (when both client_cert
 *      and sign_fn are set), enabling mutual TLS with the eIM.
 * ------------------------------------------------------------------------- */
static CURLcode ssl_ctx_cb(CURL *curl, void *ssl_ctx_void, void *clientp)
{
	struct http_ctx *ctx = clientp;
	SSL_CTX *ssl_ctx = ssl_ctx_void;
	(void)curl;

	if (ctx->ca_cert) {
		/* Build a new, empty trust store and add only our CA cert.
		 * SSL_CTX_set_cert_store() takes ownership of the new store
		 * and frees the previous one (which may contain system CAs
		 * loaded by curl from CURLOPT_CAINFO or system defaults). */
		X509_STORE *store = X509_STORE_new();
		if (!store)
			return CURLE_OUT_OF_MEMORY;
		if (!X509_STORE_add_cert(store, ctx->ca_cert)) {
			X509_STORE_free(store);
			return CURLE_SSL_CACERT_BADFILE;
		}
		SSL_CTX_set_cert_store(ssl_ctx, store);
	}

	if (ctx->client_cert && ctx->sign_fn) {
		EC_KEY *ec_orig, *ec;
		EVP_PKEY *pub, *pkey;
		struct http_sign_ctx *sc;

		if (SSL_CTX_use_certificate(ssl_ctx, ctx->client_cert) != 1)
			return CURLE_SSL_CERTPROBLEM;

		/* Extract the public-key EC_KEY from the certificate (no
		 * private key component — the private key lives in the eUICC
		 * and is never exported). */
		pub = X509_get_pubkey(ctx->client_cert);
		if (!pub)
			return CURLE_SSL_CERTPROBLEM;
		ec_orig = EVP_PKEY_get0_EC_KEY(pub);
		ec = ec_orig ? EC_KEY_dup(ec_orig) : NULL;
		EVP_PKEY_free(pub);
		if (!ec)
			return CURLE_SSL_CERTPROBLEM;

		/* Attach our custom method; signing is delegated to the
		 * ipa_tls_sign_fn stored in the per-key ex-data. */
		init_sign_method_once();
		EC_KEY_set_method(ec, g_sign_method);

		sc = IPA_ALLOC(struct http_sign_ctx);
		if (!sc) {
			EC_KEY_free(ec);
			return CURLE_OUT_OF_MEMORY;
		}
		sc->fn = ctx->sign_fn;
		sc->arg = ctx->sign_arg;
		/* sign_ctx_ex_free releases sc when ec is eventually freed. */
		EC_KEY_set_ex_data(ec, g_sign_ctx_ex_idx, sc);

		pkey = EVP_PKEY_new();
		if (!pkey) {
			EC_KEY_free(ec); /* also frees sc via ex-data */
			return CURLE_OUT_OF_MEMORY;
		}
		EVP_PKEY_assign_EC_KEY(pkey, ec); /* pkey takes ownership of ec */

		if (SSL_CTX_use_PrivateKey(ssl_ctx, pkey) != 1) {
			EVP_PKEY_free(pkey); /* also frees ec and sc */
			return CURLE_SSL_CERTPROBLEM;
		}
		EVP_PKEY_free(pkey);
	}

	return CURLE_OK;
}

/* -------------------------------------------------------------------------
 * Public API
 * ------------------------------------------------------------------------- */

/*! Initialize HTTP client.
 *  \param[in] cabundle path to a CA bundle (used when no DER cert is set).
 *  \param[in] no_verif skip SSL certificate verification (insecure).
 *  \returns pointer to newly allocated HTTP client context. */
void *ipa_http_init(const char *cabundle, bool no_verif)
{
	struct http_ctx *ctx = IPA_ALLOC(struct http_ctx);
	assert(ctx);
	memset(ctx, 0, sizeof(*ctx));

	curl_global_init(CURL_GLOBAL_DEFAULT);
	ctx->initialized = true;
	ctx->cabundle = cabundle;
	ctx->no_verif = no_verif;

	IPA_LOGP(SHTTP, LINFO, "HTTP client initialized.\n");

	return ctx;
}

/*! Set the CA certificate for TLS server verification from a DER blob.
 *  When set, this supersedes the cabundle path from ipa_http_init() and
 *  restricts the trust store to this certificate only (no system CAs).
 *  \param[in] der   DER-encoded X.509 certificate bytes.
 *  \param[in] len   byte length of der.
 *  \returns 0 on success, -EINVAL if the DER cannot be parsed. */
int ipa_http_set_ca_cert_der(void *http_ctx, const uint8_t *der, size_t len)
{
	struct http_ctx *ctx = http_ctx;
	const unsigned char *p = der;
	X509 *cert;

	assert(ctx);
	if (!der || !len)
		return -EINVAL;

	cert = d2i_X509(NULL, &p, (long)len);
	if (!cert) {
		IPA_LOGP(SHTTP, LERROR, "cannot parse DER CA certificate: %s\n",
			 ERR_reason_error_string(ERR_get_error()));
		return -EINVAL;
	}

	if (ctx->ca_cert)
		X509_free(ctx->ca_cert);
	ctx->ca_cert = cert;

	IPA_LOGP(SHTTP, LINFO,
		 "eUICC CA certificate installed for TLS server verification.\n");
	return 0;
}

/*! Set the TLS client certificate and ECDSA signing callback for mTLS.
 *  \param[in] cert_der  DER-encoded eUICC X.509 certificate.
 *  \param[in] cert_len  byte length of cert_der.
 *  \param[in] sign_fn   callback that performs ECDSA signing via the eUICC.
 *  \param[in] sign_arg  opaque argument forwarded to every sign_fn call.
 *  \returns 0 on success, -EINVAL on bad arguments or parse failure. */
int ipa_http_set_client_cert_der(void *http_ctx,
				 const uint8_t *cert_der, size_t cert_len,
				 ipa_tls_sign_fn sign_fn, void *sign_arg)
{
	struct http_ctx *ctx = http_ctx;
	const unsigned char *p = cert_der;
	X509 *cert;

	assert(ctx);
	if (!cert_der || !cert_len || !sign_fn)
		return -EINVAL;

	cert = d2i_X509(NULL, &p, (long)cert_len);
	if (!cert) {
		IPA_LOGP(SHTTP, LERROR,
			 "cannot parse DER client certificate: %s\n",
			 ERR_reason_error_string(ERR_get_error()));
		return -EINVAL;
	}

	if (ctx->client_cert)
		X509_free(ctx->client_cert);
	ctx->client_cert = cert;
	ctx->sign_fn = sign_fn;
	ctx->sign_arg = sign_arg;

	IPA_LOGP(SHTTP, LINFO,
		 "eUICC client certificate installed for TLS client authentication.\n");
	return 0;
}

/* Callback function to extract the HTTP response */
static size_t store_response_cb(void *ptr, size_t size, size_t nmemb, void *clientp)
{
	struct ipa_buf *buf = *(struct ipa_buf **)clientp;
	size_t realloc_size;

	if (buf->len + size * nmemb > buf->data_len) {
		realloc_size = ((buf->len + size * nmemb) / IPA_LEN_HTTP_RESPONSE_BUF + 1) * IPA_LEN_HTTP_RESPONSE_BUF;
		IPA_LOGP(SIPA, LDEBUG,
			 "HTTP response buffer exhausted, reallocating more memory (have: %zu bytes, required: %zu bytes, will allocate: %zu bytes)\n",
			 buf->data_len, buf->len + size * nmemb, realloc_size);
		buf = ipa_buf_realloc(buf, realloc_size);
		assert(buf);
		*(struct ipa_buf **)clientp = buf;
	}

	memcpy(buf->data + buf->len, ptr, size * nmemb);
	buf->len += size * nmemb;

	return size * nmemb;
}

/*! Open a TCP connection (if not already present) and Perform HTTP request.
 *  \param[inout] http_ctx HTTP client context.
 *  \param[in] req buffer with HTTP request (POST).
 *  \param[in] url URL with HTTP request.
 *  \returns HTTP response on success, NULL on failure. */
struct ipa_buf *ipa_http_req(void *http_ctx, const struct ipa_buf *req, const char *url)
{
	return ipa_http_req_with_ct(http_ctx, req, url, NULL);
}

struct ipa_buf *ipa_http_req_with_ct(void *http_ctx, const struct ipa_buf *req,
				     const char *url, const char *content_type)
{
	struct http_ctx *ctx = http_ctx;
	CURLcode rc;
	struct curl_slist *list = NULL;
	struct ipa_buf *res = ipa_buf_alloc(IPA_LEN_HTTP_RESPONSE_BUF);
	char ct_header[128];

	assert(ctx->initialized);

	/* Create a new curl context (also represents an ongoing connection) in case it does not exist */
	if (!ctx->curl) {
		ctx->curl = curl_easy_init();
		if (!ctx->curl) {
			IPA_LOGP(SHTTP, LERROR, "internal HTTP-client failure!\n");
			goto error;
		}
	}

	/* TLS server verification: use the eUICC-provisioned CA cert when
	 * available (via ssl_ctx_cb which replaces the trust store), or fall
	 * back to the path-based CA bundle supplied at init time. */
	if (ctx->ca_cert || ctx->client_cert) {
		rc = curl_easy_setopt(ctx->curl, CURLOPT_SSL_CTX_FUNCTION,
				      ssl_ctx_cb);
		if (rc != CURLE_OK) {
			IPA_LOGP(SHTTP, LERROR, "internal HTTP-client failure: %s\n",
				 curl_easy_strerror(rc));
			goto error;
		}
		rc = curl_easy_setopt(ctx->curl, CURLOPT_SSL_CTX_DATA, ctx);
		if (rc != CURLE_OK) {
			IPA_LOGP(SHTTP, LERROR, "internal HTTP-client failure: %s\n",
				 curl_easy_strerror(rc));
			goto error;
		}
	} else if (ctx->cabundle) {
		rc = curl_easy_setopt(ctx->curl, CURLOPT_CAINFO, ctx->cabundle);
		if (rc != CURLE_OK) {
			IPA_LOGP(SHTTP, LERROR, "internal HTTP-client failure: %s\n",
				 curl_easy_strerror(rc));
			goto error;
		}
	}

	if (ctx->no_verif) {
		/* Bypass SSL certificate verification (only for debug, disable in productive use!) */
		rc = curl_easy_setopt(ctx->curl, CURLOPT_SSL_VERIFYPEER, 0L);
		if (rc != CURLE_OK) {
			IPA_LOGP(SHTTP, LERROR, "internal HTTP-client failure: %s\n", curl_easy_strerror(rc));
			goto error;
		}

		/* Bypass SSL hostname verification (only for debug, disable in productive use!) */
		rc = curl_easy_setopt(ctx->curl, CURLOPT_SSL_VERIFYHOST, 0L);
		if (rc != CURLE_OK) {
			IPA_LOGP(SHTTP, LERROR, "internal HTTP-client failure: %s\n", curl_easy_strerror(rc));
			goto error;
		}
		IPA_LOGP(SHTTP, LINFO, "security disabled: will not verify server certificate and hostname\n");
	}

	/* Setup header, see also SGP.32, section 6.1.1 */
	/* UPDATE for v1.2: CR111005R00 — User-Agent now has a spec-defined value;
	 * see IPA_HTTP_USER_AGENT in onomondo/ipa/http_hdr.h.
	 * NEW v1.2 §6.4: content_type may be passed explicitly (JSON binding);
	 * falls back to the ASN.1 default when NULL. */
	list = curl_slist_append(list, "Accept:");
	list = curl_slist_append(list, "User-Agent: " IPA_HTTP_USER_AGENT);
	list = curl_slist_append(list, "X-Admin-Protocol: " IPA_HTTP_X_ADMIN_PROTOCOL);
	if (content_type && *content_type) {
		snprintf(ct_header, sizeof(ct_header), "Content-Type: %s", content_type);
		list = curl_slist_append(list, ct_header);
	} else {
		list = curl_slist_append(list, "Content-Type: " IPA_HTTP_CONTENT_TYPE);
	}
	rc = curl_easy_setopt(ctx->curl, CURLOPT_HTTPHEADER, list);
	if (rc != CURLE_OK) {
		IPA_LOGP(SHTTP, LERROR, "internal HTTP-client failure: %s\n", curl_easy_strerror(rc));
		goto error;
	}

	/* Perform HTTP Request */
	rc = curl_easy_setopt(ctx->curl, CURLOPT_URL, url);
	if (rc != CURLE_OK) {
		IPA_LOGP(SHTTP, LERROR, "internal HTTP-client failure: %s\n", curl_easy_strerror(rc));
		goto error;
	}
	rc = curl_easy_setopt(ctx->curl, CURLOPT_POSTFIELDS, req->data);
	if (rc != CURLE_OK) {
		IPA_LOGP(SHTTP, LERROR, "internal HTTP-client failure: %s\n", curl_easy_strerror(rc));
		goto error;
	}
	rc = curl_easy_setopt(ctx->curl, CURLOPT_POSTFIELDSIZE, req->len);
	if (rc != CURLE_OK) {
		IPA_LOGP(SHTTP, LERROR, "internal HTTP-client failure: %s\n", curl_easy_strerror(rc));
		goto error;
	}
	rc = curl_easy_setopt(ctx->curl, CURLOPT_WRITEFUNCTION, store_response_cb);
	if (rc != CURLE_OK) {
		IPA_LOGP(SHTTP, LERROR, "internal HTTP-client failure: %s\n", curl_easy_strerror(rc));
		goto error;
	}
	rc = curl_easy_setopt(ctx->curl, CURLOPT_WRITEDATA, (void *)&res);
	if (rc != CURLE_OK) {
		IPA_LOGP(SHTTP, LERROR, "internal HTTP-client failure: %s\n", curl_easy_strerror(rc));
		goto error;
	}
	rc = curl_easy_setopt(ctx->curl, CURLOPT_TIMEOUT, 5);
	if (rc != CURLE_OK) {
		IPA_LOGP(SHTTP, LERROR, "internal HTTP-client failure: %s\n", curl_easy_strerror(rc));
		goto error;
	}

	rc = curl_easy_perform(ctx->curl);
	if (rc != CURLE_OK) {
		IPA_LOGP(SHTTP, LERROR, "HTTP request to %s failed: %s\n", url, curl_easy_strerror(rc));
		goto error;
	}
	IPA_LOGP(SHTTP, LINFO, "HTTP request to %s successful: %s\n", url, curl_easy_strerror(rc));

	curl_slist_free_all(list);
	return res;
error:
	ipa_http_close(http_ctx);
	curl_slist_free_all(list);
	ipa_buf_free(res);
	return NULL;
}

/*! Close the TCP underlying TCP connection (to be called after the last request).
 *  \param[inout] http_ctx HTTP client context. */
void ipa_http_close(void *http_ctx)
{
	struct http_ctx *ctx = http_ctx;
	if (!ctx->curl)
		return;
	curl_easy_cleanup(ctx->curl);
	ctx->curl = NULL;
}

/*! Free HTTP client.
 *  \param[inout] http_ctx HTTP client context. */
void ipa_http_free(void *http_ctx)
{
	struct http_ctx *ctx = http_ctx;

	if (!http_ctx)
		return;

	ipa_http_close(http_ctx);

	if (ctx->ca_cert) {
		X509_free(ctx->ca_cert);
		ctx->ca_cert = NULL;
	}
	if (ctx->client_cert) {
		X509_free(ctx->client_cert);
		ctx->client_cert = NULL;
	}

	curl_global_cleanup();
	IPA_FREE(ctx);
	IPA_LOGP(SHTTP, LINFO, "HTTP client freed.\n");
}
