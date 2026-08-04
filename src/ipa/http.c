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
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
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

/* OpenSSL 3.0 deprecates the low-level EC_KEY API in favour of providers, but
 * routing ECDSA signing to external hardware still requires an EC_KEY_METHOD
 * (or a full custom provider, which is a much larger undertaking).  The
 * deprecated API is still functional, so keep using it and confine the
 * deprecation warnings to the code that needs it rather than disabling them
 * project-wide.  Revisit if OpenSSL removes EC_KEY_METHOD outright.
 * NOTE: this signing path is not reachable yet — nothing calls
 * ipa_http_set_client_cert_der(); see the mTLS TODO in eim_init(). */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

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

#pragma GCC diagnostic pop

/* -------------------------------------------------------------------------
 * HTTP client context
 * ------------------------------------------------------------------------- */
struct http_ctx {
	bool initialized;
	const char *cabundle;  /* path-based CA bundle (legacy / fallback) */
	bool no_verif;
	bool have_openssl_backend; /* libcurl supports CURLOPT_SSL_CTX_FUNCTION */
	CURL *curl;
	/* eUICC-provisioned TLS credentials. */
	char *ca_pem;          /* PEM text of CA cert (trustedCertificateTls) */
	size_t ca_pem_len;
	EVP_PKEY *ca_pk;       /* trust-anchor public key (trustedEimPkTls) */
	X509 *client_cert;     /* eUICC cert for TLS client authentication */
	ipa_tls_sign_fn sign_fn;
	void *sign_arg;
};

/* Install the eUICC certificate and its eUICC-backed ECDSA key for TLS client
 * authentication.  The private key never leaves the chip: we clone the public
 * EC_KEY out of the certificate and attach the EC_KEY_METHOD above, whose
 * sign_sig hook calls back into the eUICC.
 * (Deprecated EC_KEY API — see the note above init_sign_method_once().) */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
static CURLcode install_client_key(SSL_CTX *ssl_ctx, struct http_ctx *ctx)
{
	const EC_KEY *ec_orig;
	EC_KEY *ec;
	EVP_PKEY *pub, *pkey;
	struct http_sign_ctx *sc;

	if (SSL_CTX_use_certificate(ssl_ctx, ctx->client_cert) != 1)
		return CURLE_SSL_CERTPROBLEM;

	/* Extract the public-key EC_KEY from the certificate (no private key
	 * component — the private key lives in the eUICC and is never exported). */
	pub = X509_get_pubkey(ctx->client_cert);
	if (!pub)
		return CURLE_SSL_CERTPROBLEM;
	ec_orig = EVP_PKEY_get0_EC_KEY(pub); /* borrowed, owned by pub */
	ec = ec_orig ? EC_KEY_dup(ec_orig) : NULL;
	EVP_PKEY_free(pub);
	if (!ec)
		return CURLE_SSL_CERTPROBLEM;

	/* Attach our custom method; signing is delegated to the ipa_tls_sign_fn
	 * stored in the per-key ex-data. */
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

	return CURLE_OK;
}
#pragma GCC diagnostic pop

/* -------------------------------------------------------------------------
 * Trust-anchor-by-public-key verification (SGP.32 trustedEimPkTls).
 *
 * The eUICC may store only the *public key* of the eIM's TLS trust anchor,
 * not a certificate.  OpenSSL's trust store is cert-based, so we cannot add
 * a bare key to it.  Instead we let the normal chain verification run and
 * hook the one error it necessarily raises — the top-of-chain certificate is
 * not a known CA — and accept it iff its public key is exactly the key the
 * eUICC provisioned.
 *
 * All other checks (per-link signatures, validity dates, hostname) still run
 * and can still fail: OpenSSL calls the callback again for each of them.  The
 * chain is therefore verified up to a root whose key came from the eUICC,
 * which is precisely the trust decision SGP.32 asks for.
 * ------------------------------------------------------------------------- */
static int g_httpctx_ssl_ex_idx = -1;

static int trust_anchor_verify_cb(int preverify_ok, X509_STORE_CTX *store_ctx)
{
	SSL *ssl;
	SSL_CTX *ssl_ctx;
	struct http_ctx *ctx;
	X509 *cur;
	EVP_PKEY *cur_pk;
	int err;

	if (preverify_ok)
		return 1;

	err = X509_STORE_CTX_get_error(store_ctx);

	/* Only the "chain does not end in a locally trusted CA" family of errors
	 * is eligible for a public-key trust override.  Anything else (expired,
	 * bad signature, hostname mismatch, ...) is a genuine failure. */
	switch (err) {
	case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
	case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
	case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
	case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
	case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
	case X509_V_ERR_CERT_UNTRUSTED:
		break;
	default:
		return 0;
	}

	ssl = X509_STORE_CTX_get_ex_data(store_ctx,
					 SSL_get_ex_data_X509_STORE_CTX_idx());
	if (!ssl)
		return 0;
	ssl_ctx = SSL_get_SSL_CTX(ssl);
	ctx = ssl_ctx ? SSL_CTX_get_ex_data(ssl_ctx, g_httpctx_ssl_ex_idx) : NULL;
	if (!ctx || !ctx->ca_pk)
		return 0;

	cur = X509_STORE_CTX_get_current_cert(store_ctx);
	cur_pk = cur ? X509_get0_pubkey(cur) : NULL;
	if (!cur_pk)
		return 0;

	if (EVP_PKEY_eq(ctx->ca_pk, cur_pk) != 1) {
		IPA_LOGP(SHTTP, LERROR,
			 "TLS chain ends in an untrusted certificate whose public key "
			 "does not match the trust anchor stored in the eUICC\n");
		return 0;
	}

	IPA_LOGP(SHTTP, LDEBUG,
		 "TLS trust anchor accepted: public key matches eUICC trustedEimPkTls\n");
	X509_STORE_CTX_set_error(store_ctx, X509_V_OK);
	return 1;
}

/* -------------------------------------------------------------------------
 * CURLOPT_SSL_CTX_FUNCTION callback.  Installs whichever eUICC-provisioned
 * TLS credentials are present:
 *
 *  1. trustedCertificateTls: add the cert to the trust store and set
 *     X509_V_FLAG_PARTIAL_CHAIN, so a leaf or intermediate stored in the
 *     eUICC can act as a direct trust anchor (SGP.32 §3.1 encourages
 *     self-signed certs, which need not chain to a public root).
 *  2. trustedEimPkTls: install trust_anchor_verify_cb (see above).
 *  3. Client certificate: install the eUICC-backed ECDSA key for mTLS.
 * ------------------------------------------------------------------------- */
static CURLcode ssl_ctx_cb(CURL *curl, void *ssl_ctx_void, void *clientp)
{
	struct http_ctx *ctx = clientp;
	SSL_CTX *ssl_ctx = ssl_ctx_void;
	(void)curl;

	if (ctx->ca_pem) {
		X509_STORE *st = SSL_CTX_get_cert_store(ssl_ctx);
		BIO *bio = BIO_new_mem_buf(ctx->ca_pem, (int)ctx->ca_pem_len);
		if (bio) {
			X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
			BIO_free(bio);
			if (cert) {
				X509_STORE_add_cert(st, cert);
				X509_free(cert);
			}
		}
		X509_STORE_set_flags(st, X509_V_FLAG_PARTIAL_CHAIN);
	}

	/* trustedEimPkTls: the eUICC gave us a bare trust-anchor public key.
	 * Accept the otherwise-untrusted top of the chain iff its key matches. */
	if (ctx->ca_pk) {
		SSL_CTX_set_ex_data(ssl_ctx, g_httpctx_ssl_ex_idx, ctx);
		SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, trust_anchor_verify_cb);
	}

	if (ctx->client_cert && ctx->sign_fn)
		return install_client_key(ssl_ctx, ctx);

	return CURLE_OK;
}

/* -------------------------------------------------------------------------
 * Public API
 * ------------------------------------------------------------------------- */

/*! Initialize HTTP client.
 *  \param[in] cabundle path to a CA bundle (used when no DER cert is set).
 *  \param[in] no_verif skip SSL certificate verification (insecure).
 *  \returns pointer to newly allocated HTTP client context. */
/* The eUICC-provisioned TLS credential paths (SGP.32 trustedPublicKeyDataTls,
 * mTLS client auth) manipulate the SSL_CTX directly via
 * CURLOPT_SSL_CTX_FUNCTION, which libcurl only implements on OpenSSL-family
 * backends.  Against e.g. a GnuTLS-backed libcurl that option fails with
 * CURLE_NOT_BUILT_IN and the credentials can never be installed. */
static bool curl_has_openssl_backend(void)
{
	const curl_version_info_data *vi = curl_version_info(CURLVERSION_NOW);

	if (!vi || !vi->ssl_version)
		return false;

	return strstr(vi->ssl_version, "OpenSSL") ||
	       strstr(vi->ssl_version, "BoringSSL") ||
	       strstr(vi->ssl_version, "LibreSSL") ||
	       strstr(vi->ssl_version, "quictls");
}

/* curl_global_init()/curl_global_cleanup() are documented as per-*program*
 * (not per-handle) and are not thread-safe.  A single context made them look
 * per-context, but with more than one HTTP context live at once (e.g. eIM +
 * SM-DP+ for direct download) a per-context cleanup would tear the global state
 * down while another context is still using it.  Refcount them so the global
 * init runs once on the first context and the global cleanup runs once after
 * the last one is freed.  This assumes the single-threaded ipa_poll() model
 * used throughout the code base (the counter is not atomic). */
static unsigned int curl_global_refcnt;

void *ipa_http_init(const char *cabundle, bool no_verif)
{
	struct http_ctx *ctx = IPA_ALLOC(struct http_ctx);
	assert(ctx);
	memset(ctx, 0, sizeof(*ctx));

	if (curl_global_refcnt++ == 0)
		curl_global_init(CURL_GLOBAL_DEFAULT);
	ctx->initialized = true;
	ctx->cabundle = cabundle;
	ctx->no_verif = no_verif;
	ctx->have_openssl_backend = curl_has_openssl_backend();

	if (!ctx->have_openssl_backend) {
		const curl_version_info_data *vi = curl_version_info(CURLVERSION_NOW);
		IPA_LOGP(SHTTP, LERROR,
			 "libcurl is built against %s, not OpenSSL. TLS credentials stored "
			 "in the eUICC cannot be used; only -C <cabundle> will work. "
			 "Rebuild against an OpenSSL-backed libcurl "
			 "(Debian/Ubuntu: libcurl4-openssl-dev).\n",
			 (vi && vi->ssl_version) ? vi->ssl_version : "an unknown TLS library");
	}

	IPA_LOGP(SHTTP, LINFO, "HTTP client initialized.\n");

	return ctx;
}

/*! Set the CA certificate for TLS server verification from a DER blob
 *  (eUICC trustedCertificateTls).  When set, this supersedes the cabundle
 *  path from ipa_http_init().
 *  \param[in] der   DER-encoded X.509 certificate bytes.
 *  \param[in] len   byte length of der.
 *  \returns 0 on success, -EINVAL if the DER cannot be parsed. */
int ipa_http_set_ca_cert_der(void *http_ctx, const uint8_t *der, size_t len)
{
	struct http_ctx *ctx = http_ctx;
	const unsigned char *p = der;
	X509 *cert;
	char subj[256];
	BIO *bio;
	char *pem_data;
	long pem_len;

	assert(ctx);
	if (!der || !len)
		return -EINVAL;

	cert = d2i_X509(NULL, &p, (long)len);
	if (!cert) {
		IPA_LOGP(SHTTP, LERROR, "cannot parse DER CA certificate: %s\n",
			 ERR_reason_error_string(ERR_get_error()));
		return -EINVAL;
	}

	X509_NAME_oneline(X509_get_subject_name(cert), subj, sizeof(subj));

	/* The trust store is cert-based and loads PEM, so convert once here. */
	bio = BIO_new(BIO_s_mem());
	if (!bio || !PEM_write_bio_X509(bio, cert)) {
		BIO_free(bio);
		X509_free(cert);
		return -EINVAL;
	}
	pem_len = BIO_get_mem_data(bio, &pem_data);

	IPA_FREE(ctx->ca_pem);
	ctx->ca_pem = IPA_ALLOC_N(pem_len + 1);
	if (!ctx->ca_pem) {
		BIO_free(bio);
		X509_free(cert);
		return -EINVAL;
	}
	memcpy(ctx->ca_pem, pem_data, (size_t)pem_len);
	ctx->ca_pem[pem_len] = '\0';
	ctx->ca_pem_len = (size_t)pem_len;

	IPA_LOGP(SHTTP, LINFO, "eUICC TLS CA certificate installed (subject=%s)\n", subj);

	BIO_free(bio);
	X509_free(cert);
	return 0;
}

/*! Set the TLS trust anchor from a DER-encoded SubjectPublicKeyInfo blob.
 *  Used for the eUICC's trustedEimPkTls, which carries only the public key of
 *  the eIM's TLS trust anchor (typically a self-signed root CA) rather than a
 *  certificate.  The server chain is verified normally; the otherwise-untrusted
 *  certificate at the top of the chain is accepted iff its public key is this
 *  one.  See trust_anchor_verify_cb().
 *  \param[in] spki   DER-encoded SubjectPublicKeyInfo bytes.
 *  \param[in] len    byte length of spki.
 *  \returns 0 on success, -EINVAL on failure. */
int ipa_http_set_ca_pk_spki(void *http_ctx, const uint8_t *spki, size_t len)
{
	struct http_ctx *ctx = http_ctx;
	const unsigned char *p = spki;
	EVP_PKEY *pk;

	assert(ctx);
	if (!spki || !len)
		return -EINVAL;

	pk = d2i_PUBKEY(NULL, &p, (long)len);
	if (!pk) {
		IPA_LOGP(SHTTP, LERROR,
			 "cannot parse eUICC trustedEimPkTls SubjectPublicKeyInfo: %s\n",
			 ERR_reason_error_string(ERR_get_error()));
		return -EINVAL;
	}

	if (g_httpctx_ssl_ex_idx < 0)
		g_httpctx_ssl_ex_idx =
		    SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, NULL);

	if (ctx->ca_pk)
		EVP_PKEY_free(ctx->ca_pk);
	ctx->ca_pk = pk;

	IPA_LOGP(SHTTP, LINFO,
		 "eUICC TLS trust anchor public key installed (type=%s, bits=%d)\n",
		 OBJ_nid2sn(EVP_PKEY_base_id(pk)), EVP_PKEY_bits(pk));
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

	/* TLS server verification.  When an eUICC CA cert is set, ssl_ctx_cb
	 * (installed below) adds it to the OpenSSL trust store and sets
	 * X509_V_FLAG_PARTIAL_CHAIN — all in one place, with no ordering
	 * dependency on when curl fires the callback vs. when it loads CAs.
	 * System CAs (loaded by curl by default) remain in the store and are
	 * harmless alongside the eUICC cert. */
	if (ctx->ca_pem) {
		IPA_LOGP(SHTTP, LDEBUG,
			 "TLS CA: eUICC trustedCertificateTls (%zu PEM bytes) + PARTIAL_CHAIN\n",
			 ctx->ca_pem_len);
		/* ssl_ctx_cb handles cert loading; nothing to set here */
	} else if (ctx->ca_pk) {
		IPA_LOGP(SHTTP, LDEBUG,
			 "TLS CA: eUICC trustedEimPkTls trust-anchor public key\n");
		/* ssl_ctx_cb installs trust_anchor_verify_cb; nothing to set here */
	} else if (ctx->cabundle) {
		IPA_LOGP(SHTTP, LDEBUG, "TLS CA: file '%s'\n", ctx->cabundle);
		rc = curl_easy_setopt(ctx->curl, CURLOPT_CAINFO, ctx->cabundle);
		if (rc != CURLE_OK) {
			IPA_LOGP(SHTTP, LERROR, "internal HTTP-client failure: %s\n",
				 curl_easy_strerror(rc));
			goto error;
		}
	} else {
		IPA_LOGP(SHTTP, LDEBUG, "TLS CA: system CAs (no eUICC cert, no -C flag)\n");
	}

	/* ssl_ctx_cb is needed for three reasons:
	 *   - ca_pem set:      add eUICC cert to trust store + PARTIAL_CHAIN
	 *   - ca_pk set:       install trust-anchor-by-public-key verify callback
	 *   - client_cert set: install eUICC-backed ECDSA key for mTLS */
	if (ctx->ca_pem || ctx->ca_pk || ctx->client_cert) {
		rc = curl_easy_setopt(ctx->curl, CURLOPT_SSL_CTX_FUNCTION, ssl_ctx_cb);
		if (rc != CURLE_OK) {
			if (rc == CURLE_NOT_BUILT_IN)
				IPA_LOGP(SHTTP, LERROR,
					 "this libcurl does not support CURLOPT_SSL_CTX_FUNCTION, so the "
					 "TLS credentials stored in the eUICC cannot be installed. "
					 "libcurl must be built against OpenSSL "
					 "(Debian/Ubuntu: libcurl4-openssl-dev, not libcurl4-gnutls-dev). "
					 "As a stopgap, pass the eIM certificate with -C <cabundle>.\n");
			else
				IPA_LOGP(SHTTP, LERROR,
					 "cannot set CURLOPT_SSL_CTX_FUNCTION: %s\n",
					 curl_easy_strerror(rc));
			goto error;
		}
		rc = curl_easy_setopt(ctx->curl, CURLOPT_SSL_CTX_DATA, ctx);
		if (rc != CURLE_OK) {
			IPA_LOGP(SHTTP, LERROR, "cannot set CURLOPT_SSL_CTX_DATA: %s\n",
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
		unsigned long ossl_err;
		long ssl_vr = 0;
		curl_easy_getinfo(ctx->curl, CURLINFO_SSL_VERIFYRESULT, &ssl_vr);
		if (ssl_vr != 0)
			IPA_LOGP(SHTTP, LERROR, "SSL verify result: %ld (%s)\n",
				 ssl_vr, X509_verify_cert_error_string(ssl_vr));
		while ((ossl_err = ERR_get_error()) != 0) {
			char errbuf[256];
			ERR_error_string_n(ossl_err, errbuf, sizeof(errbuf));
			IPA_LOGP(SHTTP, LERROR, "OpenSSL error: %s\n", errbuf);
		}
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

	if (ctx->ca_pem) {
		IPA_FREE(ctx->ca_pem);
		ctx->ca_pem_len = 0;
	}
	if (ctx->ca_pk) {
		EVP_PKEY_free(ctx->ca_pk);
		ctx->ca_pk = NULL;
	}
	if (ctx->client_cert) {
		X509_free(ctx->client_cert);
		ctx->client_cert = NULL;
	}

	/* Only the last live HTTP context tears down the curl global state
	 * (see curl_global_refcnt note in ipa_http_init). */
	if (ctx->initialized && curl_global_refcnt > 0 && --curl_global_refcnt == 0)
		curl_global_cleanup();

	IPA_FREE(ctx);
	IPA_LOGP(SHTTP, LINFO, "HTTP client freed.\n");
}
