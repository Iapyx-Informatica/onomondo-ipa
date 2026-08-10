/*
 * Copyright (c) 2025 Onomondo ApS & sysmocom - s.f.m.c. GmbH. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Golden-file encode test for make_ipa_capabilties().
 *
 * Regression guard: the named feature/protocol bits must be packed into a DER
 * BIT STRING as MSB-first bits (byte N/8, mask 0x80 >> N%8) with bits_unused set,
 * NOT as one whole byte per bit.  The correct encoding is:
 *
 *   30 08                SEQUENCE, len 8
 *      80 02 02 50       [0] ipaFeatures        BIT STRING, 2 unused bits, 0x50
 *      81 02 03 80       [1] ipaSupportedProtocols BIT STRING, 3 unused bits, 0x80
 *
 * 0x50 = bits 1 (indirectRspServerCommunication) + 3 (eimCtxParams1Generation).
 * 0x80 = bit 0 (ipaRetrieveHttps).
 */

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <assert.h>
#include <onomondo/ipa/utils.h>
#include <onomondo/ipa/http.h>
#include <onomondo/ipa/scard.h>
#include <asn_application.h>
#include <der_encoder.h>
#include <IpaCapabilities.h>
#include "src/ipa/libipa/proc_euicc_data_req.h"

struct enc_buf {
	uint8_t data[64];
	size_t len;
};

static int enc_cb(const void *buf, size_t size, void *key)
{
	struct enc_buf *out = key;
	assert(out->len + size <= sizeof(out->data));
	memcpy(out->data + out->len, buf, size);
	out->len += size;
	return 0;
}

int main(void)
{
	static const uint8_t expected[] = {
		0x30, 0x08,
		0x80, 0x02, 0x02, 0x50,
		0x81, 0x02, 0x03, 0x80,
	};
	struct IpaCapabilities *caps;
	struct enc_buf out = { 0 };
	asn_enc_rval_t er;

	caps = make_ipa_capabilties();
	assert(caps);

	er = der_encode(&asn_DEF_IpaCapabilities, caps, enc_cb, &out);
	assert(er.encoded >= 0);

	printf("IpaCapabilities DER:");
	for (size_t i = 0; i < out.len; i++)
		printf(" %02x", out.data[i]);
	printf("\n");

	assert(out.len == sizeof(expected));
	assert(memcmp(out.data, expected, out.len) == 0);

	return 0;
}

/* Stubs (libipa expects these platform hooks; unused by this test) */
void *ipa_http_init(const char *cabundle, bool no_verif)
{
	return NULL;
}

struct ipa_buf *ipa_http_req(void *http_ctx, const struct ipa_buf *req, const char *url)
{
	return NULL;
}

struct ipa_buf *ipa_http_req_with_ct(void *http_ctx, const struct ipa_buf *req,
				     const char *url, const char *content_type)
{
	return NULL;
}

int ipa_http_set_ca_cert_der(void *http_ctx, const uint8_t *der, size_t len)
{
	return 0;
}

int ipa_http_set_ca_pk_spki(void *http_ctx, const uint8_t *spki, size_t len)
{
	return 0;
}

int ipa_http_set_client_cert_der(void *http_ctx,
				 const uint8_t *cert_der, size_t cert_len,
				 ipa_tls_sign_fn sign_fn, void *sign_arg)
{
	return 0;
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
