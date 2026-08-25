/*
 * Copyright (c) 2026 Onomondo ApS & sysmocom - s.f.m.c. GmbH & Iapyx Informatica Ltda. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * What the build options actually leave in the image.
 *
 * These are not tests of behaviour so much as guards on the build: the codec trimming in asn1/gen_libasn.sh and
 * the binding guards in the ESipa modules only pay off if they keep happening, and both of them fail silently --
 * a trimming step that stops matching, or a #ifdef that stops covering a function, costs image size and breaks
 * nothing that any other test would notice.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <stdbool.h>
#include <onomondo/ipa/utils.h>
#include <onomondo/ipa/ipad.h>
#include <EimConfigurationData.h>
#include <EsipaMessageFromIpaToEim.h>
#include <UICCCapability.h>
#include "src/ipa/libipa/context.h"
#include "src/ipa/libipa/esipa.h"

/* asn1c 0.9.28 keeps the codec entry points as direct members of the type descriptor; asn1c master moved them into
 * a shared asn_TYPE_operation_t, where they are not per type and there is nothing for gen_libasn.sh to zero. Only
 * the first layout can be checked this way. */
#ifndef ASN1C_TYPE_HAS_OP
#define TD_XER_DEC(td) ((td).xer_decoder)
#define TD_XER_ENC(td) ((td).xer_encoder)
#define TD_PRINT(td) ((td).print_struct)
#define TD_BER_DEC(td) ((td).ber_decoder)
#define TD_DER_ENC(td) ((td).der_encoder)
#endif

/* Nothing in this project reads or writes XER, so no type should carry the codec for it. */
static void no_xer_codec_test(void)
{
	printf("== no_xer_codec_test ==\n");

#ifdef ASN1C_TYPE_HAS_OP
	printf("   asn1c master layout: codec slots are shared between types, nothing per type to check\n");
#else
	assert(TD_XER_DEC(asn_DEF_EimConfigurationData) == NULL);
	assert(TD_XER_ENC(asn_DEF_EimConfigurationData) == NULL);
	assert(TD_XER_DEC(asn_DEF_EsipaMessageFromIpaToEim) == NULL);
	assert(TD_XER_ENC(asn_DEF_EsipaMessageFromIpaToEim) == NULL);
	assert(TD_XER_DEC(asn_DEF_UICCCapability) == NULL);
	assert(TD_XER_ENC(asn_DEF_UICCCapability) == NULL);

	/* ... while the codecs that are used are of course still there. Without this the test would also pass on a
	 * generated tree that had been trimmed to nothing. */
	assert(TD_BER_DEC(asn_DEF_EimConfigurationData) != NULL);
	assert(TD_DER_ENC(asn_DEF_EimConfigurationData) != NULL);
	assert(TD_BER_DEC(asn_DEF_EsipaMessageFromIpaToEim) != NULL);
	assert(TD_DER_ENC(asn_DEF_EsipaMessageFromIpaToEim) != NULL);
	printf("   XER slots are empty, BER/DER slots are not\n");
#endif
}

/* The asn1c type printers are reachable only from ipa_asn1c_dump() under SHOW_ASN_OUTPUT, so a build without that
 * option should not carry them -- and a build with it must. */
static void printer_follows_show_asn_output_test(void)
{
	printf("== printer_follows_show_asn_output_test ==\n");

#ifdef ASN1C_TYPE_HAS_OP
	printf("   asn1c master layout: printers are shared between types, nothing per type to check\n");
#elif defined(SHOW_ASN_OUTPUT)
	assert(TD_PRINT(asn_DEF_EimConfigurationData) != NULL);
	assert(TD_PRINT(asn_DEF_EsipaMessageFromIpaToEim) != NULL);
	printf("   SHOW_ASN_OUTPUT is on and the printers are present\n");
#else
	assert(TD_PRINT(asn_DEF_EimConfigurationData) == NULL);
	assert(TD_PRINT(asn_DEF_EsipaMessageFromIpaToEim) == NULL);
	assert(TD_PRINT(asn_DEF_UICCCapability) == NULL);
	printf("   SHOW_ASN_OUTPUT is off and the printers are gone\n");
#endif
}

/* A binding that was not built hands ipa_esipa_call() a pair of NULL callbacks. It has to notice before it calls
 * one of them, and before it reaches the transport -- the stubs at the bottom of this file would fail the test by
 * aborting if it got that far. */
static void unbuilt_binding_is_refused_test(void)
{
	struct ipa_config cfg = { 0 };
	struct ipa_context ctx = { 0 };

	printf("== unbuilt_binding_is_refused_test ==\n");
	ctx.cfg = &cfg;

	cfg.esipa_binding = IPA_ESIPA_BINDING_ASN1;
	assert(ipa_esipa_call(&ctx, "TestFunction", NULL, NULL, NULL, NULL, NULL) == NULL);

	cfg.esipa_binding = IPA_ESIPA_BINDING_JSON;
	assert(ipa_esipa_call(&ctx, "TestFunction", NULL, NULL, NULL, NULL, NULL) == NULL);
}

/* Whichever bindings this build has, IPA_ESIPA_ASN1_CB / IPA_ESIPA_JSON_CB have to agree with them: a macro that
 * yields NULL for a binding that was built would disable it, and one that yields a function for a binding that was
 * not would fail to link. At least one binding always exists (CMake refuses to configure otherwise). */
static struct ipa_buf *dummy_enc(struct ipa_context *ctx, const void *req)
{
	(void)ctx;
	(void)req;
	return NULL;
}

static void *dummy_dec(const struct ipa_buf *res, const void *req)
{
	(void)res;
	(void)req;
	return NULL;
}

static void binding_macros_match_the_build_test(void)
{
	/* void * because the pair is an encoder and a decoder, which have different types; only whether they are
	 * NULL matters here. */
	void *asn1[] = { IPA_ESIPA_ASN1_CB(dummy_enc, dummy_dec) };
	void *json[] = { IPA_ESIPA_JSON_CB(dummy_enc, dummy_dec) };

	printf("== binding_macros_match_the_build_test ==\n");

#ifdef IPA_HAVE_ESIPA_ASN1
	assert(asn1[0] != NULL && asn1[1] != NULL);
	printf("   ASN.1 binding built\n");
#else
	assert(asn1[0] == NULL && asn1[1] == NULL);
	printf("   ASN.1 binding not built\n");
#endif
#ifdef IPA_HAVE_ESIPA_JSON
	assert(json[0] != NULL && json[1] != NULL);
	printf("   JSON binding built\n");
#else
	assert(json[0] == NULL && json[1] == NULL);
	printf("   JSON binding not built\n");
#endif
	assert(asn1[0] || json[0]);
}

/* IPA_EUICC_EMU() folds to a constant 0 in a build without the emulation, whatever the runtime flag says. */
static void emulation_macro_test(void)
{
	struct ipa_config cfg = { 0 };
	struct ipa_context ctx = { 0 };

	printf("== emulation_macro_test ==\n");
	ctx.cfg = &cfg;
	(void)ctx;	/* IPA_EUICC_EMU() does not read it in a build without the emulation */

	cfg.iot_euicc_emu_enabled = true;
#ifdef IPA_HAVE_IOT_EUICC_EMULATION
	assert(IPA_EUICC_EMU(&ctx));
	printf("   emulation built, the runtime flag decides\n");
#else
	assert(!IPA_EUICC_EMU(&ctx));
	printf("   emulation not built, the runtime flag cannot turn it on\n");
#endif

	cfg.iot_euicc_emu_enabled = false;
	assert(!IPA_EUICC_EMU(&ctx));
}

int main(int argc, char **argv)
{
	no_xer_codec_test();
	printer_follows_show_asn_output_test();
	unbuilt_binding_is_refused_test();
	binding_macros_match_the_build_test();
	emulation_macro_test();
	printf("build_options_test: all checks passed\n");
	return 0;
}

/* Stubs. Reaching the transport at all would be a failure here, so these abort rather than return. */
void *ipa_http_init(const char *cabundle, bool no_verif)
{
	assert(0 && "the transport must not be reached");
	return NULL;
}

struct ipa_buf *ipa_http_req(void *http_ctx, const struct ipa_buf *req, const char *url)
{
	assert(0 && "the transport must not be reached");
	return NULL;
}

struct ipa_buf *ipa_http_req_with_ct(void *http_ctx, const struct ipa_buf *req, const char *url,
				     const char *content_type)
{
	assert(0 && "the transport must not be reached");
	return NULL;
}

long ipa_http_last_status(void *http_ctx)
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
