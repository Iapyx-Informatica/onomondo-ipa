/*
 * Copyright (c) 2026 Onomondo ApS & sysmocom - s.f.m.c. GmbH & Iapyx Informatica Ltda. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Tests for the non volatile state serialization in ipad.c.
 *
 * The stored image is a wholesale copy of struct ipa_nvstate followed by the buffers its pointer
 * members refer to.  That means the image also carries the pointer values themselves -- addresses
 * belonging to the process that wrote the file, meaningless to the process that reads it.  Every
 * check here exists because of that: the deserializer has to reach a state where those slots hold
 * either freshly allocated buffers or NULL, and it must never hand one of the stored addresses to
 * free().
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <assert.h>
#include <onomondo/ipa/utils.h>
#include <onomondo/ipa/ipad.h>
#include <onomondo/ipa/http.h>
#include <onomondo/ipa/scard.h>
#include "src/ipa/libipa/context.h"

/* A value that is not a heap address this process owns.  Freeing it aborts or segfaults, which is
 * exactly the failure being guarded against. */
#define POISON ((struct ipa_buf *)(uintptr_t)0xdeadbeefUL)

static struct ipa_config cfg;

/* Build a stored image by hand: sizeof(struct ipa_nvstate) bytes, laid out as nvstate_serialize()
 * would lay them out, with the pointer slots poisoned the way a real file's are stale. */
static struct ipa_buf *stored_image(uint32_t version)
{
	struct ipa_nvstate ns;
	struct ipa_buf *img;

	memset(&ns, 0, sizeof(ns));
	ns.version = version;
	ns.iot_euicc_emu.eim_cfg_ber = POISON;
	ns.iot_euicc_emu.immediate_enable.smdp_oid = POISON;
	ns.iot_euicc_emu.immediate_enable.smdp_address = POISON;

	img = ipa_buf_alloc(sizeof(ns));
	assert(img);
	memcpy(img->data, &ns, sizeof(ns));
	img->len = sizeof(ns);
	return img;
}

static void assert_fresh(const struct ipa_context *ctx)
{
	assert(ctx->nvstate.version == IPA_NVSTATE_VERSION);
	assert(ctx->nvstate.state_change_cause == IPA_STATE_CHANGE_NONE);
	assert(ctx->nvstate.iot_euicc_emu.eim_cfg_ber == NULL);
	assert(ctx->nvstate.iot_euicc_emu.immediate_enable.smdp_oid == NULL);
	assert(ctx->nvstate.iot_euicc_emu.immediate_enable.smdp_address == NULL);
	assert(ctx->nvstate.iot_euicc_emu.association_token_counter == 0);
}

/* An image from a build with a different IPA_NVSTATE_VERSION must be rejected and replaced by fresh
 * state.  Rejecting it after copying it in would leave the stored addresses in the struct for the
 * reset to free; this is the regression that motivated the check to move ahead of the copy. */
static void version_mismatch_test(void)
{
	struct ipa_buf *img;
	struct ipa_context *ctx;

	printf("== version_mismatch_test ==\n");

	img = stored_image(IPA_NVSTATE_VERSION - 1);
	ctx = ipa_new_ctx(&cfg, img);
	assert(ctx);
	assert_fresh(ctx);
	printf("   older version                    -> reset to version %u, no stored pointer freed\n",
	       ctx->nvstate.version);
	ipa_buf_free(ipa_free_ctx(ctx));
	ipa_buf_free(img);

	/* A newer image is just as unusable, and reaches the same path. */
	img = stored_image(IPA_NVSTATE_VERSION + 1);
	ctx = ipa_new_ctx(&cfg, img);
	assert(ctx);
	assert_fresh(ctx);
	printf("   newer version                    -> reset, likewise\n");
	ipa_buf_free(ipa_free_ctx(ctx));
	ipa_buf_free(img);
}

/* No image at all, and an image too short to hold the current struct.  Both predate the version
 * check and are covered so that moving it did not disturb them. */
static void degenerate_image_test(void)
{
	struct ipa_buf *img;
	struct ipa_context *ctx;

	printf("== degenerate_image_test ==\n");

	ctx = ipa_new_ctx(&cfg, NULL);
	assert(ctx);
	assert_fresh(ctx);
	printf("   no image                         -> fresh state\n");
	ipa_buf_free(ipa_free_ctx(ctx));

	/* Shorter than the struct: written by a build whose struct had fewer static members.  The
	 * version cannot be trusted to be present, so the length is what rejects it. */
	img = stored_image(IPA_NVSTATE_VERSION);
	img->len = sizeof(struct ipa_nvstate) - 1;
	ctx = ipa_new_ctx(&cfg, img);
	assert(ctx);
	assert_fresh(ctx);
	printf("   image shorter than the struct    -> fresh state\n");
	ipa_buf_free(ipa_free_ctx(ctx));
	ipa_buf_free(img);
}

/* The path that must keep working: a matching version round-trips every member, static and dynamic.
 * Serialization is only reachable through ipa_free_ctx(), so the context is built, populated, torn
 * down, and read back. */
static void round_trip_test(void)
{
	static const uint8_t oid[] = { 0x06, 0x03, 0x2a, 0x03, 0x04 };
	static const uint8_t addr[] = "smdp.example.org";
	static const uint8_t ber[] = { 0xbf, 0x37, 0x03, 0x80, 0x01, 0x2a };
	static const uint8_t iccid[IPA_LEN_ICCID] = { 0x98, 0x76, 0x54, 0x32, 0x10,
						      0x01, 0x02, 0x03, 0x04, 0x05 };
	struct ipa_context *ctx;
	struct ipa_buf *img;

	printf("== round_trip_test ==\n");

	ctx = ipa_new_ctx(&cfg, NULL);
	assert(ctx);
	ctx->nvstate.iot_euicc_emu.association_token_counter = 7;
	ctx->nvstate.state_change_cause = IPA_STATE_CHANGE_FALLBACK;
	ctx->nvstate.iot_euicc_emu.immediate_enable.flag = true;
	memcpy(ctx->nvstate.iot_euicc_emu.fallback_iccid, iccid, IPA_LEN_ICCID);
	ctx->nvstate.iot_euicc_emu.eim_cfg_ber = ipa_buf_alloc_data(sizeof(ber), (uint8_t *)ber);
	ctx->nvstate.iot_euicc_emu.immediate_enable.smdp_oid = ipa_buf_alloc_data(sizeof(oid), (uint8_t *)oid);
	ctx->nvstate.iot_euicc_emu.immediate_enable.smdp_address = ipa_buf_alloc_data(sizeof(addr), (uint8_t *)addr);

	img = ipa_free_ctx(ctx);
	assert(img);
	assert(img->len > sizeof(struct ipa_nvstate));

	ctx = ipa_new_ctx(&cfg, img);
	assert(ctx);
	assert(ctx->nvstate.version == IPA_NVSTATE_VERSION);
	assert(ctx->nvstate.iot_euicc_emu.association_token_counter == 7);
	assert(ctx->nvstate.state_change_cause == IPA_STATE_CHANGE_FALLBACK);
	assert(ctx->nvstate.iot_euicc_emu.immediate_enable.flag == true);
	assert(memcmp(ctx->nvstate.iot_euicc_emu.fallback_iccid, iccid, IPA_LEN_ICCID) == 0);
	printf("   static members                   -> restored\n");

	/* Restored, and restored into memory this process owns rather than the addresses in the image. */
	assert(ctx->nvstate.iot_euicc_emu.eim_cfg_ber);
	assert(ctx->nvstate.iot_euicc_emu.eim_cfg_ber->len == sizeof(ber));
	assert(memcmp(ctx->nvstate.iot_euicc_emu.eim_cfg_ber->data, ber, sizeof(ber)) == 0);
	assert(ctx->nvstate.iot_euicc_emu.immediate_enable.smdp_oid);
	assert(ctx->nvstate.iot_euicc_emu.immediate_enable.smdp_oid->len == sizeof(oid));
	assert(memcmp(ctx->nvstate.iot_euicc_emu.immediate_enable.smdp_oid->data, oid, sizeof(oid)) == 0);
	assert(ctx->nvstate.iot_euicc_emu.immediate_enable.smdp_address);
	assert(ctx->nvstate.iot_euicc_emu.immediate_enable.smdp_address->len == sizeof(addr));
	assert(memcmp(ctx->nvstate.iot_euicc_emu.immediate_enable.smdp_address->data, addr, sizeof(addr)) == 0);
	printf("   dynamic members                  -> restored byte for byte\n");

	ipa_buf_free(ipa_free_ctx(ctx));
	ipa_buf_free(img);
}

/* A state whose dynamic members were never set serializes as three empty placeholders and must come
 * back as three NULLs, not as three empty buffers. */
static void absent_dynamic_members_test(void)
{
	struct ipa_context *ctx;
	struct ipa_buf *img;

	printf("== absent_dynamic_members_test ==\n");

	ctx = ipa_new_ctx(&cfg, NULL);
	assert(ctx);
	ctx->nvstate.iot_euicc_emu.association_token_counter = 3;
	img = ipa_free_ctx(ctx);
	assert(img);

	ctx = ipa_new_ctx(&cfg, img);
	assert(ctx);
	assert(ctx->nvstate.iot_euicc_emu.association_token_counter == 3);
	assert(ctx->nvstate.iot_euicc_emu.eim_cfg_ber == NULL);
	assert(ctx->nvstate.iot_euicc_emu.immediate_enable.smdp_oid == NULL);
	assert(ctx->nvstate.iot_euicc_emu.immediate_enable.smdp_address == NULL);
	printf("   unset dynamic members            -> NULL, not empty buffers\n");

	ipa_buf_free(ipa_free_ctx(ctx));
	ipa_buf_free(img);
}

/* Append a serialized ipa_buf header to an image, with the length fields set to whatever the caller
 * wants to claim -- including claims the image cannot back up.  This is what a truncated or corrupted
 * nvstate.bin looks like from the deserializer's side. */
static struct ipa_buf *append_hdr(struct ipa_buf *img, size_t data_len, size_t len, const void *payload,
				  size_t payload_len)
{
	struct ipa_buf hdr;
	size_t off = img->len;

	memset(&hdr, 0, sizeof(hdr));
	hdr.data = (uint8_t *)(uintptr_t)0xabadcafeUL;	/* as stale as a real one */
	hdr.data_len = data_len;
	hdr.len = len;

	img = ipa_buf_realloc(img, off + sizeof(hdr) + payload_len);
	memcpy(img->data + off, &hdr, sizeof(hdr));
	if (payload_len)
		memcpy(img->data + off + sizeof(hdr), payload, payload_len);
	img->len = off + sizeof(hdr) + payload_len;
	return img;
}

/* An image whose header survives but whose data section does not.  Before ipa_buf_deserialize()
 * honoured its len argument, the claimed data_len drove both the allocation and the copy, so the
 * copy ran off the end of the image -- a heap overread on data taken straight from a file. */
static void malformed_image_test(void)
{
	struct ipa_buf *img;
	struct ipa_context *ctx;

	printf("== malformed_image_test ==\n");

	/* Correct version, but the dynamic section is missing entirely. */
	img = stored_image(IPA_NVSTATE_VERSION);
	ctx = ipa_new_ctx(&cfg, img);
	assert(ctx);
	assert_fresh(ctx);
	printf("   dynamic section absent           -> reset, no read past the image\n");
	ipa_buf_free(ipa_free_ctx(ctx));
	ipa_buf_free(img);

	/* A header that claims more payload than the image holds. */
	img = stored_image(IPA_NVSTATE_VERSION);
	img = append_hdr(img, 4096, 4096, NULL, 0);
	ctx = ipa_new_ctx(&cfg, img);
	assert(ctx);
	assert_fresh(ctx);
	printf("   data_len beyond the image        -> reset, no read past the image\n");
	ipa_buf_free(ipa_free_ctx(ctx));
	ipa_buf_free(img);

	/* A header cut in half. */
	img = stored_image(IPA_NVSTATE_VERSION);
	img = append_hdr(img, 0, 0, NULL, 0);
	img->len -= 1;
	ctx = ipa_new_ctx(&cfg, img);
	assert(ctx);
	assert_fresh(ctx);
	printf("   truncated header                 -> reset\n");
	ipa_buf_free(ipa_free_ctx(ctx));
	ipa_buf_free(img);

	/* Useful length larger than the allocation that is supposed to hold it.  Accepting this would
	 * hand every later reader an ipa_buf whose len runs past its own data. */
	img = stored_image(IPA_NVSTATE_VERSION);
	img = append_hdr(img, 4, 64, "abcd", 4);
	ctx = ipa_new_ctx(&cfg, img);
	assert(ctx);
	assert_fresh(ctx);
	printf("   len larger than data_len         -> reset\n");
	ipa_buf_free(ipa_free_ctx(ctx));
	ipa_buf_free(img);

	/* One good member followed by a broken one: the good member must not be kept, because a state
	 * loaded from an image that stopped making sense partway is not the state that was saved. */
	img = stored_image(IPA_NVSTATE_VERSION);
	img = append_hdr(img, 4, 4, "abcd", 4);
	img = append_hdr(img, 4096, 4096, NULL, 0);
	ctx = ipa_new_ctx(&cfg, img);
	assert(ctx);
	assert_fresh(ctx);
	printf("   good member then broken one      -> whole state reset\n");
	ipa_buf_free(ipa_free_ctx(ctx));
	ipa_buf_free(img);
}

/* ipa_buf_deserialize() is public, so its contract is checked directly too. */
static void buf_deserialize_test(void)
{
	struct ipa_buf hdr;
	uint8_t img[sizeof(struct ipa_buf) + 4];
	struct ipa_buf *buf;

	printf("== buf_deserialize_test ==\n");

	memset(&hdr, 0, sizeof(hdr));
	hdr.data = (uint8_t *)(uintptr_t)0xabadcafeUL;
	hdr.data_len = 4;
	hdr.len = 4;
	memcpy(img, &hdr, sizeof(hdr));
	memcpy(img + sizeof(hdr), "wxyz", 4);

	buf = ipa_buf_deserialize(img, sizeof(img));
	assert(buf);
	assert(buf->data_len == 4 && buf->len == 4);
	assert(memcmp(buf->data, "wxyz", 4) == 0);
	/* Restored into memory this process owns, not the address the header carried. */
	assert(buf->data != (uint8_t *)(uintptr_t)0xabadcafeUL);
	ipa_buf_free(buf);
	printf("   well formed                      -> restored, own storage\n");

	assert(ipa_buf_deserialize(NULL, sizeof(img)) == NULL);
	assert(ipa_buf_deserialize(img, 0) == NULL);
	assert(ipa_buf_deserialize(img, sizeof(hdr) - 1) == NULL);
	printf("   no header                        -> NULL\n");

	/* Exactly the header, with the data section it promises absent. */
	assert(ipa_buf_deserialize(img, sizeof(hdr)) == NULL);
	/* One byte short of the promised data section. */
	assert(ipa_buf_deserialize(img, sizeof(img) - 1) == NULL);
	printf("   data section short               -> NULL\n");

	/* A zero-length member is legitimate: that is how an unset member is stored. */
	memset(&hdr, 0, sizeof(hdr));
	memcpy(img, &hdr, sizeof(hdr));
	buf = ipa_buf_deserialize(img, sizeof(hdr));
	assert(buf);
	assert(buf->data_len == 0 && buf->len == 0);
	ipa_buf_free(buf);
	printf("   empty member                     -> accepted\n");
}

/* The transport is irrelevant here -- no context in this file ever opens one -- but ipa_free_ctx()
 * references both, so they have to resolve.  Same approach as euicc_emu_test.c. */
void ipa_http_free(void *http_ctx) { (void)http_ctx; }
int ipa_scard_free(void *scard_ctx) { (void)scard_ctx; return 0; }
int ipa_scard_transceive(void *scard_ctx, struct ipa_buf *res, const struct ipa_buf *req)
{
	(void)scard_ctx; (void)res; (void)req;
	assert(0 && "no eUICC exchange expected in the nvstate tests");
	return -1;
}

int main(void)
{
	memset(&cfg, 0, sizeof(cfg));

	version_mismatch_test();
	degenerate_image_test();
	round_trip_test();
	absent_dynamic_members_test();
	malformed_image_test();
	buf_deserialize_test();

	printf("\nAll nvstate tests passed.\n");
	return 0;
}
