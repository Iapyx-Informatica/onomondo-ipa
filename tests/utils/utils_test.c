/*
 * Copyright (c) 2025 Onomondo ApS & sysmocom - s.f.m.c. GmbH. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Author: Philipp Maier <pmaier@sysmocom.de> / sysmocom - s.f.m.c. GmbH
 */

#include <stdio.h>
#include <stdbool.h>
#include <onomondo/ipa/utils.h>
#include "src/ipa/libipa/utils.h"

void ipa_tag_in_taglist_test(void)
{
	uint8_t _tag_list[] = { 0x80, 0xBF, 0x20, 0xBF, 0x22, 0x83, 0x84, 0xA5, 0xA6, 0x88, 0xA9, 0xBF, 0x2B };
	struct ipa_buf *tag_list;
	bool rc;

	tag_list = ipa_buf_alloc_data(sizeof(_tag_list), _tag_list);

	rc = ipa_tag_in_taglist(0x80, tag_list);
	assert(rc == true);
	rc = ipa_tag_in_taglist(0xBF20, tag_list);
	assert(rc == true);
	rc = ipa_tag_in_taglist(0xBF2B, tag_list);
	assert(rc == true);
	rc = ipa_tag_in_taglist(0xA5, tag_list);
	assert(rc == true);
	rc = ipa_tag_in_taglist(0x22, tag_list);
	assert(rc == false);
	rc = ipa_tag_in_taglist(0xBF, tag_list);
	assert(rc == false);
	rc = ipa_tag_in_taglist(0x2B, tag_list);
	assert(rc == false);
	rc = ipa_tag_in_taglist(0xA3, tag_list);
	assert(rc == false);
	rc = ipa_tag_in_taglist(0x81, tag_list);
	assert(rc == false);
	rc = ipa_tag_in_taglist(0xFF, tag_list);
	assert(rc == false);
	rc = ipa_tag_in_taglist(0x00, tag_list);
	assert(rc == false);
	rc = ipa_tag_in_taglist(0xBF23, tag_list);
	assert(rc == false);
	rc = ipa_tag_in_taglist(0xBF00, tag_list);
	assert(rc == false);
	rc = ipa_tag_in_taglist(0xBFFF, tag_list);
	assert(rc == false);

	IPA_FREE(tag_list);
}

void ipa_parse_btlv_hdr_test(void)
{
	size_t len;
	uint16_t tag;
	size_t hdr;

	/* Regression: a short-form length octet of 0x7f (127) must be parsed as a
	 * valid short-form length, not mistaken for a long-form indicator.  The old
	 * `*data < 0x7f` test rejected exactly this value. */
	{
		uint8_t d[] = { 0x80, 0x7f };
		struct ipa_buf *b = ipa_buf_alloc_data(sizeof(d), d);
		hdr = ipa_parse_btlv_hdr(&len, &tag, b);
		assert(hdr == 2);
		assert(tag == 0x80);
		assert(len == 127);
		IPA_FREE(b);
	}

	/* Short-form boundary just below (126). */
	{
		uint8_t d[] = { 0x80, 0x7e };
		struct ipa_buf *b = ipa_buf_alloc_data(sizeof(d), d);
		hdr = ipa_parse_btlv_hdr(&len, &tag, b);
		assert(hdr == 2 && len == 126);
		IPA_FREE(b);
	}

	/* Long-form: 0x81 0x80 encodes length 128 in one extra octet. */
	{
		uint8_t d[] = { 0x80, 0x81, 0x80 };
		struct ipa_buf *b = ipa_buf_alloc_data(sizeof(d), d);
		hdr = ipa_parse_btlv_hdr(&len, &tag, b);
		assert(hdr == 3 && len == 128);
		IPA_FREE(b);
	}

	/* Two-byte tag (0xBF2B) with a short-form length. */
	{
		uint8_t d[] = { 0xBF, 0x2B, 0x05 };
		struct ipa_buf *b = ipa_buf_alloc_data(sizeof(d), d);
		hdr = ipa_parse_btlv_hdr(&len, &tag, b);
		assert(hdr == 3 && tag == 0xBF2B && len == 5);
		IPA_FREE(b);
	}
}

void ipa_strip_tlv_envelope_test(void)
{
	/* Matching envelope: the 2-byte header is chopped, value remains. */
	{
		uint8_t d[] = { 0x88, 0x02, 0xAA, 0xBB };
		int n = ipa_strip_tlv_envelope(d, sizeof(d), 0x88);
		assert(n == 2);
		assert(d[0] == 0xAA && d[1] == 0xBB);
	}

	/* Tag mismatch: buffer is left untouched. */
	{
		uint8_t d[] = { 0x87, 0x02, 0xAA, 0xBB };
		int n = ipa_strip_tlv_envelope(d, sizeof(d), 0x88);
		assert(n == (int)sizeof(d));
	}

	/* Finding #5: an invalid/truncated header (2-byte tag indicated but only
	 * one byte present) makes parse_btlv_hdr return a negative error.  The
	 * caller must detect that (the previously-dead `chop_bytes < 0` check) and
	 * leave the buffer untouched rather than reading an uninitialised tag. */
	{
		uint8_t d[] = { 0xBF };
		int n = ipa_strip_tlv_envelope(d, sizeof(d), 0x88);
		assert(n == 1);
	}
}

int main(int argc, char **argv)
{
	ipa_tag_in_taglist_test();
	ipa_parse_btlv_hdr_test();
	ipa_strip_tlv_envelope_test();
	return 0;
}

/* Stubs */
void *ipa_http_init(const char *cabundle, bool no_verif)
{
	return NULL;
}

struct ipa_buf *ipa_http_req(void *http_ctx, const struct ipa_buf *req, const char *url)
{
	return NULL;
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
