/*
 * Copyright (c) 2025 Onomondo ApS & sysmocom - s.f.m.c. GmbH. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Author: Philipp Maier <pmaier@sysmocom.de> / sysmocom - s.f.m.c. GmbH
 */

#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <onomondo/ipa/log.h>
#include <asn_application.h>
#include "utils.h"
#include "es10x.h"
#include "bpp_segments.h"

/* See also GSMA SGP.22, section  2.5.5 (bullet point 1) */
static struct ipa_buf *enc_init_sec_chan_req(const struct BoundProfilePackage *bpp,
					     const struct InitialiseSecureChannelRequest *init_sec_chan_req)
{
	struct ipa_buf *init_sec_chan_req_encoded = NULL;
	asn_enc_rval_t rc;

	/* "Tag and length fields of the BoundProfilePackage TLV..." */
	rc = der_encode(&asn_DEF_BoundProfilePackage, IPA_ASN_PTR_RW(bpp), ipa_asn1c_consume_bytes_cb,
			&init_sec_chan_req_encoded);
	if (rc.encoded <= 0) {
		IPA_LOGP(SIPA, LDEBUG, "cannot re-encode BoundProfilePackage!\n");
		IPA_FREE(init_sec_chan_req_encoded);
		return NULL;
	}

	/* Pinch-off the value part of the TLV */
	init_sec_chan_req_encoded->len = ipa_parse_btlv_hdr(NULL, NULL, init_sec_chan_req_encoded);

	/* "...plus the initialiseSecureChannelRequest TLV */
	rc = der_encode(&asn_DEF_InitialiseSecureChannelRequest, IPA_ASN_PTR_RW(init_sec_chan_req), ipa_asn1c_consume_bytes_cb,
			&init_sec_chan_req_encoded);

	if (rc.encoded <= 0) {
		IPA_LOGP(SIPA, LERROR, "cannot encode segment for InitialiseSecureChannelRequest!\n");
		IPA_FREE(init_sec_chan_req_encoded);
		return NULL;
	}

	IPA_LOGP(SIPA, LDEBUG, "encoded InitialiseSecureChannelRequest segment:\n");
	ipa_buf_hexdump_multiline(init_sec_chan_req_encoded, 32, 1, SIPA, LDEBUG);

	return init_sec_chan_req_encoded;
}

/* Encode a "<SequenceOfNN> header + first '87' TLV" segment (SGP.22 §2.5.5
 * bullet points 2 and 5).  first/second SequenceOf87 differ only in their outer
 * SEQUENCE type descriptor and log label; the inner element is always an '87'
 * TLV.  list_array/list_count come from the caller's typed ->list member. */
static struct ipa_buf *enc_seq_of_87(const struct asn_TYPE_descriptor_s *seq_td, const void *seq_sptr,
				     void *const *list_array, int list_count, const char *label)
{
	struct ipa_buf *enc = NULL;
	asn_enc_rval_t rc;

	/* "Tag and length fields of the <label> TLV" */
	rc = der_encode(IPA_ASN_TD_RW(seq_td), IPA_ASN_PTR_RW(seq_sptr), ipa_asn1c_consume_bytes_cb, &enc);
	if (rc.encoded <= 0) {
		IPA_LOGP(SIPA, LERROR, "cannot encode segment for %s (tlv header)!\n", label);
		IPA_FREE(enc);
		return NULL;
	}

	/* Pinch-off the value part of the TLV */
	enc->len = ipa_parse_btlv_hdr(NULL, NULL, enc);

	/* plus the first '87' TLV */
	if (list_count < 1) {
		IPA_LOGP(SIPA, LERROR, "cannot encode segment for %s (empty sequence)!\n", label);
		IPA_FREE(enc);
		return NULL;
	}
	if (list_count > 1) {
		/* The spec explicitly states "first '87' TLV"! */
		IPA_LOGP(SIPA, LDEBUG, "ignoring excess items in the %s!\n", label);
	}

	rc = der_encode(&asn_DEF_BoundProfilePackage_87tlv, list_array[0], ipa_asn1c_consume_bytes_cb, &enc);
	if (rc.encoded <= 0) {
		IPA_LOGP(SIPA, LERROR, "cannot encode segment for %s (first 87 TLV)!\n", label);
		IPA_FREE(enc);
		return NULL;
	}

	IPA_LOGP(SIPA, LDEBUG, "encoded %s segment:\n", label);
	ipa_buf_hexdump_multiline(enc, 32, 1, SIPA, LDEBUG);

	return enc;
}

/* Encode just the tag and length fields of a SequenceOf88/SequenceOf86 TLV
 * (SGP.22 §2.5.5 bullet points 3 and 6); the value part is pinched off. */
static struct ipa_buf *enc_seq_tag_and_len(const struct asn_TYPE_descriptor_s *seq_td, const void *seq_sptr,
					   const char *label)
{
	struct ipa_buf *enc = NULL;
	asn_enc_rval_t rc;

	rc = der_encode(IPA_ASN_TD_RW(seq_td), IPA_ASN_PTR_RW(seq_sptr), ipa_asn1c_consume_bytes_cb, &enc);
	if (rc.encoded <= 0) {
		IPA_LOGP(SIPA, LERROR, "cannot encode segment for tag and length field of %s!\n", label);
		IPA_FREE(enc);
		return NULL;
	}

	/* Pinch-off the value part as we were only asked for tag and length fields */
	enc->len = ipa_parse_btlv_hdr(NULL, NULL, enc);

	IPA_LOGP(SIPA, LDEBUG, "encoded tag and length field of %s segment: %s\n", label, ipa_buf_hexdump(enc));
	return enc;
}

/* Encode one '88'/'86' TLV element (SGP.22 §2.5.5 bullet points 4 and 7). */
static struct ipa_buf *enc_each_tlv(const struct asn_TYPE_descriptor_s *tlv_td, const void *one_tlv,
				    const char *tlv_label, unsigned int index)
{
	struct ipa_buf *enc = NULL;
	asn_enc_rval_t rc;

	rc = der_encode(IPA_ASN_TD_RW(tlv_td), IPA_ASN_PTR_RW(one_tlv), ipa_asn1c_consume_bytes_cb, &enc);
	if (rc.encoded <= 0) {
		IPA_LOGP(SIPA, LERROR, "cannot encode segment for '%s' TLV %u!\n", tlv_label, index);
		IPA_FREE(enc);
		return NULL;
	}

	IPA_LOGP(SIPA, LDEBUG, "encoded '%s' TLV segment %u:\n", tlv_label, index);
	ipa_buf_hexdump_multiline(enc, 32, 1, SIPA, LDEBUG);

	return enc;
}

struct ipa_bpp_segments *ipa_bpp_segments_encode(const struct BoundProfilePackage *bpp)
{
	unsigned int i;
	struct ipa_bpp_segments *segments = NULL;
	struct ipa_buf *segment = NULL;
	size_t segment_count = 3 + bpp->sequenceOf88.list.count + 2 + bpp->sequenceOf86.list.count;

	segments = IPA_ALLOC_ZERO(struct ipa_bpp_segments);
	segments->segment = IPA_ALLOC_N(sizeof(*segments->segment) * segment_count);
	memset(segments->segment, 0, sizeof(*segments->segment) * segment_count);

	segment = enc_init_sec_chan_req(bpp, &bpp->initialiseSecureChannelRequest);
	if (!segment)
		goto error;
	segments->segment[segments->count] = segment;
	segments->count++;

	segment = enc_seq_of_87(&asn_DEF_BoundProfilePackage_FirstSequenceOf87, &bpp->firstSequenceOf87,
				(void *const *)bpp->firstSequenceOf87.list.array,
				bpp->firstSequenceOf87.list.count, "FirstSequenceOf87");
	if (!segment)
		goto error;
	segments->segment[segments->count] = segment;
	segments->count++;

	segment = enc_seq_tag_and_len(&asn_DEF_BoundProfilePackage_SequenceOf88, &bpp->sequenceOf88, "SequenceOf88");
	if (!segment)
		goto error;
	segments->segment[segments->count] = segment;
	segments->count++;

	for (i = 0; i < bpp->sequenceOf88.list.count; i++) {
		segment = enc_each_tlv(&asn_DEF_BoundProfilePackage_88tlv, bpp->sequenceOf88.list.array[i], "88", i);
		if (!segment)
			goto error;
		segments->segment[segments->count] = segment;
		segments->count++;
	}

	/* Optional */
	if (bpp->secondSequenceOf87) {
		segment = enc_seq_of_87(&asn_DEF_BoundProfilePackage_SecondSequenceOf87, bpp->secondSequenceOf87,
					(void *const *)bpp->secondSequenceOf87->list.array,
					bpp->secondSequenceOf87->list.count, "SecondSequenceOf87");
		if (!segment)
			goto error;
		segments->segment[segments->count] = segment;
		segments->count++;
	}

	segment = enc_seq_tag_and_len(&asn_DEF_BoundProfilePackage_SequenceOf86, &bpp->sequenceOf86, "SequenceOf86");
	if (!segment)
		goto error;
	segments->segment[segments->count] = segment;
	segments->count++;

	for (i = 0; i < bpp->sequenceOf86.list.count; i++) {
		segment = enc_each_tlv(&asn_DEF_BoundProfilePackage_86tlv, bpp->sequenceOf86.list.array[i], "86", i);
		if (!segment)
			goto error;
		segments->segment[segments->count] = segment;
		segments->count++;
	}

	return segments;
error:
	ipa_bpp_segments_free(segments);
	return NULL;
}

void ipa_bpp_segments_free(struct ipa_bpp_segments *segments)
{
	unsigned int i;

	if (!segments)
		return;

	for (i = 0; i < segments->count; i++)
		IPA_FREE(segments->segment[i]);
	IPA_FREE(segments->segment);

	IPA_FREE(segments);
}
