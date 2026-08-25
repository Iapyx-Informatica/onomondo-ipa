/*
 * Copyright (c) 2026 Onomondo ApS & sysmocom - s.f.m.c. GmbH & Iapyx Informatica Ltda. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * The hand-rolled EimPackageResult DER builder (GSMA SGP.32, section 6.3.2.7).  It exists so that the
 * EuiccPackageResult bytes the eUICC produced travel to the eIM untouched: a BER->DER round trip would
 * change euiccPackageResultDataSigned and euiccSignEPR would no longer verify.  That is why the TLV is
 * assembled by hand rather than by the asn1c encoder, and it is what these checks pin down.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <stdbool.h>
#include <onomondo/ipa/utils.h>
#include <SGP32-RetrieveNotificationsListResponse.h>
#include <SGP32-PendingNotificationList.h>
#include "src/ipa/libipa/esipa_prvde_eim_pkg_rslt.h"

/* ------------------------------------------------------------------ */
/* Helpers                                                            */
/* ------------------------------------------------------------------ */

/* Stand-in for the raw ES10b.LoadEuiccPackage response: the BF 51 tag the euiccPackageResult CHOICE arm
 * is recognised by, a length, and `payload_len` bytes of filler.  The filler is never parsed; what the
 * checks below care about is that it comes back byte for byte. */
static struct ipa_buf *raw_epr(size_t payload_len)
{
	struct ipa_buf *buf;
	size_t hdr, i;
	uint8_t lenbuf[5];
	size_t lenlen = 0;

	/* Length of the filler, long form where it does not fit in 7 bits.  Written out here rather than
	 * reusing the encoder under test, so that a bug in that one cannot cancel itself out. */
	if (payload_len < 0x80) {
		lenbuf[lenlen++] = (uint8_t)payload_len;
	} else if (payload_len < 0x100) {
		lenbuf[lenlen++] = 0x81;
		lenbuf[lenlen++] = (uint8_t)payload_len;
	} else if (payload_len < 0x10000) {
		lenbuf[lenlen++] = 0x82;
		lenbuf[lenlen++] = (uint8_t)(payload_len >> 8);
		lenbuf[lenlen++] = (uint8_t)payload_len;
	} else {
		lenbuf[lenlen++] = 0x83;
		lenbuf[lenlen++] = (uint8_t)(payload_len >> 16);
		lenbuf[lenlen++] = (uint8_t)(payload_len >> 8);
		lenbuf[lenlen++] = (uint8_t)payload_len;
	}

	hdr = 2 + lenlen;
	buf = ipa_buf_alloc(hdr + payload_len);
	assert(buf);
	buf->data[0] = 0xBF;
	buf->data[1] = 0x51;
	memcpy(buf->data + 2, lenbuf, lenlen);
	for (i = 0; i < payload_len; i++)
		buf->data[hdr + i] = (uint8_t)(i * 7 + 1);
	buf->len = hdr + payload_len;
	return buf;
}

/* Read a DER tag+length header at `p`.  An independent reimplementation of the length parser: the point
 * is to check what the builder wrote, not to agree with it by construction. */
static size_t tlv_hdr(const uint8_t *p, size_t avail, size_t *value_len)
{
	size_t off = 1;		/* single-byte tags only; that is all this builder emits at the top */
	size_t n, i, len = 0;

	assert(avail >= 2);
	if (p[off] < 0x80) {
		len = p[off];
		off += 1;
	} else {
		n = p[off] & 0x7f;
		assert(n >= 1 && n <= 4);
		assert(avail >= off + 1 + n);
		off += 1;
		for (i = 0; i < n; i++)
			len = (len << 8) | p[off + i];
		off += n;
	}
	*value_len = len;
	return off;
}

/* One SGP32-PendingNotification that really encodes: CompactOtherSignedNotification is the cheapest arm
 * to fill in completely. */
static struct SGP32_PendingNotification *encodable_notification(void)
{
	struct SGP32_PendingNotification *n = calloc(1, sizeof(*n));
	struct CompactOtherSignedNotification *c;
	static const uint8_t sig[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
	static const uint8_t event[1] = { 0x40 };	/* one bit set, as NotificationEvent requires */

	assert(n);
	n->present = SGP32_PendingNotification_PR_compactOtherSignedNotification;
	c = &n->choice.compactOtherSignedNotification;
	c->tbsOtherNotification.seqNumber = 42;
	/* NotificationEvent is a BIT STRING, so it is filled in by hand rather than through
	 * OCTET_STRING_fromBuf(): bits_unused has to be set alongside the buffer. */
	c->tbsOtherNotification.profileManagementOperation.buf = malloc(sizeof(event));
	assert(c->tbsOtherNotification.profileManagementOperation.buf);
	memcpy(c->tbsOtherNotification.profileManagementOperation.buf, event, sizeof(event));
	c->tbsOtherNotification.profileManagementOperation.size = sizeof(event);
	c->tbsOtherNotification.profileManagementOperation.bits_unused = 6;
	assert(OCTET_STRING_fromBuf(&c->tbsOtherNotification.notificationAddress, "eim.example.org", 15) == 0);
	assert(OCTET_STRING_fromBuf(&c->euiccNotificationSignature, (const char *)sig, sizeof(sig)) == 0);
	return n;
}

static struct SGP32_RetrieveNotificationsListResponse *notif_list(int count)
{
	struct SGP32_RetrieveNotificationsListResponse *lst = calloc(1, sizeof(*lst));
	int i;

	assert(lst);
	lst->present = SGP32_RetrieveNotificationsListResponse_PR_notificationList;
	for (i = 0; i < count; i++)
		ASN_SEQUENCE_ADD(&lst->choice.notificationList.list, encodable_notification());
	return lst;
}

/* ------------------------------------------------------------------ */
/* Checks                                                             */
/* ------------------------------------------------------------------ */

/* Without notifications the raw bytes are the whole answer: they already carry the BF 51 tag that names
 * the euiccPackageResult arm of the EimPackageResult CHOICE. */
static void euicc_pkg_result_arm_test(void)
{
	struct ipa_buf *raw = raw_epr(64);
	struct SGP32_RetrieveNotificationsListResponse other = { 0 };
	struct ipa_buf *out;

	printf("== euicc_pkg_result_arm_test ==\n");

	out = ipa_esipa_build_eim_pkg_result_der(raw, NULL);
	assert(out);
	assert(out->len == raw->len);
	assert(memcmp(out->data, raw->data, raw->len) == 0);
	IPA_FREE(out);
	printf("   no notification list             -> raw bytes verbatim\n");

	/* The other arms of RetrieveNotificationsListResponse never travel with a package result. */
	other.present = SGP32_RetrieveNotificationsListResponse_PR_notificationsListResultError;
	out = ipa_esipa_build_eim_pkg_result_der(raw, &other);
	assert(out);
	assert(out->len == raw->len && memcmp(out->data, raw->data, raw->len) == 0);
	IPA_FREE(out);

	other.present = SGP32_RetrieveNotificationsListResponse_PR_euiccPackageResultList;
	out = ipa_esipa_build_eim_pkg_result_der(raw, &other);
	assert(out);
	assert(out->len == raw->len && memcmp(out->data, raw->data, raw->len) == 0);
	IPA_FREE(out);
	printf("   non-notificationList arms        -> raw bytes verbatim\n");

	IPA_FREE(raw);
}

/* With notifications: 30 <len> <raw BF51 bytes> A0 <len> <notifications>.  The [0] IMPLICIT re-tag is
 * done by overwriting the encoder's 0x30 with 0xA0, so what sits under that byte has to still be the
 * SEQUENCE OF the encoder produced. */
static void notifications_arm_test(void)
{
	struct ipa_buf *raw = raw_epr(40);
	struct SGP32_RetrieveNotificationsListResponse *lst = notif_list(2);
	struct SGP32_PendingNotificationList *decoded = NULL;
	struct ipa_buf *out;
	size_t hdr, body_len, notif_off, notif_hdr, notif_len;
	uint8_t *reconstructed;
	asn_dec_rval_t rc;

	printf("== notifications_arm_test ==\n");

	out = ipa_esipa_build_eim_pkg_result_der(raw, lst);
	assert(out);

	assert(out->data[0] == 0x30);
	hdr = tlv_hdr(out->data, out->len, &body_len);
	assert(hdr + body_len == out->len);
	printf("   outer SEQUENCE length            -> matches the bytes that follow\n");

	/* The whole reason this builder exists. */
	assert(memcmp(out->data + hdr, raw->data, raw->len) == 0);
	printf("   EuiccPackageResult               -> embedded byte for byte\n");

	notif_off = hdr + raw->len;
	assert(out->data[notif_off] == 0xA0);
	notif_hdr = tlv_hdr(out->data + notif_off, out->len - notif_off, &notif_len);
	assert(notif_off + notif_hdr + notif_len == out->len);
	printf("   notificationList                 -> re-tagged [0] IMPLICIT, length intact\n");

	/* Put the UNIVERSAL SEQUENCE tag back and the value has to decode as the list that went in, which
	 * is what proves the re-tag only touched the tag. */
	reconstructed = malloc(notif_hdr + notif_len);
	assert(reconstructed);
	memcpy(reconstructed, out->data + notif_off, notif_hdr + notif_len);
	reconstructed[0] = 0x30;
	rc = ber_decode(0, &asn_DEF_SGP32_PendingNotificationList, (void **)&decoded,
			reconstructed, notif_hdr + notif_len);
	assert(rc.code == RC_OK);
	assert(rc.consumed == notif_hdr + notif_len);
	assert(decoded->list.count == 2);
	printf("   notificationList value           -> decodes back to 2 notifications\n");

	ASN_STRUCT_FREE(asn_DEF_SGP32_PendingNotificationList, decoded);
	free(reconstructed);
	IPA_FREE(out);
	ASN_STRUCT_FREE(asn_DEF_SGP32_RetrieveNotificationsListResponse, lst);
	IPA_FREE(raw);
}

/* The invariant the old assert(off == total_len) stood for: the header der_length_size() sized and the
 * one der_write_length() wrote have to be the same size, at every boundary between the two.  Sizes are
 * chosen so the SEQUENCE body lands on either side of the 1, 2, 3 and 4-byte length forms. */
static void length_boundary_test(void)
{
	static const size_t payloads[] = {
		1, 0x40, 0x70, 0x7a, 0x7b, 0x7c, 0x80, 0xf0, 0xfa, 0xfb, 0xfc,
		0x100, 0xfff0, 0xfffa, 0xfffb, 0xfffc, 0x10000, 0x20000
	};
	size_t i;

	printf("== length_boundary_test ==\n");

	for (i = 0; i < sizeof(payloads) / sizeof(payloads[0]); i++) {
		struct ipa_buf *raw = raw_epr(payloads[i]);
		struct SGP32_RetrieveNotificationsListResponse *lst = notif_list(1);
		struct ipa_buf *out = ipa_esipa_build_eim_pkg_result_der(raw, lst);
		size_t hdr, body_len;

		assert(out);
		hdr = tlv_hdr(out->data, out->len, &body_len);
		/* Declared length describes exactly the bytes present, and the raw result still starts
		 * right after the header rather than being shifted by a mis-sized one. */
		assert(hdr + body_len == out->len);
		assert(memcmp(out->data + hdr, raw->data, raw->len) == 0);
		assert(out->data[hdr + raw->len] == 0xA0);

		IPA_FREE(out);
		ASN_STRUCT_FREE(asn_DEF_SGP32_RetrieveNotificationsListResponse, lst);
		IPA_FREE(raw);
	}
	printf("   %zu payload sizes across the 1/2/3/4-byte length forms -> header sizes body exactly\n",
	       sizeof(payloads) / sizeof(payloads[0]));
}

/* A notification list the encoder refuses.  Dropping the notifications is the deliberate choice here:
 * they stay pending and are retried, whereas a EuiccPackageResult that never leaves is lost, the eUICC
 * having already retired the eUICC Package. */
static void unencodable_notifications_test(void)
{
	struct ipa_buf *raw = raw_epr(32);
	struct SGP32_RetrieveNotificationsListResponse *lst = calloc(1, sizeof(*lst));
	struct SGP32_PendingNotification *empty = calloc(1, sizeof(*empty));
	struct ipa_buf *out;

	printf("== unencodable_notifications_test ==\n");

	assert(lst && empty);
	lst->present = SGP32_RetrieveNotificationsListResponse_PR_notificationList;
	empty->present = SGP32_PendingNotification_PR_NOTHING;
	ASN_SEQUENCE_ADD(&lst->choice.notificationList.list, empty);

	out = ipa_esipa_build_eim_pkg_result_der(raw, lst);
	assert(out);
	assert(out->len == raw->len);
	assert(memcmp(out->data, raw->data, raw->len) == 0);
	printf("   notification list will not encode -> EuiccPackageResult still delivered, alone\n");

	IPA_FREE(out);
	ASN_STRUCT_FREE(asn_DEF_SGP32_RetrieveNotificationsListResponse, lst);

	/* A list where only the second member is unencodable.  asn1c sizes the whole SEQUENCE OF before
	 * writing any of it, so the good member never reaches the callback either and the buffer comes
	 * back empty; the list is dropped whole rather than shipped short. */
	lst = notif_list(1);
	empty = calloc(1, sizeof(*empty));
	assert(empty);
	empty->present = SGP32_PendingNotification_PR_NOTHING;
	ASN_SEQUENCE_ADD(&lst->choice.notificationList.list, empty);

	out = ipa_esipa_build_eim_pkg_result_der(raw, lst);
	assert(out);
	assert(out->len == raw->len);
	assert(memcmp(out->data, raw->data, raw->len) == 0);
	printf("   one bad member                   -> whole list dropped, none of it shipped\n");

	IPA_FREE(out);
	ASN_STRUCT_FREE(asn_DEF_SGP32_RetrieveNotificationsListResponse, lst);
	IPA_FREE(raw);
}

/* Without EuiccPackageResult bytes there is no message to build, and no arm of the CHOICE to guess at. */
static void degenerate_input_test(void)
{
	struct ipa_buf *empty = ipa_buf_alloc(16);

	printf("== degenerate_input_test ==\n");

	assert(empty);
	empty->len = 0;

	assert(ipa_esipa_build_eim_pkg_result_der(NULL, NULL) == NULL);
	assert(ipa_esipa_build_eim_pkg_result_der(empty, NULL) == NULL);
	printf("   no raw EuiccPackageResult        -> NULL\n");

	IPA_FREE(empty);
}

int main(int argc, char **argv)
{
	(void)argc;
	(void)argv;

	euicc_pkg_result_arm_test();
	notifications_arm_test();
	length_boundary_test();
	unencodable_notifications_test();
	degenerate_input_test();
	printf("eim_pkg_result_der_test: all checks passed\n");
	return 0;
}

/* Stubs: this test never reaches the eUICC or the eIM. */
void *ipa_http_init(const char *cabundle, bool no_verif) { (void)cabundle; (void)no_verif; return NULL; }
struct ipa_buf *ipa_http_req(void *c, const struct ipa_buf *r, const char *u) { (void)c; (void)r; (void)u; return NULL; }
struct ipa_buf *ipa_http_req_with_ct(void *c, const struct ipa_buf *r, const char *u, const char *t) { (void)c; (void)r; (void)u; (void)t; return NULL; }
void ipa_http_close(void *c) { (void)c; }
void ipa_http_free(void *c) { (void)c; }
void *ipa_scard_init(unsigned int n) { (void)n; return NULL; }
int ipa_scard_reset(void *c) { (void)c; return 0; }
int ipa_scard_atr(void *c, struct ipa_buf *a) { (void)c; (void)a; return 0; }
int ipa_scard_transceive(void *c, struct ipa_buf *res, const struct ipa_buf *req) { (void)c; (void)res; (void)req; return 0; }
int ipa_scard_free(void *c) { (void)c; return 0; }
