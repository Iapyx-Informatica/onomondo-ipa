/*
 * Copyright (c) 2026 Onomondo ApS & sysmocom - s.f.m.c. GmbH & Iapyx Informatica Ltda. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * See euicc_stub.h.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <onomondo/ipa/utils.h>
#include <asn_application.h>
#include "euicc_stub.h"

/* Mirrors the constants euicc.c sends with; kept local so a change there shows up as a test
 * failure rather than being silently followed. */
#define STORE_DATA_CLA 0x80
#define STORE_DATA_INS 0xE2
#define STORE_DATA_P1_LAST_BLOCK 0x91
#define STORE_DATA_P1_MORE_BLOCKS 0x11
#define GET_RESPONSE_CLA 0x00
#define GET_RESPONSE_INS 0xC0

#define MAX_QUEUE 16
#define MAX_MSG 4096

struct msg {
	uint8_t data[MAX_MSG];
	size_t len;
};

static struct msg queue[MAX_QUEUE];
static unsigned int queued, dequeued;

static struct msg requests[MAX_QUEUE];
static unsigned int request_count;

static struct msg in_progress;	/* request being assembled from STORE DATA blocks */
static struct msg pending;	/* response being handed out via GET RESPONSE */
static size_t pending_offset;
static bool offline;

void euicc_stub_reset(void)
{
	memset(queue, 0, sizeof(queue));
	memset(requests, 0, sizeof(requests));
	memset(&in_progress, 0, sizeof(in_progress));
	memset(&pending, 0, sizeof(pending));
	queued = dequeued = request_count = 0;
	pending_offset = 0;
	offline = false;
}

void euicc_stub_queue(const uint8_t *der, size_t len)
{
	assert(queued < MAX_QUEUE);
	assert(len <= MAX_MSG);
	if (len)
		memcpy(queue[queued].data, der, len);
	queue[queued].len = len;
	queued++;
}

void euicc_stub_queue_empty(void)
{
	euicc_stub_queue(NULL, 0);
}

static int collect(const void *buf, size_t size, void *key)
{
	struct msg *m = key;

	assert(m->len + size <= MAX_MSG);
	memcpy(m->data + m->len, buf, size);
	m->len += size;
	return 0;
}

void euicc_stub_queue_asn1(const struct asn_TYPE_descriptor_s *td, const void *obj)
{
	struct msg m = { 0 };
	asn_enc_rval_t er;

	er = der_encode((struct asn_TYPE_descriptor_s *)td, (void *)obj, collect, &m);
	assert(er.encoded >= 0);
	euicc_stub_queue(m.data, m.len);
}

unsigned int euicc_stub_requests(void)
{
	return request_count;
}

const uint8_t *euicc_stub_request(unsigned int n, size_t *len)
{
	if (n >= request_count)
		return NULL;
	if (len)
		*len = requests[n].len;
	return requests[n].data;
}

bool euicc_stub_request_has_tag(unsigned int n, uint16_t tag)
{
	size_t len;
	const uint8_t *req = euicc_stub_request(n, &len);

	if (!req)
		return false;
	if (tag > 0xff)
		return len >= 2 && req[0] == (tag >> 8) && req[1] == (tag & 0xff);
	return len >= 1 && req[0] == (uint8_t)tag;
}

void euicc_stub_set_offline(bool value)
{
	offline = value;
}

/* One complete request has arrived: record it and take the next queued response. */
static void finish_request(void)
{
	assert(request_count < MAX_QUEUE);
	requests[request_count++] = in_progress;
	memset(&in_progress, 0, sizeof(in_progress));

	if (dequeued < queued)
		pending = queue[dequeued++];
	else
		memset(&pending, 0, sizeof(pending));	/* nothing queued: answer 9000, no data */
	pending_offset = 0;
}

static int reply(struct ipa_buf *res, const uint8_t *data, size_t len, uint16_t sw)
{
	if (len)
		memcpy(res->data, data, len);
	res->data[len] = sw >> 8;
	res->data[len + 1] = sw & 0xff;
	res->len = len + 2;
	return 0;
}

/* SW to send once a request is complete: 61xx when there is a response body to fetch, else 9000.
 * xx is the number of bytes still available, or 0 meaning 256 (ETSI TS 102 221 section 10.1.6). */
static uint16_t sw_for_pending(void)
{
	size_t left = pending.len - pending_offset;

	if (!left)
		return 0x9000;
	return 0x6100 | (left > 255 ? 0x00 : (uint8_t)left);
}

int ipa_scard_transceive(void *scard_ctx, struct ipa_buf *res, const struct ipa_buf *req)
{
	const uint8_t *a = req->data;
	(void)scard_ctx;

	if (offline)
		return -1;

	assert(req->len >= 5);

	if ((a[0] & 0xf0) == STORE_DATA_CLA && a[1] == STORE_DATA_INS) {
		uint8_t lc = a[4];

		assert(req->len == 5u + lc);
		assert(a[2] == STORE_DATA_P1_LAST_BLOCK || a[2] == STORE_DATA_P1_MORE_BLOCKS);
		assert(in_progress.len + lc <= MAX_MSG);
		memcpy(in_progress.data + in_progress.len, a + 5, lc);
		in_progress.len += lc;

		if (a[2] == STORE_DATA_P1_MORE_BLOCKS)
			return reply(res, NULL, 0, 0x9000);	/* ack, keep going */

		finish_request();
		return reply(res, NULL, 0, sw_for_pending());
	}

	if ((a[0] & 0xf0) == GET_RESPONSE_CLA && a[1] == GET_RESPONSE_INS) {
		size_t want = a[4] ? a[4] : 256;
		size_t left = pending.len - pending_offset;
		size_t give = want < left ? want : left;

		/* euicc.c asks for exactly what the previous SW advertised and rejects a short
		 * answer, so a mismatch here is a bug in this stub, not in the code under test. */
		assert(give == want);
		pending_offset += give;
		return reply(res, pending.data + pending_offset - give, give, sw_for_pending());
	}

	fprintf(stderr, "euicc_stub: unexpected APDU %02X %02X\n", a[0], a[1]);
	abort();
}

/* The rest of the smartcard interface: enough for a context to come up, nothing more. */
void *ipa_scard_init(unsigned int reader_num)
{
	(void)reader_num;
	return (void *)"euicc_stub";
}

int ipa_scard_reset(void *scard_ctx)
{
	(void)scard_ctx;
	return 0;
}

int ipa_scard_atr(void *scard_ctx, struct ipa_buf *atr)
{
	(void)scard_ctx;
	(void)atr;
	return 0;
}

int ipa_scard_free(void *scard_ctx)
{
	(void)scard_ctx;
	return 0;
}
