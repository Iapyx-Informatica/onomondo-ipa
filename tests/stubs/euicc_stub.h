/*
 * Copyright (c) 2026 Onomondo ApS & sysmocom - s.f.m.c. GmbH & Iapyx Informatica Ltda. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * A fake eUICC for tests, sitting at the smartcard interface.
 *
 * It implements the ES10x carrier of GSMA SGP.22 section 5.7.2 -- STORE DATA blocks in, SW=61xx,
 * GET RESPONSE blocks out -- so a test drives the whole real stack above it: the es10b_* module, the
 * ES10x framing in euicc.c, and the ASN.1 codec.  Nothing in libipa is stubbed or overridden, which
 * is what makes this usable for the IoT eUICC emulation paths: those consist mostly of libipa
 * talking to itself, and replacing any of it would test the wrong thing.
 *
 * A test queues the responses the card will give, in the order the code under test will ask for
 * them, then inspects the requests that arrived.
 */

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct asn_TYPE_descriptor_s;

/*! Forget all queued responses and recorded requests.  Call at the start of every case. */
void euicc_stub_reset(void);

/*! Queue one ES10x response, as the raw bytes the eUICC would return (a full DER TLV).
 *  Responses are handed out in the order queued, one per request. */
void euicc_stub_queue(const uint8_t *der, size_t len);

/*! Queue one ES10x response by encoding an asn1c structure.  The usual case. */
void euicc_stub_queue_asn1(const struct asn_TYPE_descriptor_s *td, const void *obj);

/*! Queue a request that the card answers with SW=9000 and no data, the way an ES10x function
 *  without a response body behaves. */
void euicc_stub_queue_empty(void);

/*! Number of complete ES10x requests received since the last reset. */
unsigned int euicc_stub_requests(void);

/*! The n-th complete ES10x request received (0-based), or NULL if there was no such request. */
const uint8_t *euicc_stub_request(unsigned int n, size_t *len);

/*! Does the n-th request start with this tag?  The convenient check, since an ES10x request is a
 *  single DER TLV whose tag identifies the function. */
bool euicc_stub_request_has_tag(unsigned int n, uint16_t tag);

/*! Make the card stop answering: every APDU fails at the reader, as a pulled card would.
 *  Exercises the transport-error paths that a queued response cannot reach. */
void euicc_stub_set_offline(bool offline);
