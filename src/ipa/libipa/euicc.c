/*
 * Copyright (c) 2025 Onomondo ApS. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * Author: Philipp Maier <pmaier@sysmocom.de> / sysmocom - s.f.m.c. GmbH
 */

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <errno.h>
#include <onomondo/ipa/mem.h>
#include <onomondo/ipa/utils.h>
#include <onomondo/ipa/scard.h>
#include <onomondo/ipa/log.h>
#include <onomondo/ipa/ipad.h>
#include <ISDRProprietaryApplicationTemplateIoT.h>
#include "context.h"
#include "utils.h"
#include "euicc.h"

#define STORE_DATA_CLA 0x80
#define STORE_DATA_INS 0xE2
#define STORE_DATA_P1_LAST_BLOCK 0x91
#define STORE_DATA_P1_MORE_BLOCKS 0x11

#define GET_RESPONSE_CLA 0x00
#define GET_RESPONSE_INS 0xC0

#define FETCH_CLA 0x80
#define FETCH_INS 0x12

#define TERMINAL_RESPONSE_CLA 0x80
#define TERMINAL_RESPONSE_INS 0x14

#define SELECT_CLA 0x00
#define SELECT_INS 0xA4

#define MANAGE_CHANNEL_CLA 0x00
#define MANAGE_CHANNEL_INS 0x70

/* Proactive command type, ETSI TS 102 223 section 9.4 */
#define PROACTIVE_CMD_REFRESH 0x01

/* REFRESH command qualifiers, ETSI TS 102 223 section 6.6.7 */
#define REFRESH_NAA_INIT_AND_FULL_FILE_CHANGE 0x00
#define REFRESH_FILE_CHANGE 0x01
#define REFRESH_NAA_INIT_AND_FILE_CHANGE 0x02
#define REFRESH_NAA_INIT 0x03
#define REFRESH_UICC_RESET 0x04
#define REFRESH_NAA_APP_RESET 0x05
#define REFRESH_NAA_SESSION_RESET 0x06

#define MAX_BLOCKSIZE_TX 255
#define MAX_BLOCKSIZE_RX 256

#ifdef __APPLE__
#define MAX_GET_RESPONSE_CHUNK_RX 21
#else
#define MAX_GET_RESPONSE_CHUNK_RX MAX_BLOCKSIZE_RX
#endif

struct req_apdu {
	uint8_t cla;
	uint8_t ins;
	uint8_t p1;
	uint8_t p2;
	uint8_t lc;
	uint16_t le;
	uint8_t data[255];
};

struct res_apdu {
	uint16_t le;
	uint8_t data[255];
	uint16_t sw;
};

/* Format the given req_apdu struct into an IPA_BUF that contains the APDU
 * bytes to send. */
static struct ipa_buf *format_req_apdu(const struct req_apdu *req_apdu)
{
	struct ipa_buf *buf_req = ipa_buf_alloc(5 + req_apdu->lc);
	assert(buf_req);

	buf_req->data[0] = req_apdu->cla;
	buf_req->data[1] = req_apdu->ins;
	buf_req->data[2] = req_apdu->p1;
	buf_req->data[3] = req_apdu->p2;

	if (req_apdu->lc > 0 && req_apdu->le == 0) {
		/* Send data (no response data expected) */
		buf_req->data[4] = req_apdu->lc;
		memcpy(buf_req->data + 5, req_apdu->data, req_apdu->lc);
		buf_req->len = 5 + req_apdu->lc;
	} else if (req_apdu->lc == 0 && req_apdu->le > 0) {
		/* Receive data (no data to send) */
		if (req_apdu->le < 256)
			buf_req->data[4] = req_apdu->le;
		else
			/* See also ETSI TS 102 221, section 10.1.6 */
			buf_req->data[4] = 0;
		buf_req->len = 5;
	} else if (req_apdu->lc == 0 && req_apdu->le == 0) {
		/* No data to send and no receive data expected */
		buf_req->data[4] = 0;
		buf_req->len = 5;
	} else {
		/* The T=0 protocol does not support receiving and sending data
		 * at the same time. The caller must ensure that the APDU
		 * struct is filled in with reasonable values! */
		assert(NULL);
	}

	return buf_req;
}

/* Take the received APDU bytes in res_encoded and parse them into an APDU
 * struct (res_apdu) */
static int parse_res_apdu(struct res_apdu *res_apdu, const struct ipa_buf *res_encoded)
{
	memset(res_apdu, 0, sizeof(*res_apdu));

	/* The encoded response should at least contain 2 byte status word */
	if (res_encoded->len < 2)
		return -EINVAL;

	res_apdu->le = res_encoded->len - 2;
	if (res_apdu->le)
		memcpy(res_apdu->data, res_encoded->data, res_apdu->le);

	res_apdu->sw = res_encoded->data[res_apdu->le] << 8;
	res_apdu->sw |= res_encoded->data[res_apdu->le + 1];

	return 0;
}

static int send_es10x_block(struct ipa_context *ctx, uint16_t *sw,
			    const struct ipa_buf *es10x_req, size_t offset, uint8_t block_nr)
{
	size_t len_req;
	int rc;
	struct req_apdu req_apdu = { 0 };
	struct res_apdu res_apdu = { 0 };
	struct ipa_buf *buf_req = NULL;
	struct ipa_buf *buf_res = NULL;
	uint8_t channel = ctx->cfg->euicc_channel;

	buf_res = ipa_buf_alloc(MAX_BLOCKSIZE_TX + 2);
	assert(buf_res);

	len_req = es10x_req->len - offset;

	/* fill in request APDU for STORE DATA
	 * (see also GSMA SGP.22, section 5.7.2) */
	req_apdu.cla = STORE_DATA_CLA | channel;
	req_apdu.ins = STORE_DATA_INS;
	if (len_req > MAX_BLOCKSIZE_TX)
		req_apdu.p1 = STORE_DATA_P1_MORE_BLOCKS;
	else
		req_apdu.p1 = STORE_DATA_P1_LAST_BLOCK;
	req_apdu.p2 = block_nr;
	if (len_req > MAX_BLOCKSIZE_TX)
		req_apdu.lc = MAX_BLOCKSIZE_TX;
	else
		req_apdu.lc = (uint8_t) len_req;
	memcpy(req_apdu.data, es10x_req->data + offset, req_apdu.lc);

	/* transceive block */
	buf_req = format_req_apdu(&req_apdu);
	rc = ipa_scard_transceive(ctx->scard_ctx, buf_res, buf_req);
	if (rc < 0) {
		IPA_LOGP(SEUICC, LERROR, "unable to send ES10x block %u, offset=%zu\n", block_nr, offset);
		ctx->check_scard = true;
		goto exit;
	}

	/* parse response */
	rc = parse_res_apdu(&res_apdu, buf_res);
	if (rc < 0) {
		IPA_LOGP(SEUICC, LERROR,
			 "invalid response while sending ES10x block %u, offset=%zu\n", block_nr, offset);
		goto exit;
	}
	*sw = res_apdu.sw;

	IPA_LOGP(SEUICC, LINFO, "successfully sent ES10x block %u, offset=%zu, sw=%04x\n", block_nr, offset, *sw);

	/* Return how many data we have sent. */
	rc = req_apdu.lc;
exit:
	IPA_FREE(buf_req);
	IPA_FREE(buf_res);
	return rc;
}

static int recv_es10x_block(struct ipa_context *ctx, uint16_t *sw,
			    struct ipa_buf **es10x_res, uint16_t block_len, uint8_t block_nr)
{
	int rc;
	struct req_apdu req_apdu = { 0 };
	struct res_apdu res_apdu = { 0 };
	struct ipa_buf *buf_req = NULL;
	struct ipa_buf *buf_res = NULL;
	uint8_t channel = ctx->cfg->euicc_channel;
	struct ipa_buf *es10x_res_ptr = *es10x_res;
	size_t realloc_size;

	/* We only support channel 0-3 */
	assert(channel <= 3);

	buf_res = ipa_buf_alloc(MAX_BLOCKSIZE_RX + 2);
	assert(buf_res);

	/* In case the expected block length exceeds our buffer limit, we must
	 * clip. This is no problem since it is always up to the caller to
	 * check by the return code how many bytes were actually transmitted.
	 * The caller also must evaluate the status word to know if there are
	 * still bytes available in the GET RESPONSE buffer of the eUICC. */
	if (block_len > MAX_BLOCKSIZE_RX)
		block_len = MAX_BLOCKSIZE_RX;
	if (block_len > MAX_GET_RESPONSE_CHUNK_RX)
		block_len = MAX_GET_RESPONSE_CHUNK_RX;

	/* fill in request APDU for GET RESPONSE
	 * (see also ISO/IEC 7816-4, 7.6.1) */
	req_apdu.cla = GET_RESPONSE_CLA | channel;
	req_apdu.ins = GET_RESPONSE_INS;
	req_apdu.p1 = 0x00;
	req_apdu.p2 = 0x00;
	req_apdu.lc = 0;
	req_apdu.le = block_len;

	/* receive block */
	buf_req = format_req_apdu(&req_apdu);
	rc = ipa_scard_transceive(ctx->scard_ctx, buf_res, buf_req);
	if (rc < 0) {
		IPA_LOGP(SEUICC, LERROR, "unable to receive ES10x block %u, offset=%zu\n", block_nr,
			 es10x_res_ptr->len);
		ctx->check_scard = true;
		rc = -EIO;
		goto exit;
	}

	/* parse response */
	rc = parse_res_apdu(&res_apdu, buf_res);
	if (rc < 0) {
		IPA_LOGP(SEUICC, LERROR,
			 "invalid response while receiving ES10x block %u, offset=%zu\n", block_nr, es10x_res_ptr->len);
		rc = -EINVAL;
		goto exit;
	}
	if (res_apdu.le != block_len) {
		IPA_LOGP(SEUICC, LERROR,
			 "unexpected block length (expected:%u, got:%u) while sending ES10x block %u, offset=%zu\n",
			 block_len, res_apdu.le, block_nr, es10x_res_ptr->len);
		rc = -EINVAL;
		goto exit;
	}
	if (es10x_res_ptr->len + res_apdu.le > es10x_res_ptr->data_len) {
		realloc_size = ((es10x_res_ptr->len + res_apdu.le) / IPA_LEN_EUICC_BUF + 1) * IPA_LEN_EUICC_BUF;

		IPA_LOGP(SEUICC, LDEBUG,
			 "eUICC response buffer exhausted, reallocating more memory (have: %zu bytes, required: %zu bytes, will allocate: %zu bytes)\n",
			 es10x_res_ptr->data_len, es10x_res_ptr->len + res_apdu.le, realloc_size);

		/* Reallocate the buffer with enough space for one additional block of size MAX_BLOCKSIZE_RX */
		es10x_res_ptr = ipa_buf_realloc(es10x_res_ptr, realloc_size);
		assert(es10x_res_ptr);
	}

	memcpy(es10x_res_ptr->data + es10x_res_ptr->len, res_apdu.data, res_apdu.le);
	es10x_res_ptr->len += res_apdu.le;
	*sw = res_apdu.sw;

	IPA_LOGP(SEUICC, LINFO,
		 "successfully received ES10x block %u, offset=%zu, sw=%04x\n", block_nr, es10x_res_ptr->len, *sw);

	/* Return how many data we have received. */
	rc = res_apdu.le;
exit:
	IPA_FREE(buf_req);
	IPA_FREE(buf_res);
	*es10x_res = es10x_res_ptr;
	return rc;
}

/* Parse Command Details TLV (tag 0x01/0x81) from a D0-wrapped proactive command.
 * Fills cmd_num, cmd_type, qualifier and returns true on success. */
static bool parse_proactive_cmd_details(const struct ipa_buf *proactive_cmd,
					uint8_t *cmd_num, uint8_t *cmd_type, uint8_t *qualifier)
{
	const uint8_t *d = proactive_cmd->data;
	size_t len = proactive_cmd->len;
	size_t inner_end;
	size_t i;

	/* Outer envelope: D0 <single-byte-len> ... */
	if (len < 4 || d[0] != 0xD0 || d[1] > 0x7F)
		return false;

	inner_end = 2 + d[1];
	if (len < inner_end)
		return false;

	for (i = 2; i + 1 < inner_end;) {
		uint8_t tag  = d[i] & 0x7F; /* strip comprehension-required bit */
		uint8_t tlen = d[i + 1];

		if (i + 2 + tlen > inner_end)
			break;

		if (tag == 0x01 && tlen == 3) { /* Command Details */
			*cmd_num   = d[i + 2];
			*cmd_type  = d[i + 3];
			*qualifier = d[i + 4];
			return true;
		}
		i += 2 + tlen;
	}
	return false;
}

/* Issue a FETCH APDU on the basic logical channel (STK, ETSI TS 102 221 §11.2.2).
 * fetch_len is the byte count from SW=91xx (0 means 256).
 * Returns a newly allocated buffer with the proactive command, or NULL on error.
 * Caller must IPA_FREE the result. */
static struct ipa_buf *do_fetch(struct ipa_context *ctx, uint8_t fetch_len)
{
	struct req_apdu req_apdu = { 0 };
	struct res_apdu res_apdu = { 0 };
	struct ipa_buf *buf_req = NULL;
	struct ipa_buf *buf_res = NULL;
	struct ipa_buf *result = NULL;

	buf_res = ipa_buf_alloc(MAX_BLOCKSIZE_RX + 2);
	assert(buf_res);

	/* FETCH is always on the basic logical channel (CLA=0x80, no channel bits) */
	req_apdu.cla = FETCH_CLA;
	req_apdu.ins = FETCH_INS;
	req_apdu.p1  = 0x00;
	req_apdu.p2  = 0x00;
	req_apdu.lc  = 0;
	req_apdu.le  = fetch_len ? fetch_len : 256;

	buf_req = format_req_apdu(&req_apdu);
	if (ipa_scard_transceive(ctx->scard_ctx, buf_res, buf_req) < 0) {
		IPA_LOGP(SEUICC, LERROR, "FETCH failed due to communication error\n");
		ctx->check_scard = true;
		goto exit;
	}

	if (parse_res_apdu(&res_apdu, buf_res) < 0) {
		IPA_LOGP(SEUICC, LERROR, "FETCH: invalid response APDU\n");
		goto exit;
	}

	if (res_apdu.sw != 0x9000) {
		IPA_LOGP(SEUICC, LERROR, "FETCH failed, sw=%04x\n", res_apdu.sw);
		goto exit;
	}

	result = ipa_buf_alloc(res_apdu.le);
	assert(result);
	memcpy(result->data, res_apdu.data, res_apdu.le);
	result->len = res_apdu.le;

	IPA_LOGP(SEUICC, LINFO, "FETCH successful, %u bytes of proactive command received\n", res_apdu.le);

exit:
	IPA_FREE(buf_req);
	IPA_FREE(buf_res);
	return result;
}

/* Send a TERMINAL RESPONSE acknowledging a REFRESH proactive command
 * (ETSI TS 102 223 §6.8, ETSI TS 102 221 §11.2.3).
 * cmd_details[3] = {cmd_num, cmd_type, qualifier} from the FETCH response. */
static int send_terminal_response(struct ipa_context *ctx, const uint8_t cmd_details[3])
{
	/*
	 * Minimal TERMINAL RESPONSE TLV sequence (no outer envelope):
	 *   81 03 <cmd_num> <cmd_type> <qualifier>  -- Command Details (CR=1)
	 *   82 02 82 81                              -- Device Identities: terminal→UICC
	 *   83 01 00                                 -- Result: success
	 */
	uint8_t tr[12] = {
		0x81, 0x03, cmd_details[0], cmd_details[1], cmd_details[2],
		0x82, 0x02, 0x82, 0x81,
		0x83, 0x01, 0x00,
	};
	struct req_apdu req_apdu = { 0 };
	struct res_apdu res_apdu = { 0 };
	struct ipa_buf *buf_req = NULL;
	struct ipa_buf *buf_res = NULL;
	int rc = 0;

	buf_res = ipa_buf_alloc(MAX_BLOCKSIZE_RX + 2);
	assert(buf_res);

	/* TERMINAL RESPONSE is always on the basic logical channel */
	req_apdu.cla = TERMINAL_RESPONSE_CLA;
	req_apdu.ins = TERMINAL_RESPONSE_INS;
	req_apdu.p1  = 0x00;
	req_apdu.p2  = 0x00;
	req_apdu.lc  = sizeof(tr);
	memcpy(req_apdu.data, tr, sizeof(tr));

	buf_req = format_req_apdu(&req_apdu);
	if (ipa_scard_transceive(ctx->scard_ctx, buf_res, buf_req) < 0) {
		IPA_LOGP(SEUICC, LERROR, "TERMINAL RESPONSE failed due to communication error\n");
		ctx->check_scard = true;
		rc = -EIO;
		goto exit;
	}

	if (parse_res_apdu(&res_apdu, buf_res) < 0) {
		IPA_LOGP(SEUICC, LERROR, "TERMINAL RESPONSE: invalid response APDU\n");
		rc = -EINVAL;
		goto exit;
	}

	if (res_apdu.sw != 0x9000) {
		IPA_LOGP(SEUICC, LERROR, "TERMINAL RESPONSE failed, sw=%04x\n", res_apdu.sw);
		rc = -EINVAL;
		goto exit;
	}

	IPA_LOGP(SEUICC, LINFO, "TERMINAL RESPONSE sent successfully\n");

exit:
	IPA_FREE(buf_req);
	IPA_FREE(buf_res);
	return rc;
}

/* Human readable name of a REFRESH command qualifier, for logging purposes. */
static const char *refresh_qualifier_name(uint8_t qualifier)
{
	switch (qualifier) {
	case REFRESH_NAA_INIT_AND_FULL_FILE_CHANGE:
		return "NAA Initialization and Full File Change Notification";
	case REFRESH_FILE_CHANGE:
		return "File Change Notification";
	case REFRESH_NAA_INIT_AND_FILE_CHANGE:
		return "NAA Initialization and File Change Notification";
	case REFRESH_NAA_INIT:
		return "NAA Initialization";
	case REFRESH_UICC_RESET:
		return "UICC Reset";
	case REFRESH_NAA_APP_RESET:
		return "NAA Application Reset";
	case REFRESH_NAA_SESSION_RESET:
		return "NAA Session Reset";
	default:
		return "unknown";
	}
}

/* Handle a pending proactive REFRESH signalled by SW=91xx: issue FETCH then
 * TERMINAL RESPONSE.  Errors are logged but do not fail the ES10x operation
 * because the eUICC has already committed the command (e.g. profile enable). */
static void handle_proactive_refresh(struct ipa_context *ctx, uint8_t fetch_len)
{
	struct ipa_buf *proactive_cmd;
	/* Fallback defaults, used when the proactive command cannot be fetched or parsed:
	 * cmd_num=1, REFRESH, NAA Initialization and Full File Change Notification. */
	uint8_t cmd_details[3] = { 0x01, PROACTIVE_CMD_REFRESH, REFRESH_NAA_INIT_AND_FULL_FILE_CHANGE };
	bool parsed = false;

	IPA_LOGP(SEUICC, LINFO,
		 "SW=91xx: proactive REFRESH pending (%u bytes), issuing FETCH + TERMINAL RESPONSE\n", fetch_len);

	proactive_cmd = do_fetch(ctx, fetch_len);
	if (proactive_cmd) {
		parsed = parse_proactive_cmd_details(proactive_cmd, &cmd_details[0], &cmd_details[1],
						     &cmd_details[2]);
		if (!parsed)
			IPA_LOGP(SEUICC, LERROR,
				 "unable to parse the command details of the proactive command\n");
		IPA_FREE(proactive_cmd);
	}

	send_terminal_response(ctx, cmd_details);

	/* The proactive command details could not be read, so the qualifier below is a guess
	 * and must not be acted upon. */
	if (!parsed)
		return;

	/* SW=91xx only tells us that a proactive command is pending, not which one. Anything
	 * other than REFRESH does not concern the ES10x link. */
	if (cmd_details[1] != PROACTIVE_CMD_REFRESH) {
		IPA_LOGP(SEUICC, LINFO, "pending proactive command is not a REFRESH (type=%02x), ignoring\n",
			 cmd_details[1]);
		return;
	}

	IPA_LOGP(SEUICC, LINFO, "proactive REFRESH, qualifier %02x (%s)\n", cmd_details[2],
		 refresh_qualifier_name(cmd_details[2]));

	/* Of the qualifiers defined in ETSI TS 102 223 section 6.6.7 only "UICC Reset" asks the
	 * terminal to reset the card. The others concern NAA initialization, NAA/session reset or
	 * file change notifications and leave the ISD-R logical channel intact, so re-opening it
	 * would be wrong: MANAGE CHANNEL addresses a fixed channel number here and some cards
	 * reject opening a channel that was never closed.
	 *
	 * This path only covers eUICCs that ask for the reset. Those that silently require one
	 * after a profile change are handled in ipa_poll(), which keys on the package contents
	 * rather than on card behaviour. */
	if (cmd_details[2] != REFRESH_UICC_RESET)
		return;

	if (ipa_euicc_reset_es10x(ctx) < 0)
		IPA_LOGP(SEUICC, LERROR, "eUICC reset after REFRESH (UICC Reset) failed\n");
	else
		IPA_LOGP(SEUICC, LINFO, "eUICC reset and ES10x re-initialized after REFRESH (UICC Reset)\n");
}

static int euicc_transceive_es10x(struct ipa_context *ctx, struct ipa_buf **es10x_res, const struct ipa_buf *es10x_req)
{
	uint16_t sw;
	uint16_t block_len = 0;
	uint8_t block_nr = 0;
	size_t offset = 0;
	int rc;

	while (1) {
		rc = send_es10x_block(ctx, &sw, es10x_req, offset, block_nr);
		if (rc < 0)
			return -EIO;
		offset += rc;
		block_nr++;

		/* Check if we are done */
		if (offset >= es10x_req->len)
			break;

		/* The eUICC should ACK each block with SW=9000, the last block
		 * be confirmed with 61xx to indicate that response data is
		 * available */
		if (sw != 0x9000 && offset < es10x_req->len) {
			IPA_LOGP(SEUICC, LERROR, "ES10x transmission aborted early by eUICC, sw=%04x\n", sw);
			break;
		}

		/* We can only transmit a maximum amount of 255 blocks in one
		 * STORE DATA cycle. */
		if (block_nr == 255) {
			IPA_LOGP(SEUICC, LERROR,
				 "ES10x request exceeds maximum transmission length (%zu)!\n", es10x_req->len);
			return -EINVAL;
		}
	}

	/* When the transfer of the ES10x request is done, we expect the eUICC
	 * to answer with a response. */
	if (sw == 0x9000) {
		IPA_LOGP(SEUICC, LINFO, "ES10x transmission successful, sw=%04x\n", sw);
		return 0;
	} else if ((sw & 0xff00) == 0x6100) {
		block_nr = 0;

		while (1) {
			/* See also ISO/IEC 7816-4, section 7.4.2 and ETSI TS 102 221, section 10.1.6 */
			if ((sw & 0xff) == 0)
				block_len = 256;
			else
				block_len = sw & 0xff;

			rc = recv_es10x_block(ctx, &sw, es10x_res, block_len, block_nr);
			if (rc < 0)
				return -EIO;
			block_nr++;

			if (sw == 0x9000) {
				IPA_LOGP(SEUICC, LINFO, "ES10x transmission successful, sw=%04x\n", sw);
				return 0;
			}

			/* SW=91xx after GET RESPONSE: the eUICC has delivered all ES10b
			 * response data and is additionally signalling a proactive REFRESH
			 * command (e.g. after a profile enable).  Handle FETCH + TERMINAL
			 * RESPONSE, then report success with the data already accumulated. */
			if ((sw & 0xff00) == 0x9100) {
				IPA_LOGP(SEUICC, LINFO,
					 "ES10x data fully received, proactive command pending, sw=%04x\n", sw);
				handle_proactive_refresh(ctx, sw & 0xff);
				return 0;
			}

			if ((sw & 0xff00) != 0x6100) {
				IPA_LOGP(SEUICC, LINFO, "ES10x transmission failed, sw=%04x\n", sw);
				return -EINVAL;
			}
		}
	} else if ((sw & 0xff00) == 0x9100) {
		/* SW=91xx after the final STORE DATA: the eUICC processed the command
		 * successfully but has no ES10b response data — it is only signalling
		 * a proactive REFRESH (analogous to 9000 + pending STK command). */
		IPA_LOGP(SEUICC, LINFO,
			 "ES10x transmission successful (proactive command pending), sw=%04x\n", sw);
		handle_proactive_refresh(ctx, sw & 0xff);
		return 0;
	} else {
		IPA_LOGP(SEUICC, LERROR, "ES10x transmission failed! sw=%04x\n", sw);
		return -EINVAL;
	}

	return 0;
}

/*! Transceive eUICC/es10x APDU.
 *  \param[inout] ctx pointer to ipa_context.
 *  \param[in] es10x_req buffer with eUICC/es10x request.
 *  \returns IPA_BUF with ES10x response on success, NULL on failure. */
struct ipa_buf *ipa_euicc_transceive_es10x(struct ipa_context *ctx, const struct ipa_buf *es10x_req)
{
	struct ipa_buf *es10x_res;
	int rc;

	/* SGP.32 3.8.4: once the eUICC's own IPAe is running we are not the IPA any more, and SGP.32
	 * 3.8.2 has the eUICC enable the ES10 functions only for the IPA the device declared. Sending
	 * anyway would at best be rejected by the card and at worst be acted on behind the IPAe's back,
	 * so refuse here rather than at each of the several dozen call sites. Recovering is an eUICC
	 * reset followed by a TERMINAL CAPABILITY that declares IPAd again, i.e. ipa_euicc_reset_es10x(),
	 * which puts the mode back before anything reaches this function. */
	if (ctx->ipa_mode == IPA_MODE_IPAE) {
		IPA_LOGP(SEUICC, LERROR,
			 "refusing to send ES10x: the eUICC runs its own IPAe, this IPAd is not the active IPA\n");
		return NULL;
	}

	es10x_res = ipa_buf_alloc(IPA_LEN_EUICC_BUF);

	IPA_LOGP(SEUICC, LDEBUG, "sending %zu bytes to eUICC (buffer size: %zu bytes)\n", es10x_req->len,
		 es10x_req->data_len);

	rc = euicc_transceive_es10x(ctx, &es10x_res, es10x_req);

	if (rc < 0) {
		IPA_FREE(es10x_res);
		return NULL;
	}

	IPA_LOGP(SEUICC, LDEBUG, "received %zu bytes from eUICC (buffer size: %zu bytes)\n", es10x_res->len,
		 es10x_res->data_len);

	return es10x_res;
}

/* Tags of the ISD-R SELECT response, see ISO/IEC 7816-4 and GlobalPlatform. */
#define FCI_TEMPLATE_TAG 0x6F
#define FCI_PROPRIETARY_TAG 0xA5
/* SGP.32, section 3.8.4: ISDRProprietaryApplicationTemplateIoT ::= [PRIVATE 1] SEQUENCE, tag 'E1'. */
#define FCI_ISDR_PROPRIETARY_IOT_TAG 0xE1

/*! Track which IPA is active, see SGP.32, section 3.8.4 and euicc.h.  This is a property of the
 *  conversation, not something the eUICC can be asked: it is our own TERMINAL CAPABILITY that settles
 *  it, and an IpaeActivationRequest that hands it back. */
void ipa_euicc_set_ipa_mode(struct ipa_context *ctx, enum ipa_mode mode)
{
	static const struct num_str_map mode_strings[] = {
		{ IPA_MODE_IPAD, "IPAd" }, { IPA_MODE_IPAE, "IPAe" }, { 0, NULL }
	};

	if (ctx->ipa_mode == mode)
		return;

	ctx->ipa_mode = mode;
	IPA_LOGP(SEUICC, LINFO, "active IPA is now %s\n", ipa_str_from_num(mode_strings, mode, "unknown"));
}

/* Find one TLV by tag among the TLVs packed into data[0..data_len).
 * Returns a pointer to the whole TLV (tag included) and, through the out parameters, where its value
 * starts and how long the whole thing is -- ber_decode() wants the former, a nested walk the latter. */
static const uint8_t *find_tlv(uint16_t wanted, const uint8_t *data, size_t data_len, size_t *hdr_len,
			       size_t *val_len)
{
	size_t offs = 0;

	while (offs < data_len) {
		uint16_t tag = 0;
		size_t len = 0;
		long hdr = ipa_parse_btlv_hdr_at(&len, &tag, data + offs, data_len - offs);

		if (hdr < 0 || (size_t)hdr > data_len - offs || len > data_len - offs - (size_t)hdr)
			return NULL;
		if (tag == wanted) {
			*hdr_len = (size_t)hdr;
			*val_len = len;
			return data + offs;
		}
		offs += (size_t)hdr + len;
	}

	return NULL;
}

/* Pull ISDRProprietaryApplicationTemplateIoT out of the SELECT response FCI.
 *
 * SGP.32 section 3.8.4 has the eUICC return it "within the FCI template after the objects defined in
 * GlobalPlatform Card Specification", so it sits directly under '6F'.  Cards that group their
 * proprietary objects under 'A5' are also accommodated, since that placement is common enough in the
 * field that failing on it would cost us the template for no good reason. */
static void parse_isdr_fci(struct ipa_context *ctx, const uint8_t *fci, size_t fci_len)
{
	ISDRProprietaryApplicationTemplateIoT_t *tmpl = NULL;
	const uint8_t *body, *tlv;
	size_t body_hdr, body_len, tlv_hdr, tlv_len;
	asn_dec_rval_t rval;

	body = find_tlv(FCI_TEMPLATE_TAG, fci, fci_len, &body_hdr, &body_len);
	if (!body) {
		IPA_LOGP(SEUICC, LDEBUG, "ISD-R SELECT response carries no FCI template\n");
		return;
	}
	body += body_hdr;

	tlv = find_tlv(FCI_ISDR_PROPRIETARY_IOT_TAG, body, body_len, &tlv_hdr, &tlv_len);
	if (!tlv) {
		const uint8_t *prop;
		size_t prop_hdr, prop_len;

		prop = find_tlv(FCI_PROPRIETARY_TAG, body, body_len, &prop_hdr, &prop_len);
		if (prop)
			tlv = find_tlv(FCI_ISDR_PROPRIETARY_IOT_TAG, prop + prop_hdr, prop_len, &tlv_hdr, &tlv_len);
	}
	if (!tlv) {
		/* An SGP.22 eUICC carries the [PRIVATE 0] 'E0' template instead, and some cards return no
		 * proprietary template at all.  Neither is our failure: section 3.8.4 puts the SHALL on
		 * the eUICC, and nothing this IPA does depends on the answer. */
		IPA_LOGP(SEUICC, LDEBUG, "ISD-R FCI carries no ISDRProprietaryApplicationTemplateIoT\n");
		return;
	}

	rval = ber_decode(NULL, &asn_DEF_ISDRProprietaryApplicationTemplateIoT, (void **)&tmpl, tlv,
			  tlv_hdr + tlv_len);
	if (rval.code != RC_OK) {
		IPA_LOGP(SEUICC, LERROR, "unable to decode ISDRProprietaryApplicationTemplateIoT from ISD-R FCI\n");
		ASN_STRUCT_FREE(asn_DEF_ISDRProprietaryApplicationTemplateIoT, tmpl);
		return;
	}

	ctx->isdr_fci.valid = true;
	ctx->isdr_fci.ipae_supported =
	    ipa_bit_string_get_named_bit(&tmpl->euiccConfiguration,
					 ISDRProprietaryApplicationTemplateIoT__euiccConfiguration_ipaeSupported);

	IPA_LOGP(SEUICC, LINFO, "eUICC reports IPAe %s, enabled profile: %s\n",
		 ctx->isdr_fci.ipae_supported ? "supported" : "not supported",
		 ipa_bit_string_get_named_bit(&tmpl->euiccConfiguration,
					      ISDRProprietaryApplicationTemplateIoT__euiccConfiguration_enabledProfile)
		 ? "yes" : "no");

	/* Section 3.8.4: an eUICC with an IPAe runs it unless the device has claimed IPAd.  If the mode
	 * is still unsettled when we learn this, the IPAe is what is in charge.  send_termcap() runs
	 * before this today, so this does not fire -- it is the rule, not a guess about the order. */
	if (ctx->ipa_mode == IPA_MODE_UNKNOWN && ctx->isdr_fci.ipae_supported)
		ipa_euicc_set_ipa_mode(ctx, IPA_MODE_IPAE);

	ASN_STRUCT_FREE(asn_DEF_ISDRProprietaryApplicationTemplateIoT, tmpl);
}

/* Fetch the FCI the ISD-R SELECT left waiting behind SW=61xx and hand it to parse_isdr_fci(). */
static void get_isdr_fci(struct ipa_context *ctx, uint8_t fci_len)
{
	struct req_apdu req_apdu = { 0 };
	struct res_apdu res_apdu = { 0 };
	struct ipa_buf *buf_req = NULL;
	struct ipa_buf *buf_res = NULL;

	buf_res = ipa_buf_alloc(MAX_BLOCKSIZE_RX + 2);
	assert(buf_res);

	req_apdu.cla = GET_RESPONSE_CLA | ctx->cfg->euicc_channel;
	req_apdu.ins = GET_RESPONSE_INS;
	req_apdu.le = fci_len ? fci_len : 256;
	buf_req = format_req_apdu(&req_apdu);

	if (ipa_scard_transceive(ctx->scard_ctx, buf_res, buf_req) < 0) {
		IPA_LOGP(SEUICC, LERROR, "unable to read the ISD-R FCI due to communication error\n");
		ctx->check_scard = true;
		goto exit;
	}
	if (parse_res_apdu(&res_apdu, buf_res) < 0 || (res_apdu.sw & 0xFF00) != 0x9000) {
		IPA_LOGP(SEUICC, LERROR, "unable to read the ISD-R FCI, sw=%04x\n", res_apdu.sw);
		goto exit;
	}

	parse_isdr_fci(ctx, res_apdu.data, res_apdu.le);
exit:
	IPA_FREE(buf_req);
	IPA_FREE(buf_res);
}

/* Send terminal capablilities, see also 3gpp TS 102.221 V16.2.0, section 11.1.19.2.4 */
static int send_termcap(struct ipa_context *ctx)
{
	//const uint8_t termcap[] = { 0xA9, 0x03, 0x83, 0x01, 0x07 };
	const uint8_t termcap[] = { 0xA9, 0x03, 0x84, 0x01, 0x01 };
	int rc;
	struct req_apdu req_apdu = { 0 };
	struct res_apdu res_apdu = { 0 };
	struct ipa_buf *buf_req = NULL;
	struct ipa_buf *buf_res = NULL;

	buf_res = ipa_buf_alloc(MAX_BLOCKSIZE_RX + 2);
	assert(buf_res);

	/* send TERMINAL CAPABILITIES */
	req_apdu.cla = 0x80;
	req_apdu.ins = 0xAA;
	req_apdu.p1 = 0x00;
	req_apdu.p2 = 0x00;
	req_apdu.lc = sizeof(termcap);
	memcpy(req_apdu.data, termcap, sizeof(termcap));
	buf_req = format_req_apdu(&req_apdu);

	rc = ipa_scard_transceive(ctx->scard_ctx, buf_res, buf_req);
	if (rc < 0) {
		IPA_LOGP(SEUICC, LERROR, "unable to send TERMINAL CAPABILITIES due to communication error\n");
		ctx->check_scard = true;
		rc = -EIO;
		goto exit;
	}

	rc = parse_res_apdu(&res_apdu, buf_res);
	if (rc < 0) {
		IPA_LOGP(SEUICC, LERROR, "invalid response while sending TERMINAL CAPABILITIES\n");
		rc = -EINVAL;
		goto exit;
	}

	if ((res_apdu.sw & 0xFF00) != 0x9000) {
		IPA_LOGP(SEUICC, LERROR, "failed to send TERMINAL CAPABILITIES, sw=%04x\n", res_apdu.sw);
		rc = -EINVAL;
		goto exit;
	}

	IPA_LOGP(SEUICC, LINFO, "TERMINAL CAPABILITIES sent\n");
	/* SGP.32 3.8.4: having declared IPAd support (tag '84', b1 = 1) and sending no
	 * IpaeActivationRequest, the eUICC SHALL NOT activate the IPAe -- so from here on we are it. */
	ipa_euicc_set_ipa_mode(ctx, IPA_MODE_IPAD);
exit:
	IPA_FREE(buf_req);
	IPA_FREE(buf_res);
	return rc;
}

static int select_isd_r(struct ipa_context *ctx)
{
	const uint8_t aid_isd_r[] =
	    { 0xA0, 0x00, 0x00, 0x05, 0x59, 0x10, 0x10, 0xFF, 0xFF, 0xFF, 0xFF, 0x89, 0x00, 0x00, 0x01, 0x00 };

	int rc;
	struct req_apdu req_apdu = { 0 };
	struct res_apdu res_apdu = { 0 };
	struct ipa_buf *buf_req = NULL;
	struct ipa_buf *buf_res = NULL;
	uint8_t channel = ctx->cfg->euicc_channel;

	/* We only support channel 0-3 */
	assert(channel <= 3);

	buf_res = ipa_buf_alloc(MAX_BLOCKSIZE_RX + 2);
	assert(buf_res);

	/* SELECT ADF.ISD-R */
	req_apdu.cla = SELECT_CLA | channel;
	req_apdu.ins = SELECT_INS;
	req_apdu.p1 = 0x04;
	req_apdu.p2 = 0x04;
	req_apdu.lc = 16;
	req_apdu.le = 0;
	memcpy(req_apdu.data, aid_isd_r, sizeof(aid_isd_r));
	buf_req = format_req_apdu(&req_apdu);

	rc = ipa_scard_transceive(ctx->scard_ctx, buf_res, buf_req);
	if (rc < 0) {
		IPA_LOGP(SEUICC, LERROR, "unable select ISD-R due to communication error\n");
		ctx->check_scard = true;
		rc = -EIO;
		goto exit;
	}

	rc = parse_res_apdu(&res_apdu, buf_res);
	if (rc < 0) {
		IPA_LOGP(SEUICC, LERROR, "invalid response while selecting ISD-R\n");
		rc = -EINVAL;
		goto exit;
	}

	if ((res_apdu.sw & 0xFF00) != 0x6100) {
		IPA_LOGP(SEUICC, LERROR, "failed to select ISD-R, sw=%04x\n", res_apdu.sw);
		rc = -EINVAL;
		goto exit;
	}

	IPA_LOGP(SEUICC, LINFO, "ISD-R selected\n");

	/* SW=61xx says how many FCI bytes are waiting. Reading them is best effort: SGP.32 3.8.4 puts
	 * the SHALL on the eUICC, and nothing this IPA does depends on what the template says. */
	get_isdr_fci(ctx, res_apdu.sw & 0x00FF);
exit:
	IPA_FREE(buf_req);
	IPA_FREE(buf_res);
	return rc;

}

static int manage_channel(struct ipa_context *ctx, bool close)
{
	int rc;
	struct req_apdu req_apdu = { 0 };
	struct res_apdu res_apdu = { 0 };
	struct ipa_buf *buf_req = NULL;
	struct ipa_buf *buf_res = NULL;
	uint8_t channel = ctx->cfg->euicc_channel;

	/* We only support channel 0-3 */
	assert(channel <= 3);

	if (channel == 0) {
		IPA_LOGP(SEUICC, LINFO, "using basic logical channel %u, no need to %s a channel\n", channel,
			 close ? "close" : "open");
		return 0;
	}

	buf_res = ipa_buf_alloc(MAX_BLOCKSIZE_RX + 2);
	assert(buf_res);

	/* MANAGE CHANNEL */
	req_apdu.cla = MANAGE_CHANNEL_CLA;
	req_apdu.ins = MANAGE_CHANNEL_INS;
	if (close)
		req_apdu.p1 = 0x80;
	else
		req_apdu.p1 = 0x00;
	req_apdu.p2 = channel;
	req_apdu.lc = 0;
	req_apdu.le = 0;
	buf_req = format_req_apdu(&req_apdu);

	rc = ipa_scard_transceive(ctx->scard_ctx, buf_res, buf_req);
	if (rc < 0) {
		IPA_LOGP(SEUICC, LERROR, "unable %s logical channel %u due to communication error with eUICC\n",
			 close ? "close" : "open", channel);
		ctx->check_scard = true;
		rc = -EIO;
		goto exit;
	}

	rc = parse_res_apdu(&res_apdu, buf_res);
	if (rc < 0) {
		IPA_LOGP(SEUICC, LERROR, "invalid response from eUICC, cannot %s logical channel %u\n",
			 close ? "close" : "open", channel);
		rc = -EINVAL;
		goto exit;
	}

	if ((res_apdu.sw) != 0x9000) {
		IPA_LOGP(SEUICC, LERROR, "failed to %s logical channel %u, sw=%04x\n", close ? "close" : "open",
			 channel, res_apdu.sw);
		rc = -EINVAL;
		goto exit;
	}

	IPA_LOGP(SEUICC, LINFO, "logical channel %u %s\n", channel, close ? "closed" : "opened");
exit:
	IPA_FREE(buf_req);
	IPA_FREE(buf_res);
	return rc;
}

/*! open the communication channel between eUICC and IPAd.
 *  \param[inout] ctx pointer to ipa_context.
 *  \returns 0 on success, negative on error. */
int ipa_euicc_init_es10x(struct ipa_context *ctx)
{
	int rc;

	rc = send_termcap(ctx);
	if (rc < 0)
		return rc;

	rc = manage_channel(ctx, false);
	if (rc < 0)
		return rc;

	rc = select_isd_r(ctx);
	return rc;
}

/*! reset the eUICC and re-establish the communication channel between eUICC and IPAd.
 *
 *  An eUICC may refuse any further ES10b command with SW=6985 until it has been reset, in
 *  particular after the active profile has changed. Closing and re-opening the logical
 *  channel does not satisfy this: the card keeps answering MANAGE CHANNEL and SELECT, it
 *  is only the ES10b STORE DATA commands that are rejected. The card must be reset on the
 *  reader level.
 *
 *  \param[inout] ctx pointer to ipa_context.
 *  \returns 0 on success, negative on error. */
int ipa_euicc_reset_es10x(struct ipa_context *ctx)
{
	int rc;

	rc = ipa_scard_reset(ctx->scard_ctx);
	if (rc < 0) {
		IPA_LOGP(SEUICC, LERROR, "unable to reset the eUICC\n");
		ctx->check_scard = true;
		return rc;
	}

	/* The reset dropped all logical channels and the TERMINAL CAPABILITIES the eUICC was
	 * told about, so the initialization has to run again in full. */
	rc = ipa_euicc_init_es10x(ctx);
	if (rc < 0) {
		IPA_LOGP(SEUICC, LERROR, "unable to re-initialize the ES10x link after the eUICC reset\n");
		return rc;
	}

	return 0;
}

/*! close the communication channel between eUICC and IPAd.
 *  \param[inout] ctx pointer to ipa_context.
 *  \returns 0 on success, negative on error. */
int ipa_euicc_close_es10x(struct ipa_context *ctx)
{
	return manage_channel(ctx, true);
}
