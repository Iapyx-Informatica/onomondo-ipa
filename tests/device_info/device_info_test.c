/*
 * Copyright (c) 2026 Onomondo ApS & sysmocom - s.f.m.c. GmbH & Iapyx Informatica Ltda. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * The cases below follow GSMA SGP.22, section 4.2 (Device Information): tac is mandatory, deviceCapabilities is
 * a mandatory SEQUENCE whose members are all OPTIONAL, and imei is optional.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <stdbool.h>
#include <onomondo/ipa/utils.h>
#include <onomondo/ipa/ipad.h>
#include "src/ipa/libipa/device_info.h"

static const uint8_t tac[IPA_LEN_TAC] = { 0x12, 0x34, 0x56, 0x78 };
static const uint8_t imei[IPA_LEN_IMEI] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };
/* 3GPP release 15, coded major/minor/revision. */
static const uint8_t rel15[IPA_LEN_VERSION] = { 0x0f, 0x00, 0x00 };
static const uint8_t rel17[IPA_LEN_VERSION] = { 0x11, 0x00, 0x00 };

static void base_cfg(struct ipa_config *cfg)
{
	memset(cfg, 0, sizeof(*cfg));
	memcpy(cfg->tac, tac, sizeof(tac));
}

/* Nothing configured beyond the TAC: everything optional stays absent. */
static void minimal_test(void)
{
	struct ipa_config cfg;
	struct DeviceInfo info;
	struct ipa_device_info_store store;

	printf("== minimal_test ==\n");
	base_cfg(&cfg);
	ipa_device_info_fill(&info, &store, &cfg);

	assert(info.tac.size == IPA_LEN_TAC);
	assert(memcmp(info.tac.buf, tac, IPA_LEN_TAC) == 0);

	/* imei is OPTIONAL and was not configured. */
	assert(info.imei == NULL);

	/* deviceCapabilities is mandatory, but with every member absent it is simply an empty SEQUENCE. */
	assert(info.deviceCapabilities.gsmSupportedRelease == NULL);
	assert(info.deviceCapabilities.utranSupportedRelease == NULL);
	assert(info.deviceCapabilities.eutranEpcSupportedRelease == NULL);
	assert(info.deviceCapabilities.nr5gcSupportedRelease == NULL);
}

/* "IMEI (optional)" */
static void imei_test(void)
{
	struct ipa_config cfg;
	struct DeviceInfo info;
	struct ipa_device_info_store store;

	printf("== imei_test ==\n");
	base_cfg(&cfg);
	cfg.imei = imei;
	ipa_device_info_fill(&info, &store, &cfg);

	assert(info.imei);
	assert(info.imei->size == IPA_LEN_IMEI);
	assert(memcmp(info.imei->buf, imei, IPA_LEN_IMEI) == 0);
}

/* "Device capabilities: The Device SHALL set all the capabilities it supports" -- each entry independently. */
static void capabilities_test(void)
{
	struct ipa_config cfg;
	struct DeviceInfo info;
	struct ipa_device_info_store store;
	struct DeviceCapabilities *caps = &info.deviceCapabilities;

	printf("== capabilities_test ==\n");

	/* A single technology set does not drag the others along. */
	base_cfg(&cfg);
	cfg.device_capabilities.eutran_epc = rel15;
	ipa_device_info_fill(&info, &store, &cfg);
	assert(caps->eutranEpcSupportedRelease);
	assert(caps->eutranEpcSupportedRelease->size == IPA_LEN_VERSION);
	assert(memcmp(caps->eutranEpcSupportedRelease->buf, rel15, IPA_LEN_VERSION) == 0);
	assert(caps->gsmSupportedRelease == NULL);
	assert(caps->nr5gcSupportedRelease == NULL);

	/* Two technologies at different releases must not share storage. */
	base_cfg(&cfg);
	cfg.device_capabilities.gsm = rel15;
	cfg.device_capabilities.nr_5gc = rel17;
	ipa_device_info_fill(&info, &store, &cfg);
	assert(caps->gsmSupportedRelease && caps->nr5gcSupportedRelease);
	assert(memcmp(caps->gsmSupportedRelease->buf, rel15, IPA_LEN_VERSION) == 0);
	assert(memcmp(caps->nr5gcSupportedRelease->buf, rel17, IPA_LEN_VERSION) == 0);
	assert(caps->gsmSupportedRelease != caps->nr5gcSupportedRelease);

	/* Every entry lands in its own member, and nothing else. */
	base_cfg(&cfg);
	cfg.device_capabilities.gsm = rel15;
	cfg.device_capabilities.utran = rel15;
	cfg.device_capabilities.cdma2000_onex = rel15;
	cfg.device_capabilities.cdma2000_hrpd = rel15;
	cfg.device_capabilities.cdma2000_ehrpd = rel15;
	cfg.device_capabilities.eutran_epc = rel15;
	cfg.device_capabilities.nr_epc = rel15;
	cfg.device_capabilities.nr_5gc = rel15;
	cfg.device_capabilities.eutran_5gc = rel15;
	ipa_device_info_fill(&info, &store, &cfg);
	assert(caps->gsmSupportedRelease && caps->utranSupportedRelease);
	assert(caps->cdma2000onexSupportedRelease && caps->cdma2000hrpdSupportedRelease);
	assert(caps->cdma2000ehrpdSupportedRelease && caps->eutranEpcSupportedRelease);
	assert(caps->nrEpcSupportedRelease && caps->nr5gcSupportedRelease);
	assert(caps->eutran5gcSupportedRelease);
	/* Members this configuration cannot reach stay absent. */
	assert(caps->contactlessSupportedRelease == NULL);
	assert(caps->rspCrlSupportedVersion == NULL);
	assert(caps->lpaSvn == NULL);
}

/* Refilling must not leave anything behind from the previous configuration. */
static void refill_test(void)
{
	struct ipa_config cfg;
	struct DeviceInfo info;
	struct ipa_device_info_store store;

	printf("== refill_test ==\n");

	base_cfg(&cfg);
	cfg.imei = imei;
	cfg.device_capabilities.gsm = rel15;
	ipa_device_info_fill(&info, &store, &cfg);
	assert(info.imei && info.deviceCapabilities.gsmSupportedRelease);

	base_cfg(&cfg);
	ipa_device_info_fill(&info, &store, &cfg);
	assert(info.imei == NULL);
	assert(info.deviceCapabilities.gsmSupportedRelease == NULL);
}

/* The structure has to survive a DER encode, which is the only thing the SM-DP+ ever sees. */
static void encode_test(void)
{
	struct ipa_config cfg;
	struct DeviceInfo info;
	struct ipa_device_info_store store;
	asn_enc_rval_t rc;
	uint8_t buf[256];
	asn_enc_rval_t (*dummy)(void) = NULL;
	(void)dummy;

	printf("== encode_test ==\n");
	base_cfg(&cfg);
	cfg.imei = imei;
	cfg.device_capabilities.eutran_epc = rel15;
	ipa_device_info_fill(&info, &store, &cfg);

	rc = der_encode_to_buffer(&asn_DEF_DeviceInfo, &info, buf, sizeof(buf));
	assert(rc.encoded > 0);
	printf("   DeviceInfo: %s\n", ipa_hexdump(buf, rc.encoded));

	/* The empty-capabilities case has to encode too: deviceCapabilities is mandatory. */
	base_cfg(&cfg);
	ipa_device_info_fill(&info, &store, &cfg);
	rc = der_encode_to_buffer(&asn_DEF_DeviceInfo, &info, buf, sizeof(buf));
	assert(rc.encoded > 0);
	printf("   minimal:    %s\n", ipa_hexdump(buf, rc.encoded));
}

int main(int argc, char **argv)
{
	minimal_test();
	imei_test();
	capabilities_test();
	refill_test();
	encode_test();
	printf("device_info_test: all checks passed\n");
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

struct ipa_buf *ipa_http_req_with_ct(void *http_ctx, const struct ipa_buf *req, const char *url,
				     const char *content_type)
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
