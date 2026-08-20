/*
 * Copyright (c) 2026 Onomondo ApS & sysmocom - s.f.m.c. GmbH & Iapyx Informatica Ltda. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * See also: GSMA SGP.22, section 4.2: Device Information
 *
 * DeviceInfo travels to the SM-DP+ twice over: inside ctxParams1 during the Common Mutual Authentication
 * procedure, and inside IpaEuiccDataResponse when the eIM asks the IPA for it. Both build the same structure
 * from the same configuration, so both build it here.
 */

#include <string.h>
#include <assert.h>
#include <onomondo/ipa/ipad.h>
#include "utils.h"
#include "device_info.h"

/* The radio access technologies of SGP.22 section 4.2 ("Radio access technologies, including release"), in the
 * order they appear in the DeviceCapabilities SEQUENCE. Each is OPTIONAL, and absent means "not supported". */
static void fill_device_capabilities(struct DeviceCapabilities *caps, struct ipa_device_info_store *store,
				     const struct ipa_device_capabilities *cfg_caps)
{
	struct {
		const uint8_t *value;
		VersionType_t **dest;
	} entries[IPA_DEVICE_CAP_COUNT] = {
		{ cfg_caps->gsm, &caps->gsmSupportedRelease },
		{ cfg_caps->utran, &caps->utranSupportedRelease },
		{ cfg_caps->cdma2000_onex, &caps->cdma2000onexSupportedRelease },
		{ cfg_caps->cdma2000_hrpd, &caps->cdma2000hrpdSupportedRelease },
		{ cfg_caps->cdma2000_ehrpd, &caps->cdma2000ehrpdSupportedRelease },
		{ cfg_caps->eutran_epc, &caps->eutranEpcSupportedRelease },
		{ cfg_caps->nr_epc, &caps->nrEpcSupportedRelease },
		{ cfg_caps->nr_5gc, &caps->nr5gcSupportedRelease },
		{ cfg_caps->eutran_5gc, &caps->eutran5gcSupportedRelease },
	};
	unsigned int i;

	for (i = 0; i < IPA_DEVICE_CAP_COUNT; i++) {
		if (!entries[i].value)
			continue;
		IPA_ASSIGN_BUF_TO_ASN(store->version[i], (uint8_t *) entries[i].value, IPA_LEN_VERSION);
		*entries[i].dest = &store->version[i];
	}
}

/*! Fill in a DeviceInfo from the IPAd configuration. */
void ipa_device_info_fill(struct DeviceInfo *device_info, struct ipa_device_info_store *store,
			  const struct ipa_config *cfg)
{
	assert(device_info);
	assert(store);
	assert(cfg);

	memset(device_info, 0, sizeof(*device_info));
	memset(store, 0, sizeof(*store));

	IPA_ASSIGN_BUF_TO_ASN(device_info->tac, (uint8_t *) cfg->tac, IPA_LEN_TAC);

	/* deviceCapabilities is mandatory in DeviceInfo but every one of its members is OPTIONAL, so a device that
	 * declares nothing still encodes a (empty) SEQUENCE. That is legal, and it is what happens when the
	 * integrator leaves ipa_config.device_capabilities alone -- it just tells the SM-DP+ that this device
	 * supports no radio access technology at all, which is unlikely to be true. */
	fill_device_capabilities(&device_info->deviceCapabilities, store, &cfg->device_capabilities);

	/* "IMEI (optional)" */
	if (cfg->imei) {
		IPA_ASSIGN_BUF_TO_ASN(store->imei, (uint8_t *) cfg->imei, IPA_LEN_IMEI);
		device_info->imei = &store->imei;
	}
}
