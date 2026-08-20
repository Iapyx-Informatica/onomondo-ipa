/*
 * Copyright (c) 2026 Onomondo ApS & sysmocom - s.f.m.c. GmbH & Iapyx Informatica Ltda. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * See also: GSMA SGP.22, section 4.2: Device Information
 */

#pragma once

#include <DeviceInfo.h>
#include <VersionType.h>
#include <OCTET_STRING.h>
#include <onomondo/ipa/ipad.h>
struct ipa_context;

/*! Number of radio access technologies in struct ipa_device_capabilities. */
#define IPA_DEVICE_CAP_COUNT 9

/*! Backing storage for the OPTIONAL members of a DeviceInfo.
 *
 *  The ASN.1 structure references its optional members by pointer, so something has to own them for as long as
 *  the DeviceInfo is in use. Keeping that here, next to the DeviceInfo it belongs to, is what lets two callers
 *  build one each without sharing hidden state. */
struct ipa_device_info_store {
	VersionType_t version[IPA_DEVICE_CAP_COUNT];
	OCTET_STRING_t imei;
};

/*! Fill in a DeviceInfo from the IPAd configuration.
 *  \param[out] device_info structure to populate; zeroed first.
 *  \param[out] store backing storage for the optional members, must outlive device_info.
 *  \param[in] cfg IPAd configuration the TAC, IMEI and device capabilities come from. */
void ipa_device_info_fill(struct DeviceInfo *device_info, struct ipa_device_info_store *store,
			  const struct ipa_config *cfg);
