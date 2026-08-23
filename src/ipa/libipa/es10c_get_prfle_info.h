/*
 * Copyright (c) 2025 Onomondo ApS & sysmocom - s.f.m.c. GmbH. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include <ProfileInfoListRequest.h>
#include <ProfileInfoListResponse.h>
#include <SGP32-ProfileInfoListResponse.h>
#include <SGP32-ProfileInfo.h>
struct ipa_context;

struct ipa_es10c_get_prfle_info_req {
	struct ProfileInfoListRequest req;
};

struct ipa_es10c_get_prfle_info_res {
	struct ProfileInfoListResponse *res;
	struct SGP32_ProfileInfoListResponse *sgp32_res;
	struct SGP32_ProfileInfo *currently_active_prfle;
	long prfle_info_list_err;

	/*! When the IoT eUICC emulation is enabled, this function will retrieve the ProfileInfoListResponse
	 *  (res, SGP.22) from the eUICC and derive SGP32_ProfileInfoListResponse (sgp32_res) from it. When
	 *  the emulation is turned off sgp32_res will be retrieved directly and no conversion is needed. This also
	 *  means that res (SGP.22) will be left unpopulated (NULL) in this case. Hence it is recommended to use
	 *  sgp32_res only, since it will always be populated, regardless of which eUICC type is used. */
};

struct ipa_es10c_get_prfle_info_res *ipa_es10c_get_prfle_info(struct ipa_context *ctx,
							      const struct ipa_es10c_get_prfle_info_req *req);
void ipa_es10c_get_prfle_info_res_free(struct ipa_es10c_get_prfle_info_res *res);

/*! Find one Profile by ICCID in a GetProfilesInfo result.
 *  \param[in] res result to search, may be NULL or hold an error.
 *  \param[in] iccid IPA_LEN_ICCID bytes to match.
 *  \returns the matching ProfileInfo, NULL when the eUICC does not have it. */
const struct SGP32_ProfileInfo *ipa_es10c_prfle_by_iccid(const struct ipa_es10c_get_prfle_info_res *res,
							 const uint8_t *iccid);

/*! Is this Profile enabled? Tolerates a NULL Profile and an absent profileState, both of which mean
 *  "not enabled" rather than an error. */
bool ipa_es10c_prfle_is_enabled(const struct SGP32_ProfileInfo *prfle_info);
