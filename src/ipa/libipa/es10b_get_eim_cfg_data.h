/*
 * Copyright (c) 2025 Onomondo ApS & sysmocom - s.f.m.c. GmbH. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#pragma once

#include <GetEimConfigurationDataResponse.h>
struct ipa_context;
struct ipa_buf;

/*! Struct to hold a single item of the EimConfigurationData list */
struct ipa_eim_cfg_data {
	char *eim_id;
	char *eim_fqdn;
	long *eim_id_type;
	long *counter_value;
	long *association_token;
	struct {
		struct ipa_buf *eim_public_key;
		struct ipa_buf *eim_certificate;
	} eim_public_key_data;
	struct {
		struct ipa_buf *trusted_eim_pk_tls;
		struct ipa_buf *trusted_certificate_tls;
	} trusted_public_key_data_tls;
	struct ipa_buf *eim_supported_protocol;
	struct ipa_buf *euicc_ci_pkid;
};

struct ipa_es10b_eim_cfg_data {
	struct GetEimConfigurationDataResponse *res;

	/* The GetEimConfigurationDataResponse contains a list of EimConfigurationData elements. To simplify the
	 * the access to the list items and their members, the list is automatically converted into an array of
	 * struct ipa_eim_cfg_data items (see above). In case the caller wants to take ownership of eim_cfg_data_list,
	 * he can do so by setting eim_cfg_data_list to NULL before calling ipa_es10b_get_eim_cfg_data_free. */
	struct ipa_eim_cfg_data **eim_cfg_data_list;
	long eim_cfg_data_list_count;
};

/*! Read eIM Configuration Data from the eUICC, see GSMA SGP.32, section 5.9.18.
 *  \param[inout] ctx pointer to ipa_context.
 *  \param[in] eim_id when set, sent as searchCriteria.eimId so the eUICC returns only that entry;
 *             NULL or empty asks for the whole list. Callers that want one specific eIM should pass it
 *             here and still run ipa_es10b_get_eim_cfg_data_filter() on the result -- the filter costs
 *             nothing and does not assume the eUICC honoured the criteria.
 *  \returns newly allocated response, NULL on error. */
struct ipa_es10b_eim_cfg_data *ipa_es10b_get_eim_cfg_data(struct ipa_context *ctx, const char *eim_id);
void ipa_es10b_get_eim_cfg_data_free(struct ipa_es10b_eim_cfg_data *res);

struct EimConfigurationData *ipa_es10b_get_eim_cfg_data_filter(struct ipa_es10b_eim_cfg_data *res, char *eim_id);
