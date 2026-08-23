/*
 * Copyright (c) 2025 Onomondo ApS & sysmocom - s.f.m.c. GmbH. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * =====================================================================
 * NEW in v1.1: 5.9.24 — ES10b function GetConnectivityParameters.
 * Tag: [95] (BF5F).
 *
 * GetConnectivityParametersRequest  ::= SEQUENCE { }
 * GetConnectivityParametersResponse ::= CHOICE {
 *   connectivityParameters ConnectivityParameters,
 *   connectivityParametersError ConnectivityParametersError
 * }
 * ConnectivityParameters       ::= SEQUENCE { httpParams [1] OCTET STRING OPTIONAL }
 * ConnectivityParametersError  ::= INTEGER {
 *   parametersNotAvailable(1), undefinedError(127)
 * }
 *
 * Lets an eUICC expose connectivity parameters (HTTP and/or CoAP) that the
 * IPA must use when reaching back to the eIM / RSP server.
 *
 * Implemented in es10b_get_connectivity_params.c and exposed as
 * ipa_get_connectivity_params().  The parameters are handed to the host rather than
 * applied to http.c / esipa.c here: which of them to honour is a device decision, and
 * onomondo/ipa/ipad.h says so at the declaration.
 * =====================================================================
 */

#pragma once

struct ipa_context;
struct ipa_buf;

struct ipa_es10b_connectivity_params {
	struct ipa_buf *http_params; /* OCTET STRING; may be NULL */
};

struct ipa_es10b_connectivity_params *ipa_es10b_get_connectivity_params(struct ipa_context *ctx);
void ipa_es10b_connectivity_params_free(struct ipa_es10b_connectivity_params *p);
