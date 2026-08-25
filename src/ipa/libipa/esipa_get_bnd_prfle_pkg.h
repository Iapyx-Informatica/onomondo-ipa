/*
 * Copyright (c) 2025 Onomondo ApS & sysmocom - s.f.m.c. GmbH. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#pragma once

#include <PrepareDownloadResponse.h>
#include <TransactionId.h>
#include <EsipaMessageFromEimToIpa.h>
#include <GetBoundProfilePackageOkEsipa.h>
struct ipa_context;

struct ipa_esipa_get_bnd_prfle_pkg_req {
	const struct PrepareDownloadResponse *prep_dwnld_res;
};

struct ipa_esipa_get_bnd_prfle_pkg_res {
	struct EsipaMessageFromEimToIpa *msg_to_ipa;
	struct GetBoundProfilePackageOkEsipa *get_bnd_prfle_pkg_ok;
	long get_bnd_prfle_pkg_err;
};

/* The transaction id that belongs to a PrepareDownloadResponse.
 *
 * SGP.32, section 6.4.1.3 lists transactionId among the required members of the GetBoundProfilePackage request,
 * in the ASN.1 binding as well as in the JSON one, but no caller is handed it separately: it travels inside the
 * PrepareDownloadResponse that ES10b.PrepareDownload produced, in a different place for each branch of the
 * CHOICE. Both bindings derive it here so that neither has to know where it hides.
 *
 * Returns a pointer into prep_dwnld_res, or NULL when the response carries no transaction id. */
const TransactionId_t *ipa_esipa_get_bnd_prfle_pkg_transaction_id(const struct PrepareDownloadResponse
								  *prep_dwnld_res);

struct ipa_esipa_get_bnd_prfle_pkg_res *ipa_esipa_get_bnd_prfle_pkg(struct ipa_context *ctx,
								    const struct ipa_esipa_get_bnd_prfle_pkg_req *req);
void ipa_esipa_get_bnd_prfle_pkg_res_free(struct ipa_esipa_get_bnd_prfle_pkg_res *res);

/*! Name of an ESipa.GetBoundProfilePackage error code, for log messages.  Shared by the ASN.1 and
 *  JSON bindings so that one code is never described by two different names. */
const char *ipa_esipa_get_bnd_prfle_pkg_err_str(long err);
