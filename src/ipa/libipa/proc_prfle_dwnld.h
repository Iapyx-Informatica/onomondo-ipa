/*
 * Copyright (c) 2025 Onomondo ApS & sysmocom - s.f.m.c. GmbH. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#pragma once

#include <AuthenticateClientOkDPEsipa.h>

struct ipa_context;
struct ipa_esipa_get_bnd_prfle_pkg_res;

struct ipa_proc_prfle_dwnlod_pars {
	const AuthenticateClientOkDPEsipa_t *auth_clnt_ok_dpe;
};

/* Run steps 16 and 17 of SGP.32, section 3.2.3.2.
 *
 * On failure the caller has to cancel the RSP session, and section 3.2.3.3 is particular about the reason it
 * gives: metadataMismatch when the eIM reported that the metadata changed, loadBppExecutionError only for an
 * error "while installing a Bound Profile Package", and undefinedReason for anything else. cancel_reason is set
 * to the reason that fits whatever went wrong here, so the caller does not have to guess. It is left untouched
 * on success. */
struct ipa_esipa_get_bnd_prfle_pkg_res *ipa_proc_prfle_dwnlod(struct ipa_context *ctx,
							      const struct ipa_proc_prfle_dwnlod_pars *pars,
							      long *cancel_reason);
