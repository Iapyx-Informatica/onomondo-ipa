/*
 * Copyright (c) 2026 Onomondo ApS & sysmocom - s.f.m.c. GmbH & Iapyx Informatica Ltda. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * See also: GSMA SGP.32, 3.8.4: ISD-R Selection and IPAe Activation.
 *           NEW in v1.1.  Tag [66] (BF42).
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <onomondo/ipa/mem.h>
#include <onomondo/ipa/utils.h>
#include <onomondo/ipa/log.h>
#include <IpaeActivationRequest.h>
#include <IpaeActivationResponse.h>
#include "context.h"
#include "utils.h"
#include "euicc.h"
#include "es10x.h"
#include "ipae_activation.h"

static const struct num_str_map error_code_strings[] = {
	{ IpaeActivationResponse__ipaeActivationResult_ok, "ok" },
	{ IpaeActivationResponse__ipaeActivationResult_notSupported, "notSupported" },
	{ 0, NULL }
};

static int dec_ipae_activation_res(const struct ipa_buf *res_encoded)
{
	struct IpaeActivationResponse *asn = NULL;
	int rc;

	asn = ipa_es10x_res_dec(&asn_DEF_IpaeActivationResponse, res_encoded, "IpaeActivation");
	if (!asn)
		return -EINVAL;

	rc = asn->ipaeActivationResult;
	if (rc == IpaeActivationResponse__ipaeActivationResult_ok)
		IPA_LOGP_ES10X("IpaeActivation", LINFO, "function succeeded with status code %d=%s\n",
			       rc, ipa_str_from_num(error_code_strings, rc, "(unknown)"));
	else
		IPA_LOGP_ES10X("IpaeActivation", LERROR, "function failed with error code %d=%s\n",
			       rc, ipa_str_from_num(error_code_strings, rc, "(unknown)"));

	ASN_STRUCT_FREE(asn_DEF_IpaeActivationResponse, asn);
	return rc;
}

/*! Activate the eUICC's own IPAe.  See ipa_activate_ipae() in onomondo/ipa/ipad.h.
 *  \param[inout] ctx pointer to ipa_context.
 *  \returns eUICC result code (0 = ok, positive = eUICC error status), negative on transport error. */
int ipa_ipae_activation(struct ipa_context *ctx)
{
	struct ipa_buf *req_encoded = NULL;
	struct ipa_buf *res_encoded = NULL;
	struct IpaeActivationRequest req = { 0 };
	/* ipaeOption has one named bit (0) -> 1 byte, 7 unused bits at the LSB end.  The DER encoder
	 * masks the last octet with (0xff << bits_unused), so too large a value would silently clear
	 * the only bit we are here to set. */
	uint8_t ipae_option[1] = { 0 };

	int rc = -EINVAL;

	/* Section 3.8.4 conditions the activation on the eUICC having advertised IPAe in the ISD-R FCI.
	 * When it positively said otherwise, do not spend an APDU on a request that can only come back
	 * notSupported.  When the template was absent we do not know, so let the eUICC answer. */
	if (ctx->isdr_fci.valid && !ctx->isdr_fci.ipae_supported) {
		IPA_LOGP_ES10X("IpaeActivation", LERROR,
			       "eUICC did not advertise IPAe support in the ISD-R FCI, not activating\n");
		return -ENOTSUP;
	}
	if (!ctx->isdr_fci.valid)
		IPA_LOGP_ES10X("IpaeActivation", LINFO,
			       "eUICC returned no ISD-R capability template, activating IPAe unconditionally\n");

	req.ipaeOption.buf = ipae_option;
	req.ipaeOption.size = sizeof(ipae_option);
	req.ipaeOption.bits_unused = 7;
	ipae_option[0] |= (1 << (7 - IpaeActivationRequest__ipaeOption_activateIpae));

	req_encoded = ipa_es10x_req_enc(&asn_DEF_IpaeActivationRequest, &req, "IpaeActivation");
	if (!req_encoded) {
		IPA_LOGP_ES10X("IpaeActivation", LERROR, "unable to encode request\n");
		goto error;
	}

	res_encoded = ipa_euicc_transceive_es10x(ctx, req_encoded);
	if (!res_encoded) {
		IPA_LOGP_ES10X("IpaeActivation", LERROR, "no response\n");
		goto error;
	}

	rc = dec_ipae_activation_res(res_encoded);
	if (rc == IpaeActivationResponse__ipaeActivationResult_ok) {
		/* The eUICC's IPAe is in charge from here.  Section 3.8.4 notes that getting back to IPAd
		 * takes an eUICC reset followed by a TERMINAL CAPABILITY that declares IPAd support --
		 * which is exactly what ipa_euicc_reset_es10x() does. */
		ipa_euicc_set_ipa_mode(ctx, IPA_MODE_IPAE);
		IPA_LOGP_ES10X("IpaeActivation", LERROR,
			       "the eUICC now runs its own IPAe; this IPAd is no longer the active IPA\n");
	}

error:
	IPA_FREE(req_encoded);
	IPA_FREE(res_encoded);
	return rc;
}
