/*
 * Copyright (c) 2026 Onomondo ApS & sysmocom - s.f.m.c. GmbH & Iapyx Informatica Ltda. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 *
 * =====================================================================
 * NEW in v1.1: 3.8.4 — ISD-R Selection and IPAe Activation.
 * Tag: [66] (BF42), shared with SGP.22's LpaeActivationRequest.
 *
 * IpaeActivationRequest  ::= SEQUENCE { ipaeOption BIT STRING { activateIpae(0) } }
 * IpaeActivationResponse ::= SEQUENCE { ipaeActivationResult INTEGER { ok(0), notSupported(1) } }
 *
 * Not an ES10a/b/c function: section 3.8.4 only says the request "SHALL be sent to the ISD-R using
 * the transport mechanism defined in section 5.7.2 of SGP.22", which is the same STORE DATA carrier
 * the ES10 functions ride on. It therefore goes through ipa_euicc_transceive_es10x() like the rest,
 * but it is filed under its own name rather than es10b_*.
 *
 * This hands control of the eUICC from this IPAd to the eUICC's own IPAe; see ipa_activate_ipae() in
 * onomondo/ipa/ipad.h for what that costs the caller.
 * =====================================================================
 */

#pragma once

struct ipa_context;

int ipa_ipae_activation(struct ipa_context *ctx);
