/*
 * Copyright (c) 2025 Onomondo ApS & sysmocom - s.f.m.c. GmbH. All rights reserved.
 *
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#pragma once

#include <onomondo/ipa/ipad.h>

struct ipa_buf;
struct ipa_context;

struct ipa_buf *ipa_euicc_transceive_es10x(struct ipa_context *ctx, const struct ipa_buf *es10x_req);
int ipa_euicc_init_es10x(struct ipa_context *ctx);
int ipa_euicc_reset_es10x(struct ipa_context *ctx);
int ipa_euicc_close_es10x(struct ipa_context *ctx);

/*! Record which IPA is active, see SGP.32, section 3.8.4. Only the few places that can actually change
 *  it call this: bringing the link up (TERMINAL CAPABILITY declares IPAd) and activating the IPAe. */
void ipa_euicc_set_ipa_mode(struct ipa_context *ctx, enum ipa_mode mode);
