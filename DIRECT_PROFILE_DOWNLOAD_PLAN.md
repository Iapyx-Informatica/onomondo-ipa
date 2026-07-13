# Implementation plan: Direct Profile Download (ES8+ inside ES9+)

## The gap

onomondo-ipa can only reach an SM-DP+ through the eIM (Indirect Profile Download,
SGP.32 §3.2.3.2). Three things are missing, and they are independent:

1. **The eIM's instruction is discarded.** SGP.32 v1.1 §2.11.1.1.1 signals the mode via
   `EimConfigurationData.indirectProfileDownload [9] NULL OPTIONAL` — *present* = use the
   eIM as proxy, *absent* = the IPAd contacts the SM-DP+ directly. The field exists in
   `asn1/SGP32Definitions.asn:89`, but `convert_get_eim_cfg_data()`
   (`es10b_get_eim_cfg_data.c`) never extracts it and `struct ipa_eim_cfg_data` has no
   member for it. `es10b_add_init_eim.c:22-24` already carries a TODO saying exactly this.

2. **There is no transport that can reach an SM-DP+.** `ipa_esipa_req()` (`esipa.c:159`)
   always posts to `ipa_esipa_get_eim_url_for()`, which is hardcoded to
   `ctx->eim_fqdn` + `/gsma/rsp2/asn1`. The SM-DP+ address parsed from the activation code
   is only ever passed *inside* the InitiateAuthentication payload for the eIM to act on
   (`proc_cmn_mtl_auth.c:212`).

3. **The IPAd advertises indirect-only**, consistently: `proc_euicc_data_req.c:92-93` sets
   `directRspServerCommunication = 0`, and `proc_eim_pkg_retr.c:142` unconditionally calls
   `ipa_proc_indirect_prfle_dwnlod()`.

## The key simplification

**Use the ES9+ ASN.1 binding, not the JSON binding.** `asn1/RSPDefinitions.asn:657-670`
already defines `RemoteProfileProvisioningRequest` / `RemoteProfileProvisioningResponse`
(SGP.22 v3 ES9+ ASN.1 binding), and every type underneath it
(`InitiateAuthenticationOkEs9`, `AuthenticateClientOk`, `GetBoundProfilePackageOk`,
`CancelSessionRequestEs9`, `HandleNotification`) is already generated into
`src/ipa/libasn/`. So the direct path reuses the existing DER codec, the existing
`ipa_http_req()`, and the same `application/x-gsma-rsp-asn1` content type. No jansson
dependency, no new wire codec — only a new envelope, a new URL, and a new TLS trust anchor.

The payloads themselves are unchanged in both modes: the IPAd sends the *same* ES10b
outputs (`AuthenticateServerResponse`, `PrepareDownloadResponse`, `CancelSessionResponse`)
to the SM-DP+ that it currently sends to the eIM.

---

## Phase 1 — Plumb the mode signal

*No behaviour change; the IPAd just learns which mode it was told to use.*

| File | Change |
|---|---|
| `es10b_get_eim_cfg_data.h` | Add `bool indirect_profile_download;` to `struct ipa_eim_cfg_data`. |
| `es10b_get_eim_cfg_data.c` | In `convert_get_eim_cfg_data()`, set it from `list.array[i]->indirectProfileDownload != NULL` (asn1c renders a `NULL` field as a `NULL_t *` presence pointer). |
| `context.h` | Add to `struct ipa_context`: `bool indirect_profile_download;` (the eIM's instruction, cached at init) and the session-scoped `enum ipa_rsp_transport { IPA_RSP_VIA_EIM, IPA_RSP_DIRECT } rsp_transport;` plus `char *smdp_fqdn;` (the RSP server for the current session). |
| `ipad.c` | In `eim_init()`, inside the loop at lines 174-196 that already selects the matching eIM config item to install TLS anchors, also record `ctx->indirect_profile_download`. |
| `include/onomondo/ipa/ipad.h` | Add `bool direct_dwnld_disabled;` to `struct ipa_config` — an integrator kill switch for constrained devices that do not want the second TLS stack. |

**Decision rule** (apply in Phase 4): use direct iff `!ctx->indirect_profile_download &&
!ctx->cfg->direct_dwnld_disabled`. If the eIM omits the flag but we cannot do direct, log
loudly and fall back to indirect — the eIM should never do this once we advertise our
capabilities honestly, but be liberal in what we accept.

---

## Phase 2 — ES9+ transport (`es9p.c` / `es9p.h`)

A near-mirror of `esipa.c`:

- `ipa_es9p_get_url(ctx)` → `https://<ctx->smdp_fqdn>/gsma/rsp2/asn1`. The SM-DP+ address
  from the activation code has no scheme, same as `eim_fqdn`.
- `ipa_es9p_req(ctx, req, function_name)` → posts via `ipa_http_req_with_ct()` on a
  **separate** HTTP context, with the ASN.1 content type. The retry/backoff loop is
  identical to `ipa_esipa_req()` (`esipa.c:170-196`) — factor that loop out into a shared
  helper rather than copying it.
- `ipa_es9p_msg_enc()` / `ipa_es9p_msg_dec()` wrapping
  `asn_DEF_RemoteProfileProvisioningRequest` / `...Response`, structurally identical to
  `esipa.c:75-152` (including the `expected_res_type` plausibility check).

**Second HTTP context.** `ctx->smdp_http_ctx = ipa_http_init(cfg->smdp_cabundle,
cfg->smdp_disable_ssl_verif)`. This is not optional: an SM-DP+ certificate chains to a GSMA
CI root, whereas `ctx->http_ctx` is (per `ipad.c:166-196`) pinned to the eIM's
`trustedPublicKeyDataTls` from the eUICC. Applying the eIM anchor to the SM-DP+ would fail;
applying no anchor would be insecure. Add `smdp_cabundle` / `smdp_disable_ssl_verif` to
`struct ipa_config`, and matching flags in the sample app (`main.c`). Remember to close and
free it in `ipa_esipa_close()` / `ipa_close()` / `ipa_free_ctx()`.

---

## Phase 3 — Direct implementations of the five RSP functions

**Do not change the call sites.** Keep the existing `ipa_esipa_init_auth()`,
`ipa_esipa_auth_clnt()`, `ipa_esipa_get_bnd_prfle_pkg()`, `ipa_esipa_cancel_session()`,
`ipa_esipa_handle_notif()` signatures and dispatch on `ctx->rsp_transport` *inside* them —
exactly as they already dispatch on `ctx->cfg->esipa_binding` (`esipa_init_auth.c:139`).
This leaves `proc_cmn_mtl_auth.c`, `proc_prfle_dwnld.c` and `proc_cmn_cancel_sess.c`
completely untouched, which is where all the delicate signature/certificate handling lives.

Each direct function encodes an ES9+ request and then **maps the ES9+ response into the
existing ESipa-shaped result struct**, so downstream code sees no difference:

| ES9+ (RSPDefinitions) | → ESipa struct the procedures already consume | Notes |
|---|---|---|
| `InitiateAuthenticationOkEs9` | `InitiateAuthenticationOkEsipa` | field-for-field; `euiccCiPKIdToBeUsed` → `euiccCiPKIdentifierToBeUsed`. `matchingId` / `ctxParams1` stay NULL — those exist only for eIM-side ctxParams1 generation, and we generate ctxParams1 ourselves in `gen_ctx_params_1()` (`proc_cmn_mtl_auth.c:152`). |
| `AuthenticateClientOk` | `AuthenticateClientOkDPEsipa` | `hashCc` is absent on ES9+ → NULL (it is OPTIONAL on the ESipa side). |
| — | `AuthenticateClientOkDSEsipa` | Not reachable on ES9+ (the SM-DS branch is ES11 `AuthenticateClientResponseEs11`). Stays NULL; `proc_cmn_mtl_auth.c:289` already tolerates that. |
| `GetBoundProfilePackageOk` | `GetBoundProfilePackageOkEsipa` | structurally identical. |
| `CancelSessionResponseEs9` | ok/error booleans | trivial. |
| `HandleNotification` | (request only) | `SEQUENCE { pendingNotification }`. |

### The one genuinely tricky bit: result ownership

`IPA_ESIPA_RES_FREE` (`esipa.h:33`) assumes `res->msg_to_ipa` is an
`EsipaMessageFromEimToIpa` and frees it with that type descriptor. On the direct path the
decoded tree is a `RemoteProfileProvisioningResponse`, and the `init_auth_ok` /
`auth_clnt_ok_dpe` / `get_bnd_prfle_pkg_ok` pointers can no longer point *into* the tree
(the types differ) — they must point at a small shallow wrapper struct whose members are
copied from the ES9+ tree and remain owned by it.

So each result struct gets:

```c
void *asn_tree;                        /* the decoded tree (either message type) */
asn_TYPE_descriptor_t *asn_tree_def;   /* how to free it */
bool ok_is_shallow_wrapper;            /* if set, IPA_FREE(ok) — do not ASN_STRUCT_FREE it */
```

and `IPA_ESIPA_RES_FREE` becomes a function that honours those. ~20 lines, but get it wrong
and you get either a leak or a double-free of ASN.1 subtrees. Worth a dedicated unit test.

### The second tricky bit: raw-BER passthrough

`esipa_auth_clnt.c` hand-builds `AuthenticateClientRequestEsipa` (`enc_auth_clnt_req_passthru`)
so the eUICC's `AuthenticateServerResponse` bytes are embedded **verbatim** — a BER→DER
re-encode would break `euiccSignature1` over `euiccSigned1`. The ES9+ request needs the same
treatment, and the inner tag is the same (`BF38`); only the wrapper differs:

```
ESipa:  BF3B <len> [80 tid] [BF38 raw…]
ES9+:   A2 <len> BF3B <len> [80 tid] [BF38 raw…]      <- extra RemoteProfileProvisioningRequest [2] wrapper
```

Reuse the existing manual encoder and add the `A2` wrapper; do not rebuild it from structs.
**If this is wrong, the SM-DP+ rejects the session with `euiccSignatureInvalid(5)` — which
looks like a crypto bug, not an encoding bug.** Budget debugging time here.

Related: ESipa carries the "possibly compact" `SGP32-*` variants while ES9+ requires the
plain SGP.22 types. On the passthrough path this is moot (the eUICC's own bytes go out
untouched). On the IoT-emulation path (`raw_res == NULL`, see `proc_cmn_mtl_auth.c:276-280`)
the request *is* rebuilt from structs — verify that path emits plain SGP.22 shapes.

---

## Phase 4 — Direct download procedure

- **New `proc_direct_prfle_dwnld.c`**, a near-copy of `proc_indirect_prfle_dwnld.c`: parse
  the activation code → set `ctx->rsp_transport = IPA_RSP_DIRECT` and
  `ctx->smdp_fqdn = ac->sm_dp_plus_address` → Common Mutual Authentication (unchanged) →
  Download Confirmation (unchanged) → consent → Profile Installation → notification.
  Reset `rsp_transport` / `smdp_fqdn` on **every** exit path, including the
  cancel-session paths — the existing `goto error` cleanup gives you the hook.
- **`proc_eim_pkg_retr.c:112-145`**: branch to direct vs indirect on the decision rule from
  Phase 1.
- **Optional, separate item:** `proc_eim_pkg_retr.c:122` currently rejects any
  `ProfileDownloadData` that is not an `activationCode`. Direct mode makes
  `contactDefaultSmdp` cheap to support — the default SM-DP+ address is already reachable
  via `es10a_get_euicc_cfg_addr.c`. Don't bundle it into this change.
- **Notifications (Phase 4b, separate):** in direct mode SGP.32 §3.7 allows delivering
  notifications straight to the notification receiver named *inside* the notification
  (ES9+ `HandleNotification`). Keeping notifications on ESipa is still compliant (the eIM
  forwards them), so ship Phase 4a with `proc_notif_delivery.c` untouched. 4b needs a
  per-notification HTTP target, which is a different shape of change.

---

## Phase 5 — Advertise the capability (do this LAST)

`proc_euicc_data_req.c:92` → `directRspServerCommunication = 1`.

This must land only once the direct path actually works: the eIM reads `IpaCapabilities` to
decide whether to omit `indirectProfileDownload`. Flip the bit early and the eIM stops
proxying — breaking downloads that currently work.

While in that function, re-check `eimCtxParams1Generation = 1` (line 100) against the spec.
The IPAd generates ctxParams1 itself (`gen_ctx_params_1()`), which suggests that bit may be
misreported today; it matters more once the eIM starts making mode decisions from it.

---

## Testing

The existing suite (`tests/`) is unit-level with golden `.ok` / `.err` output files
(`activation_code`, `bpp_segments`, `utils`). Fits this change well:

1. **`tests/es9p_codec`** — golden-file encode/decode of each
   `RemoteProfileProvisioningRequest` variant, including the raw-BER passthrough
   `AuthenticateClientRequest`. Assert the exact `A2 … BF3B … BF38 …` byte layout; that is
   the assertion that would have caught the signature-breaking bug class.
2. **`tests/eim_cfg_mode`** — an `EimConfigurationData` with and without
   `indirectProfileDownload [9]`, asserting the parsed flag and the resulting transport
   decision.
3. **Result-struct free path** — build a mapped ES9+ result, free it under ASan
   (`-DENABLE_SANITIZE=ON` is already supported) to catch the double-free described above.
4. **End-to-end** — point the IPAd at an SM-DP+ test server with an eIM config that omits
   `indirectProfileDownload`, and confirm from the wire that the IPAd opens its own TLS
   session to the SM-DP+ and that the profile installs.

---

## Sequencing and effort

Phases 1 → 2 → 3 → 4a → 5 are strictly ordered; 4b (direct notifications) and
`contactDefaultSmdp` are independent follow-ups.

Rough sizes: Phase 1 ~50 LOC; Phase 2 ~200 LOC (mostly mirrored from `esipa.c`); Phase 3
~400 LOC (five functions + the mapping/ownership work — this is the bulk); Phase 4a ~150
LOC (mostly a copy of the indirect procedure); Phase 5 one line. Plus tests.

The risk is concentrated in Phase 3, and specifically in the two "tricky bits" above
(result ownership, raw-BER passthrough) — not in volume of code.

---

*Caveat: this plan is derived from the code and the ASN.1 modules in this repo. I have not
cross-checked the procedure step numbering or the exact `indirectProfileDownload` semantics
against the SGP.32 v1.2 text itself — worth confirming §2.11.1.1.1 and §3.2.3 before
starting Phase 4.*
