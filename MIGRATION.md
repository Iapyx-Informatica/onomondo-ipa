# onomondo-ipa — SGP.32 v1.0 → v1.2 migration record

This fork implements **GSMA SGP.32 v1.2**, the version deployed on commercially
available IoT eUICCs. The migration from v1.0 is complete: the schema is v1.2
Annex C, every call site follows, and no `TODO v1.1` / `TODO v1.2` markers remain
anywhere in the tree.

This document is the record of what that involved and what is deliberately still
open. For the current build and test state see [MIGRATION_STATUS.md](MIGRATION_STATUS.md).

The ASN.1 schema lives in [`asn1/SGP32Definitions.asn`](asn1/SGP32Definitions.asn).
CMake re-runs asn1c whenever a schema or the generator changes, emitting into the
build tree under `build/.../libasn/gen`. **Do not hand-edit generated files** —
change [`asn1/*.asn`](asn1/) instead.

Changes carry inline markers so each one is traceable back to the spec:

| Marker                         | Meaning                                         |
|--------------------------------|-------------------------------------------------|
| `UPDATE for v1.1: <section>`   | Changed in the v1.0.1 → v1.1 step               |
| `UPDATE for v1.2: <CR>`        | Changed in the v1.1 → v1.2 step                 |
| `NEW in v1.1/v1.2: <section>`  | Net-new type, command or procedure              |
| `DONE for v1.2: <CR>`          | Behavioural change verified against the spec    |

---

## What shipped

### v1.0.1 → v1.1

| Section    | Change |
|------------|--------|
| 2.1.3      | Slimmer `RSPDefinitions` import list per Annex C; SGP.32 overrides carry a local `SGP32-` prefix (see below) |
| 2.11.1.1   | `EuiccPackageSigned.transactionId` → `eimTransactionId` |
| 2.11.1.1.1 | `eimId` size constraint (1..128); new `indirectProfileDownload [9]` |
| 2.11.1.1.3 | `configureAutoEnable` → `configureImmediateEnable`; new `setFallbackAttribute`, `unsetFallbackAttribute`, `setDefaultDpAddress` PSMOs |
| 2.11.1.2   | `IpaEuiccDataRequest`: `searchCriteria` → `searchCriteriaNotification`, new `searchCriteriaEuiccPackageResult` |
| 2.11.2     | Renames and new result branches across `EuiccPackageResultDataSigned` |
| 2.11.2.2   | `IpaEuiccDataResponse` restructure |
| 2.11.2.3   | `ProfileDownloadTriggerResult.profileDownloadErrorReason` |
| 3.4.5-3.4.7| **Fallback Mechanism**, including the Fallback Attribute PSMOs and the consumer-eUICC emulation of it |
| 3.8.2      | IoT Device Capabilities sent via TERMINAL CAPABILITY |
| 3.8.4      | ISD-R selection, `ipaeSupported` read from the FCI, `ipa_activate_ipae()` |
| 4.4        | `ProfileInfo` SGP.32 override (`ecallIndication`, `fallbackAttribute`, `fallbackAllowed`) |
| 5.9.2      | `EUICCInfo2` gains `euiccCiPKIdListForSigningV3`, `additionalEuiccInfo`, `highestSvn`; `IoTSpecificInfo` gains `ecallSupported`, `fallbackSupported`, surfaced by `ipa_get_euicc_caps()` |
| 5.9.4      | `unsignedEimConfigDisallowed(2)` → `associatedEimAlreadyExists(2)`; new `commandError(7)` |
| 5.9.5      | `EuiccMemoryReset` tag BF34 → BF64, new reset options, `resetImmediateEnableConfig` |
| 5.9.11     | `RetrieveNotificationsListResponse` drops `notificationAndEprList` |
| 5.9.15     | **`EnableUsingDD` → `ImmediateEnable`** with mandatory `refreshFlag` |
| 5.9.17     | `ConfigureAutoProfileEnabling` → `ConfigureImmediateProfileEnabling` |
| 5.9.18     | `GetEimConfigurationDataRequest` gains optional `searchCriteria` |
| 5.9.20-25  | **New ES10b functions**: `ExecuteFallbackMechanism`, `ReturnFromFallback`, `EnableEmergencyProfile`, `DisableEmergencyProfile`, `GetConnectivityParameters`, `SetDefaultDpAddress` |
| 5.14.1     | `InitiateAuthentication` gains optional `eimTransactionId` |
| 5.14.3     | `AuthenticateClient`: optional `transactionId`, `hashCc`, `profileMetadata` gating |
| 5.14.5     | `GetEimPackage` gains `stateChangeCause` and `rPLMN` |
| 5.14.6 / 6.3.2.7 | `ProvideEimPackageResult` restructured from CHOICE to a SEQUENCE wrapper; `ProvideEimPackageResultResponse` became a three-branch CHOICE |
| 6.3.2.1    | `euiccCiPKIdToBeused` → `euiccCiPKIdentifierToBeUsed`; new error codes |
| 6.3.2.4    | `HandleNotificationEsipa.pendingNotification` tag [0] |
| 6.3.2.6    | New `StateChangeCause`; `rPLMN` tag shifted |

### v1.1 → v1.2 change requests

| CR          | Sections            | Outcome |
|-------------|---------------------|---------|
| CR111002R00 | 6.3.2.7             | `provideEimPackageResultError` codes decoded and reported to callers |
| CR111003R00 | 6.3.2.7             | `eimPackageResultErrorCode` removed from top-level `EimPackageResult` |
| CR111005R00 | 6.1                 | Mandatory `User-Agent` value (`http_hdr.h`) |
| CR111007R00 | 5.9.15 / 22 / 23    | eUICC-side only; the IPA conveys `refreshFlag`, which it already did |
| CR12010R00  | 5.9.4               | Absent optional `EimConfigurationData` subfields get the mandated defaults; a supplied `euiccCiPKId` is validated |
| CR12011R00  | 5.2.6 / 5.14 / 6.1  | JSON ↔ ASN.1 status code mapping, in the JSON binding |
| CR12013R00  | 6.4.1.1 / 6.4.1.3   | JSON binding alignment |
| CR12014R02  | 5.14.6 / 6.3.2.7    | `EidValue` always included, per §5.14.6 NOTE 1 |

Both ESipa wire bindings are built: ASN.1/BER (§6.3) and JSON (§6.4), selected by
`ESIPA_BINDING_ASN1` / `ESIPA_BINDING_JSON`, both ON by default.

### The `SGP32-` prefix

asn1c compiles `RSPDefinitions.asn` and `SGP32Definitions.asn` in one pass into a
single flat C namespace and rejects two definitions of one name outright. libipa
needs the SGP.22 codecs as well — that is what the consumer-eUICC emulation runs
on — so wherever SGP.32 redefines an SGP.22 type under the same name, the local
one keeps an `SGP32-` prefix. This is permanent, and pruning the import does not
change it: the clash is between the definitions. The canonical explanation sits
above `SGP32-EUICCInfo2` in the schema.

Prefixed: `EUICCInfo2`, `EuiccMemoryResetRequest/Response`, `ProfileInfo`,
`ProfileInfoListResponse/Error`, `RetrieveNotificationsListRequest/Response`,
`PendingNotification`, `PendingNotificationList`, `PrepareDownloadResponse`,
`AuthenticateServerResponse`, `CancelSessionResponse`,
`SetDefaultDpAddressRequest/Response`.

Where SGP.32's definition is textually identical to SGP.22's, there is no local
copy at all and the imported type is used directly: `ProfileInstallationResult`,
`CancelSessionOk`, `EuiccSigned1`, `AuthenticateResponseOk`,
`StoreMetadataRequest`.

---

## What remains

None of these blocks a v1.2 deployment against a real IoT eUICC.

**Unimplemented procedures**, each with knock-on items:

- **Direct Profile Download (§3.2.3.1).** Only the Indirect procedure (§3.2.3.2)
  is implemented, entered from `proc_eim_pkg_retr.c`. The Activation Code parser
  exists but is reached only through the eIM's `ProfileDownloadTriggerRequest`,
  never from a locally supplied code. §3.2.3.1's own step 10 *is* satisfied,
  because §3.2.3.2 step 15 delegates the Profile Metadata verification to it and
  `ppr.c` performs it — fetching the RAT and the installed-Profile list from the
  eUICC and cancelling the session with `pprNotAllowed` on failure. CR111006R00
  clarified that same step 10 and needs nothing further.
- **IPA Capability `minimizeEsipaBytes`** (the compact ESipa forms). The compact
  ASN.1 types are generated but nothing constructs them. CR12008R01's
  `CompactOtherSignedNotification.eidValue` belongs to this work, as does
  extending the `seqNumber` extraction in `proc_notif_delivery.c` to cover the
  compact branches.
- **The SM-DS branch.** `AuthenticateClientOkDSEsipa` is decoded, but
  `proc_indirect_prfle_dwnld.c` requires the DP branch and stops otherwise, so
  `profileDownloadTrigger` on that response is never read.

**Out of scope for the IPA**, recorded because earlier drafts listed them as
open review items:

- **§5.7.4** is ES9+', the eIM to SM-DP+ interface. The IPA's HandleNotification
  is the ESipa one, §5.14.7.
- **Annex A.2** lists CAT mechanisms the *IoT Device* must support (TERMINAL
  PROFILE, SET UP EVENT LIST, REFRESH, SMS-PP, BIP channels). Those belong to the
  modem's CAT stack. The IPA's own touchpoints are TERMINAL CAPABILITY (§3.8.2,
  `euicc.c`) and REFRESH handling in the ES10x transport, both present.
- **CR12012R00** is a NOTE in §4.3 recommending that *eIM operators* keep the
  `eimId` within the 64-character RFC 5280 limit on a certificate common name.
  The normative rule is the 128-byte cap, enforced by `asn_check_constraints()`
  in `es10b_add_init_eim.c`. Enforcing 64 in the IPA would reject valid eimIds.
- **§3.5.2** (eIM Configuration Data managed by IPA) is implemented throughout:
  AddInitialEim with all six error conditions of §3.5.2.1, deletion via
  `IPA_EUICC_MEM_RST_EIM_CFG_DATA`, and `GetEimConfigurationData`.

**IoT eUICC emulation limits.** A consumer eUICC cannot sign an eUICC Package
Result (§2.11.2.1 requires `SK.EUICC.ECDSA`, which never leaves the card, and
SGP.22 ES10 has no primitive that signs caller-supplied data), so `euiccSignEPR`
is a placeholder and `seqNumber` is always 0. A conforming eIM discards such a
result under §5.14.6. See README, "IoT eUICC emulation".

**Device policy, not a spec gap.** The six new ES10b functions are implemented
and exposed through `ipad.h` (`ipa_execute_fallback()`, …), with the sample app
driving each from a one-shot CLI option. Deciding *when* to invoke them — Fallback
on radio-registration failure, say — and feeding `GetConnectivityParameters` back
into `http.c` / `esipa.c` is integration work for the host application.
