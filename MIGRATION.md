# onomondo-ipa — v1.0 → v1.2 migration notes

This document tracks the in-progress migration of `onomondo-ipa` from
**GSMA SGP.32 v1.0** to **v1.2** (the version implemented by all
commercially deployed IoT eUICCs).

Every change in this repository is traceable via inline markers of the form:

| Marker                           | Meaning                                                                   |
|----------------------------------|---------------------------------------------------------------------------|
| `UPDATE for v1.1: <section>`     | Changed in the v1.0.1 → v1.1 step (accepted CRs)                          |
| `UPDATE for v1.2: <CR>`          | Changed in the v1.1 → v1.2 step (itemised CRs; see below)                 |
| `NEW in v1.1/v1.2: <section>`    | Net-new type / command / procedure                                        |
| `TODO v1.1/v1.2: <section>`      | Still to be done — listed below                                           |

The ASN.1 schema in [`asn1/SGP32Definitions.asn`](asn1/SGP32Definitions.asn)
has been rewritten to match v1.2 Annex C.  After pulling those changes, just
rebuild — CMake detects the changed schema and re-runs asn1c automatically (the
generated `.c/.h` land in the build tree under `build/.../libasn/gen`).  **Do
not hand-edit generated files** — they are overwritten on the next
regeneration; change [`asn1/*.asn`](asn1/) instead.

> **Note:** this document covers only the v1.0 → v1.2 spec migration.
> Correctness / robustness issues found in a separate code-review pass have been
> fixed; the behavior-affecting runtime TODOs that remain will be tracked in the
> issue tracker.

---

## Build workflow after migration

Native Linux build (needs `asn1c` + `cmake` + `libcurl` (OpenSSL backend) + `libssl` + `libpcsclite`):

```sh
cmake -S . -B build -DENABLE_SANITIZE=ON -DSHOW_ASN_OUTPUT=ON
cmake --build build --parallel
```

Under the hood, CMake generates `libasn` from `asn1/*.asn` during configure, via
[`asn1/gen_libasn.sh`](asn1/gen_libasn.sh), into the build tree.  asn1c is re-run
only when a schema (or the generator) changes, or on a fresh checkout; the
output list is globbed, so added/removed types need no manual bookkeeping.

When the schema changes, **expect compile errors** in `libipa/*.c` if a rename
or new struct member lands there.  Every such site carries a `TODO v1.1` /
`TODO v1.2` marker pointing at the exact change needed.  Work through them
top-down; most are mechanical.

---

## Change summary

### v1.0.1 → v1.1 (roughly 158 accepted CRs)

| Section  | Change                                                                                     | Status  |
|----------|--------------------------------------------------------------------------------------------|---------|
| 2.1.3    | Slimmer import list from RSPDefinitions; SGP.32 overrides EUICCInfo2 / AuthenticateClient / etc. | asn ✓ / libipa TODO |
| 2.11.1.1 | `EuiccPackageSigned.transactionId` → `eimTransactionId`                                    | asn ✓   |
| 2.11.1.1.1 | Size constraint (1..128) on `eimId`; new `indirectProfileDownload[9]`                    | asn ✓   |
| 2.11.1.1.3 | `configureAutoEnable` → `configureImmediateEnable`; new `setFallbackAttribute`, `unsetFallbackAttribute`, `setDefaultDpAddress` PSMOs | asn ✓ |
| 2.11.1.2 | `IpaEuiccDataRequest` restructure: new `searchCriteriaNotification` + `searchCriteriaEuiccPackageResult`; `euiccCiPKIdentifierToBeUsed` (OCTET STRING) | asn ✓ / libipa TODO |
| 2.11.2.1 | **Signing input changed**: `euiccSignEPR/EPE` now over (`data || associationToken`) instead of (`data || eimSignature`) | asn-marker ✓ / libipa TODO |
| 2.11.2   | Renames + new result branches across `EuiccPackageResultDataSigned`; new `SetFallbackAttributeResult`, `UnsetFallbackAttributeResult` | asn ✓ |
| 2.11.2.2 | `IpaEuiccDataResponse` major restructure                                                   | asn ✓ / libipa TODO |
| 2.11.2.3 | `ProfileDownloadTriggerResult.profileDownloadErrorReason` added                            | asn ✓   |
| 3.2.3.1  | Start conditions updated                                                                   | TODO (ipad.c review) |
| 3.4.5    | **Fallback Mechanism** (new procedure)                                                     | TODO    |
| 3.5.2    | More error conditions in procedure                                                         | TODO (proc_eim_pkg_retr.c review) |
| 3.8.1-4  | New SGP.32 sections overriding SGP.22                                                      | TODO    |
| 4.4      | `ProfileInfo` SGP.32 override                                                              | asn-stub / TODO |
| 5.5      | `StoreMetadataRequest` SGP.32 override                                                     | asn-stub / TODO |
| 5.6.1    | `AuthenticateClientRequest` SGP.32 override                                                | asn-stub / TODO |
| 5.7.4    | `HandleNotification` description expanded                                                  | TODO (review proc_notif_delivery.c) |
| 5.9.2    | `EUICCInfo2` gains `euiccCiPKIdListForSigningV3`, `additionalEuiccInfo`, `highestSvn`; `IoTSpecificInfo` gains `ecallSupported`, `fallbackSupported` | asn ✓ / libipa TODO |
| 5.9.4    | `AddInitialEimResponse.unsignedEimConfigDisallowed(2)` → `associatedEimAlreadyExists(2)`; new `commandError(7)` | asn ✓ / libipa TODO |
| 5.9.5    | `EuiccMemoryReset` tag BF34 → BF64, new reset options, renamed auto-enable → immediate-enable | asn ✓ / impl ✓ |
| 5.9.11   | `RetrieveNotificationsListResponse` drops `notificationAndEprList`                         | asn ✓ / libipa TODO |
| 5.9.15   | **`EnableUsingDD` → `ImmediateEnable`** with new `refreshFlag BOOLEAN`                     | asn ✓ / impl ✓ (renamed to es10b_immediate_enable.c) |
| 5.9.17   | `ConfigureAutoProfileEnabling` → `ConfigureImmediateProfileEnabling`                       | asn ✓   |
| 5.9.18   | `GetEimConfigurationDataRequest` gains optional `searchCriteria`                           | asn ✓   |
| 5.9.20   | **NEW** ES10b `ExecuteFallbackMechanism`                                                   | asn ✓ / impl ✓ |
| 5.9.21   | **NEW** ES10b `ReturnFromFallback`                                                         | asn ✓ / impl ✓ |
| 5.9.22   | **NEW** ES10b `EnableEmergencyProfile`                                                     | asn ✓ / impl ✓ |
| 5.9.23   | **NEW** ES10b `DisableEmergencyProfile`                                                    | asn ✓ / impl ✓ |
| 5.9.24   | **NEW** ES10b `GetConnectivityParameters`                                                  | asn ✓ / impl ✓ |
| 5.9.25   | **NEW** ES10b `SetDefaultDpAddress`                                                        | asn ✓ / impl ✓ |
| 5.14.1   | `InitiateAuthentication` gains optional `eimTransactionId`                                 | asn ✓ / libipa TODO |
| 5.14.3   | `AuthenticateClient`: SGP.32 `EuiccSigned1` override; procedure description changed        | asn-stub / libipa TODO |
| 5.14.5   | `GetEimPackage` gains `stateChangeCause`                                                   | asn ✓ / libipa TODO |
| 5.14.6   | `ProvideEimPackageResult` restructured from CHOICE to SEQUENCE wrapper                     | asn ✓ / libipa TODO |
| 5.14.7   | `HandleNotification` details                                                               | asn ✓   |
| 6.1      | eIM must support both JSON and ASN.1 — IPA-side unaffected (ASN.1 only)                    | n/a     |
| 6.3.2.1  | Rename `euiccCiPKIdToBeused` → `euiccCiPKIdentifierToBeUsed`; new error codes              | asn ✓ / libipa TODO |
| 6.3.2.4  | `HandleNotificationEsipa.pendingNotification` tag [0]                                      | asn ✓   |
| 6.3.2.6  | New `StateChangeCause`; `rPLMN` tag shifted; new error codes                               | asn ✓ / libipa TODO |
| 6.3.2.7  | `ProvideEimPackageResult` / `Response` major restructure                                   | asn ✓ / libipa TODO |
| 6.4.x    | JSON bindings — N/A (this IPA is ASN.1-only)                                               | n/a     |
| Annex A.2| CAT requirements for IoT device                                                            | TODO review |

### v1.1 → v1.2 (9 CRs)

| CR            | Sections          | Change                                                          | Status       |
|---------------|-------------------|-----------------------------------------------------------------|--------------|
| CR111002R00   | 6.3.2.7, Annex C  | New error codes in `ProvideEimPackageResultResponse`            | asn ✓ / libipa TODO |
| CR111003R00   | 6.3.2.7, Annex C  | Remove `eimPackageResultErrorCode` from top-level `EimPackageResult` | asn ✓   |
| CR111005R00   | 6.1               | Mandatory `User-Agent` header value (`gsma-rsp-ipad`)           | done ✓ (http_hdr.h) |
| CR111006R00   | 3.2.3.1           | Direct profile download Step 10 clarified                       | TODO review |
| CR111007R00   | 5.9.15 / 22 / 23  | Reset rollback authorization when `refreshFlag == true`         | asn-marker ✓ / libipa TODO |
| CR12008R01    | 5.14.7            | `CompactOtherSignedNotification.eidValue` added                 | asn ✓ / libipa TODO |
| CR12010R00    | 5.9.4             | Absent optional `EimConfigurationData` subfields clarified      | asn-marker ✓ / libipa TODO |
| CR12011R00    | 5.2.6 / 5.14 / 6.1| JSON↔ASN.1 status code mapping                                  | n/a (ASN.1) |
| CR12012R00    | 4.3               | 64-char TLS CN limit (RFC5280 reference)                        | review http.c |
| CR12013R00    | 6.4.1.1 / 6.4.1.3 | JSON binding alignment                                          | n/a (ASN.1) |
| CR12014R02    | 6.3.2.7 / 6.4.1.6 / 5.14.6 | `ProvideEimPackageResult` EidValue inclusion clarified | asn-marker ✓ / libipa TODO |

Legend: **asn ✓** = `SGP32Definitions.asn` already reflects the change.
**libipa TODO** = caller source still needs to be updated; search the repo
for the corresponding `TODO v1.1` / `TODO v1.2` marker.

---

## Suggested sequencing for finishing the migration

1. **Regenerate libasn.**  Just build (`cmake --build build`) after editing the
   schema — CMake re-runs asn1c automatically.  This triggers compile errors at
   every renamed field / enum — those errors become the work list.
2. **Fix pure renames.**  Small, mechanical edits; follow `UPDATE for v1.1`
   markers in the `libipa/*.c` files.  Good candidates for the first PR.
3. **Handle the §2.11.2.1 signing-input change.**  If the IPA runs against
   real IoT eUICCs, the change is transparent (eUICC signs).  If running
   against consumer eUICCs in emulation mode, the TBS construction in the
   scard emulation layer must be updated to use `associationToken` instead
   of `eimSignature`.
4. **Restructure `IpaEuiccDataResponse` / `ProvideEimPackageResult`.**
   These touch several files (`proc_euicc_data_req.c`,
   `esipa_prvde_eim_pkg_rslt.c`).  Markers describe each replacement.
5. **`EnableUsingDD` → `ImmediateEnable` — done.**  File renamed to
   `es10b_immediate_enable.{c,h}`; the `refresh_flag` parameter is threaded
   through the API (callers pass `false` to preserve v1.0 no-REFRESH semantics).
6. **`Fallback` / `Emergency-Profile` / `GetConnectivityParameters` /
   `SetDefaultDpAddress` — implemented and exposed.**  The ES10b
   encode/transceive/decode is in place (`es10b_execute_fallback.c`,
   `es10b_return_from_fallback.c`, `es10b_enable_emergency_profile.c`,
   `es10b_disable_emergency_profile.c`, `es10b_get_connectivity_params.c`,
   `es10b_set_default_dp_addr.c`) and surfaced as a public trigger API in
   `include/onomondo/ipa/ipad.h` (`ipa_execute_fallback()`, …), with the sample
   app exercising each via one-shot CLI options (`-F`, `-b`, `-X`, `-x`, `-G`,
   `-D`, `-i`, `-R`).  What remains is device-specific policy: the daemon
   decides *when* to invoke them (e.g. Fallback on radio-registration failure)
   and feeds GetConnectivityParameters back into `http.c` / `esipa.c`.
7. **Apply the v1.1 → v1.2 CRs** last — they are small and localised.

Expected upstream strategy (as discussed with the developer): fork, land
the renames + signing fix as one reviewable PR, validate against a real
device + the client's eIM, then propose upstream to
`onomondo/onomondo-ipa`.
