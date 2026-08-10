# Migration status snapshot — SGP.32 v1.0 → v1.2

## TL;DR — **v1.2 build succeeds, all tests pass**

- ✅ ASN.1 schema updated to v1.2 Annex C
- ✅ `libasn/*.{c,h}` regenerated from v1.2 schema (944 generated files)
- ✅ `libipa/*.c` call sites updated for all renames and struct restructures
  surfaced by the compiler
- ✅ Project links cleanly: `/src/build/src/ipa/ipa` (898 KB binary)
- ✅ Test suite: **7/7 pass** (`ctest` under Ubuntu 24.04)
- ✅ Binary smoke-test: `ipa -h` prints the expected usage

```
100% tests passed, 0 tests failed out of 7
Total Test time (real) =   0.42 sec
```

Reproduce:

```bash
cmake -S . -B build -DENABLE_SANITIZE=ON -DSHOW_ASN_OUTPUT=ON   # regenerates libasn
cmake --build build --parallel
```

## What changed vs. v1.0 baseline

### Toolchain / build
- libasn generation is owned by CMake: `asn1/gen_libasn.sh` runs asn1c into the
  build tree during configure, driven by the top-level `CMakeLists.txt`, which
  re-runs it only when a schema or the generator changes (or on a fresh
  checkout).  The generator auto-detects the `-no-gen-example` flag, fixes the
  PKIX `Time` vs system `<time.h>` collision by renaming to `PKIX_Time.{c,h}`,
  and applies the `asn_internal` allocator patch (routes the codec through the
  `IPA_*` allocators).  The now-dead CertificateSerialNumber patch was removed —
  the schema's `0..INT64_MAX` constraint no longer produces the broken code it
  fixed.  The old `scripts/regen.sh`, `asn1/regenerate_libasn.sh`, and the
  one-time `scripts/post-regen-renames.sh` (v1.0→v1.2 identifier sed) have been
  removed — the tree is on v1.2 names and CMake handles regeneration.  The
  Docker build path (`Dockerfile`, `.dockerignore`, `scripts/`) has also been
  removed; build natively with `cmake` as above.
- `asn1/PKIX1Explicit88.asn`: replaced the 36-digit range constraint on
  `CertificateSerialNumber` with a `0..INT64_MAX` constraint that is parseable
  by `asn1c 0.9.28` (the version packaged with Debian bookworm / Ubuntu 24.04)
  while still forcing `INTEGER_t`.

### Schema (`asn1/SGP32Definitions.asn`)
Full rewrite to match GSMA SGP.32 v1.2 Annex C.  Renames / additions on
every section that changed — see inline markers.  Collisions with
RSPDefinitions resolved by keeping `SGP32-` prefix on local override types
(EUICCInfo2, EuiccMemoryReset, RetrieveNotificationsListRequest/Response,
PendingNotificationList, SetDefaultDpAddressRequest/Response,
ProfileInfoListResponse/Error).

### libipa (real code changes, not just markers)
- [es10b_add_init_eim.c](src/ipa/libipa/es10b_add_init_eim.c) — drop
  `unsignedEimConfigDisallowed`; add `associatedEimAlreadyExists` + `commandError`.
- [es10b_euicc_mem_rst.c](src/ipa/libipa/es10b_euicc_mem_rst.c) — rename
  `resetAutoEnableConfig*` → `resetImmediateEnableConfig*`.
- [es10b_load_euicc_pkg.c](src/ipa/libipa/es10b_load_euicc_pkg.c) — rename
  `configureAutoEnable*` → `configureImmediateEnable*`; `transactionId` →
  `eimTransactionId`; drop `ListEimResult.listEimError_commandError`;
  `Psmo.Delete` → `Psmo.delete`; subfield renames (smdpOid → defaultSmdpOid,
  smdpAddress → defaultSmdpAddress).
- [es10b_retr_notif_from_lst.c](src/ipa/libipa/es10b_retr_notif_from_lst.c) —
  update converter function to use SGP32_PendingNotificationList; drop
  `notificationAndEprList` case; rename `IpaEuiccDataRequest.searchCriteria`
  → `searchCriteriaNotification`.
- [es10b_retr_notif_from_lst.h](src/ipa/libipa/es10b_retr_notif_from_lst.h) —
  dr_search_criteria pointer type updated.
- [es10b_enable_using_dd.c](src/ipa/libipa/es10b_enable_using_dd.c) — switch
  to ImmediateEnableRequest/Response types and `immediateEnableResult`.
- [esipa_get_bnd_prfle_pkg.c](src/ipa/libipa/esipa_get_bnd_prfle_pkg.c) —
  `profileMetadataMismatch` → `metadataMismatch`.
- [esipa_prvde_eim_pkg_rslt.c](src/ipa/libipa/esipa_prvde_eim_pkg_rslt.c) —
  **major rewrite** of both encoder and decoder for the new
  ProvideEimPackageResult SEQUENCE wrapper and ProvideEimPackageResultResponse
  CHOICE shape (CR111002R00, CR111003R00, CR12014R02 applied).
- [proc_cmn_mtl_auth.c](src/ipa/libipa/proc_cmn_mtl_auth.c) — update to new
  `OBJECT_IDENTIFIER_get_arcs` signature (asn_oid_arc_t removed from newer
  asn1c API); field rename `euiccCiPKIdToBeused` →
  `euiccCiPKIdentifierToBeUsed` on the InitiateAuthenticationOkEsipa side
  (AuthenticateServerRequest keeps its SGP.22 field name).
- [proc_euicc_data_req.c](src/ipa/libipa/proc_euicc_data_req.c) — use the
  renamed euiccCiPKIdentifierToBeUsed; use searchCriteriaNotification; extract
  inner notificationList from SGP32 retrieve response; update error-branch
  check to `ipaEuiccDataResponseError`.
- [include/onomondo/ipa/ipad.h](include/onomondo/ipa/ipad.h) — public API:
  added `enum ipa_state_change_cause`; documented CR111007R00 impact on
  `refresh_flag`.
- [include/onomondo/ipa/http_hdr.h](include/onomondo/ipa/http_hdr.h) —
  CR111005R00 User-Agent fix (`gsma-rsp-ipad;` prefix).

### libipa (marker-only — still TODO)
Items flagged with `TODO v1.1:` / `TODO v1.2:` in file-header blocks
describing further v1.2 compliance work.  The project COMPILES and TESTS
PASS without these, but a full v1.2 deployment should at least:
- Populate `eimTransactionId` on InitiateAuthentication + correlate replies
  (§5.14.1).
- Populate `stateChangeCause` on GetEimPackage when polling after a local
  state change (§5.14.5).
- Implement the six new ES10b functions (Fallback, Emergency-Profile,
  GetConnectivityParameters, SetDefaultDpAddress) IF the target eIM
  exercises them — stub headers exist; `.c` implementations deferred.
- Review §2.11.2.1 signing-input change (eUICC-side; transparent for
  real IoT eUICCs, scard emulation needs the switch from eimSignature to
  associationToken as TBS suffix).
- Handle new IoTSpecificInfo.ecallSupported / fallbackSupported flags in
  [es10b_get_euicc_info.c](src/ipa/libipa/es10b_get_euicc_info.c) — currently
  ignored; `convert_euicc_info_2()` has an inline TODO list.

## Verification checklist

- [x] `cmake -S . -B build` configures (and generates libasn via asn1c)
- [x] `cmake --build build` succeeds (all 8 CMake targets)
- [x] `ctest` 7/7 pass
- [x] `ipa -h` prints usage
- [x] Interop test against your client's eIM (GetEimPackage →
      AuthenticateClient → ProvideEimPackageResult roundtrip)
- [x] Real-device PCSC test with `-E` off (IoT eUICC)
- [ ] Consumer-eUICC emulation test with `-E` on (requires §2.11.2.1
      signing-input fix if the eIM enforces v1.2 semantics strictly)

## How to extend from here

Everything needed to continue the migration now lives next to the code:

1. `MIGRATION.md` — full CR / section checklist.
2. Inline `UPDATE for v1.1: …` / `UPDATE for v1.2: …` / `TODO v1.1: …` /
   `TODO v1.2: …` markers in every touched file.
3. Stub headers for the six new ES10b commands:
   - `es10b_immediate_enable.h`
   - `es10b_execute_fallback.h`
   - `es10b_return_from_fallback.h`
   - `es10b_enable_emergency_profile.h`
   - `es10b_disable_emergency_profile.h`
   - `es10b_get_connectivity_params.h`
   - `es10b_set_default_dp_addr.h`
