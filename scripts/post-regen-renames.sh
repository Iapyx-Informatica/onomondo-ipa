#!/usr/bin/env bash
# Apply the mechanical v1.0 → v1.2 renames to libipa/*.{c,h}.
#
# Run this AFTER scripts/regen.sh has regenerated src/ipa/libasn/*.  Every
# substitution below maps a v1.0 identifier to the v1.2 name as they appear
# in GSMA SGP.32 v1.2 Annex C.  The script is idempotent.
#
# For the non-mechanical changes (struct restructures, new procedures) see
# the inline TODO v1.1 / TODO v1.2 markers in the corresponding files.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}/src/ipa/libipa"

# Use find + xargs so this works on Linux/macOS/MSYS.  Restrict to *.c/*.h.
targets=$(find . -maxdepth 1 -type f \( -name '*.c' -o -name '*.h' \))

apply() {
  local pattern="$1"; local repl="$2"; local label="$3"
  # shellcheck disable=SC2086
  if grep -l -E "${pattern}" ${targets} >/dev/null 2>&1; then
    # shellcheck disable=SC2086
    sed -i -E "s/${pattern}/${repl}/g" ${targets}
    echo "[rename] ${label}"
  fi
}

# --- Section 2.11.1.2 renames (IpaEuiccDataRequest) --------------------------
apply '\beuiccCiPKIdToBeused\b' 'euiccCiPKIdentifierToBeUsed' '6.3.2.1: euiccCiPKIdToBeused -> euiccCiPKIdentifierToBeUsed'

# --- Section 5.9.15 renames (EnableUsingDD -> ImmediateEnable) ---------------
apply '\bEnableUsingDDRequest\b'                    'ImmediateEnableRequest'  '5.9.15: EnableUsingDDRequest -> ImmediateEnableRequest'
apply '\bEnableUsingDDResponse\b'                   'ImmediateEnableResponse' '5.9.15: EnableUsingDDResponse -> ImmediateEnableResponse'
apply '\benableUsingDDResult\b'                     'immediateEnableResult'   '5.9.15: enableUsingDDResult -> immediateEnableResult'
apply 'EnableUsingDDResponse__enableUsingDDResult_autoEnableNotAvailable' \
      'ImmediateEnableResponse__immediateEnableResult_immediateEnableNotAvailable' \
      '5.9.15: autoEnableNotAvailable enum -> immediateEnableNotAvailable'
apply 'EnableUsingDDResponse__enableUsingDDResult_' \
      'ImmediateEnableResponse__immediateEnableResult_' \
      '5.9.15: EnableUsingDDResponse__enableUsingDDResult_* prefix'
apply 'asn_DEF_EnableUsingDDRequest'  'asn_DEF_ImmediateEnableRequest'  '5.9.15: asn_DEF_EnableUsingDDRequest'
apply 'asn_DEF_EnableUsingDDResponse' 'asn_DEF_ImmediateEnableResponse' '5.9.15: asn_DEF_EnableUsingDDResponse'

# --- Section 2.11.1.1.3 / 5.9.17 (ConfigureAuto -> ConfigureImmediate) -------
apply '\bConfigureAutoEnableResult\b'            'ConfigureImmediateEnableResult'            '2.11.2: ConfigureAutoEnableResult type'
apply '\bConfigureAutoProfileEnablingRequest\b'  'ConfigureImmediateProfileEnablingRequest'  '5.9.17: ConfigureAutoProfileEnablingRequest type'
apply '\bConfigureAutoProfileEnablingResponse\b' 'ConfigureImmediateProfileEnablingResponse' '5.9.17: ConfigureAutoProfileEnablingResponse type'
apply '\bconfigureAutoEnableResult\b'            'configureImmediateEnableResult'            '2.11.2: configureAutoEnableResult field'
apply '\bconfigureAutoEnable\b'                  'configureImmediateEnable'                  '2.11.1.1.3: configureAutoEnable field'
apply '\bconfigAutoEnableResult\b'               'configImmediateEnableResult'               '5.9.17: configAutoEnableResult field'

# --- Field renames inside signed structures -----------------------------------
# NOTE: bare transactionId is intentionally NOT renamed because the SGP.22
# CompactProfileInstallationResultData also has a transactionId that is
# unchanged.  Only the SGP.32-specific transactionId fields were renamed;
# the asn1c-generated field names are unique per parent struct.
# The parent structures whose transactionId -> eimTransactionId are:
#   EuiccPackageSigned, EuiccPackageResultDataSigned, EuiccPackageErrorDataSigned
# Since asn1c uses the literal ASN.1 field name, bare sed works — but apply
# only to lines that also mention one of those parent structures by proximity.
# Simpler: if a manual audit confirms there's no collision in libipa, flip
# this to a straight rename.  For safety we skip it here and rely on the
# compile errors + markers to surface each site.

# --- 2.11.1.2 — searchCriteria -> searchCriteriaNotification ------------------
# Renaming IpaEuiccDataRequest.searchCriteria would also affect the unrelated
# SGP32_RetrieveNotificationsListRequest.searchCriteria which is NOT renamed
# in v1.2.  We therefore don't blanket-sed this — the callers (proc_euicc_data_req.c,
# es10b_retr_notif_from_lst.c) carry inline TODOs that list the precise site.
# Leaving as a TODO for a human pass.

echo "[rename] done.  Build with ./scripts/build.sh to see remaining errors."
