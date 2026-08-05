# Getting started — onomondo-ipa (SGP.32 v1.2 port)

This is a fork of [onomondo/onomondo-ipa](https://github.com/onomondo/onomondo-ipa)
with an in-progress port from SGP.32 v1.0 to **v1.2**.  The build works
end-to-end and the existing test suite passes; see [MIGRATION_STATUS.md](MIGRATION_STATUS.md)
for the full state.

## Build — Linux with `asn1c` 0.9.28+ and the usual deps

On Debian/Ubuntu:

```bash
sudo apt install asn1c build-essential cmake libcurl4-gnutls-dev libpcsclite-dev
cmake -S . -B build -DENABLE_SANITIZE=ON -DSHOW_ASN_OUTPUT=ON
cmake --build build --parallel
```

That's it.  CMake will:

1. Generate the libasn codec from `asn1/*.asn` (asn1c, during configure) into
   the build tree — `asn1c` must be in PATH.  It re-runs automatically when a
   schema changes, and not otherwise.
2. Compile the project.  Run `ctest` (below) and expect **7/7 tests to pass**.

The binary is at `build/src/ipa/ipa`.

## Smoke tests

```bash
./build/src/ipa/ipa -h        # prints usage
(cd build && ctest --output-on-failure)
```

## Selecting the ESipa binding (ASN.1 vs JSON)

SGP.32 v1.2 §6.4 defines two wire bindings for the ESipa interface.
The IPA supports both:

- **ASN.1 binding (default)** — `application/x-gsma-rsp-asn1`, single endpoint
  `/gsma/rsp2/asn1`.  Most compact, recommended for NB-IoT / cat-M uplinks.
- **JSON binding** — `application/json;charset=UTF-8`, per-function endpoints
  `/gsma/rsp2/esipa/<functionName>`.  Easier to inspect with curl / Wireshark;
  typical for backend / cloud-hosted eIMs.

Both are v1.2-compliant.  Select at init time:

```c
struct ipa_config cfg = { 0 };
/* ... other fields ... */
cfg.esipa_binding = IPA_ESIPA_BINDING_JSON; /* or _ASN1 (default) */
```

The JSON binding requires `libjansson-dev` at build time (auto-detected by
CMake).  Without jansson, the binding compiles to a stub and only the
ASN.1 path is functional — the ASN.1 build is unaffected.

Note: the JSON encoders and decoders are compile-verified but have not yet
been interop-tested against a real JSON-speaking eIM.  A first-pass run
against your target eIM would be very useful for closing remaining edge
cases (error-code wrappers, `eimTransactionId` correlation, etc.).

## Running against a real eIM / eUICC

This implementation is a working IPAd — it polls an eIM over HTTPS and talks
to an eUICC via PC/SC.  Typical setup on Linux:

```bash
# 1. Plug a PC/SC reader with your IoT eUICC in.  Confirm it shows up:
pcsc_scan

# 2. Load initial eIM configuration once (per eUICC):
./build/src/ipa/ipa -r <reader_num> -f contrib/sample_eim_cfg.ber

# 3. Poll the eIM for pending packages:
./build/src/ipa/ipa -r <reader_num>
```

For testing against a consumer eUICC (not an IoT eUICC) add `-E` to enable
emulation mode.  **Note**: `-E` against a strict v1.2 eIM may fail because
the consumer-emulation signing-input change (§2.11.2.1) is still a TODO —
see [MIGRATION_STATUS.md](MIGRATION_STATUS.md).

## What changed from v1.0

See:
- [MIGRATION.md](MIGRATION.md) — CR-by-CR checklist.
- [MIGRATION_STATUS.md](MIGRATION_STATUS.md) — current build state + what's
  implemented vs. still TODO.
- Inline markers in every touched file: grep for
  `UPDATE for v1.1:`, `UPDATE for v1.2:`, `NEW in v1.1/v1.2:`,
  `TODO v1.1:`, `TODO v1.2:`.

## Questions / feedback

If something doesn't work, it's most useful to know which of the TODOs in
[MIGRATION_STATUS.md](MIGRATION_STATUS.md) actually bite your deployment.
The highest-risk items today are:

1. Does your eIM enforce v1.2 strictly (rejecting if `eidValue` is missing,
   etc.)?
2. Does it exercise Fallback / Emergency Profile flows (§5.9.20–23)?
3. Are you using `-E` (consumer-eUICC emulation)?

A short write-up of what works / what doesn't against your eIM would be
hugely valuable for closing the remaining TODOs.
